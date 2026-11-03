"""Reproducible offline UNSW-NB15 model comparison experiments.

This module deliberately does not connect any experimental model to the live
IDS service.  The Phase 4 Random Forest artifact remains the application
baseline; comparison outputs are written under the ignored models/comparison/
directory.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import joblib
import numpy as np
import pandas as pd
import psutil
import sklearn
from sklearn.base import BaseEstimator
from sklearn.calibration import calibration_curve
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
    StackingClassifier,
    VotingClassifier,
)
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss
from sklearn.model_selection import StratifiedKFold
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import LinearSVC

from app.ml.data_loader import DEFAULT_DATASET_DIR, DatasetSplit, load_dataset
from app.ml.evaluate import evaluate_predictions
from app.ml.predict import DEFAULT_MODEL_PATH, load_model
from app.ml.preprocessor import RANDOM_FOREST_CONFIG, make_preprocessor
from app.ml.train import DEFAULT_METADATA_PATH

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMPARISON_DIR = PROJECT_ROOT / "models" / "comparison"
RANDOM_STATE = 42


@dataclass(frozen=True)
class ModelSpec:
    """A fixed, pre-test configuration for one offline experiment."""

    name: str
    factory: Callable[[pd.DataFrame], BaseEstimator]
    configuration: dict[str, Any]
    supports_probability: bool


def _feature_columns(features: pd.DataFrame) -> tuple[list[str], list[str]]:
    categorical = [
        name for name in features.columns
        if pd.api.types.is_object_dtype(features[name].dtype)
        or pd.api.types.is_string_dtype(features[name].dtype)
        or isinstance(features[name].dtype, pd.CategoricalDtype)
        or pd.api.types.is_bool_dtype(features[name].dtype)
    ]
    return categorical, [name for name in features.columns if name not in categorical]


def make_dense_scaled_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    """Train-only dense transforms for estimators that do not accept sparse data."""
    categorical, numeric = _feature_columns(features)
    transformers: list[tuple[str, Any, list[str]]] = []
    if numeric:
        transformers.append(("numeric", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]), numeric))
    if categorical:
        transformers.append(("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]), categorical))
    return ColumnTransformer(transformers, remainder="drop", sparse_threshold=0.0)


def make_sparse_scaled_preprocessor(features: pd.DataFrame) -> ColumnTransformer:
    """Train-only sparse transforms for the linear SVM experiment."""
    categorical, numeric = _feature_columns(features)
    transformers: list[tuple[str, Any, list[str]]] = []
    if numeric:
        transformers.append(("numeric", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler(with_mean=False)),
        ]), numeric))
    if categorical:
        transformers.append(("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=True)),
        ]), categorical))
    return ColumnTransformer(transformers, remainder="drop")


def model_specs(random_state: int = RANDOM_STATE) -> dict[str, ModelSpec]:
    """Return fixed eligible models; no test-set-driven tuning is performed."""
    extra_config = {
        "n_estimators": 150, "min_samples_leaf": 1, "class_weight": "balanced",
        "random_state": random_state, "n_jobs": -1,
    }
    hist_config = {
        "learning_rate": 0.1, "max_iter": 200, "max_leaf_nodes": 31,
        "l2_regularization": 0.1, "random_state": random_state,
    }
    svm_config = {"C": 1.0, "class_weight": "balanced", "max_iter": 5000, "random_state": random_state}
    mlp_config = {
        "hidden_layer_sizes": [64, 32], "activation": "relu", "solver": "adam",
        "alpha": 0.0001, "batch_size": 512, "learning_rate_init": 0.001,
        "early_stopping": True, "validation_fraction": 0.1, "n_iter_no_change": 5,
        "max_iter": 40, "random_state": random_state,
    }

    def sparse_tree(factory: Callable[[], BaseEstimator]) -> Callable[[pd.DataFrame], BaseEstimator]:
        return lambda X: Pipeline([("preprocessor", make_preprocessor(X)), ("classifier", factory())])

    return {
        "extra_trees": ModelSpec("Extra Trees", sparse_tree(lambda: ExtraTreesClassifier(**extra_config)), extra_config, True),
        "hist_gradient_boosting": ModelSpec(
            "HistGradientBoosting",
            lambda X: Pipeline([("preprocessor", make_dense_scaled_preprocessor(X)), ("classifier", HistGradientBoostingClassifier(**hist_config))]),
            hist_config,
            True,
        ),
        "linear_svm": ModelSpec(
            "Linear SVM",
            lambda X: Pipeline([("preprocessor", make_sparse_scaled_preprocessor(X)), ("classifier", LinearSVC(**svm_config))]),
            svm_config,
            False,
        ),
        "mlp": ModelSpec(
            "MLP neural network",
            lambda X: Pipeline([("preprocessor", make_dense_scaled_preprocessor(X)), ("classifier", MLPClassifier(**mlp_config))]),
            mlp_config,
            True,
        ),
        "soft_voting": ModelSpec(
            "Soft voting (Random Forest + Extra Trees)",
            lambda X: VotingClassifier(
                estimators=[
                    ("rf", Pipeline([("preprocessor", make_preprocessor(X)), ("classifier", RandomForestClassifier(**{**RANDOM_FOREST_CONFIG, "n_jobs": 1}))])),
                    ("extra", Pipeline([("preprocessor", make_preprocessor(X)), ("classifier", ExtraTreesClassifier(**{**extra_config, "n_jobs": 1}))])),
                ], voting="soft", n_jobs=1,
            ),
            {"voting": "soft", "members": {"random_forest": {**RANDOM_FOREST_CONFIG, "n_jobs": 1}, "extra_trees": {**extra_config, "n_jobs": 1}}, "n_jobs": 1, "random_state": random_state},
            True,
        ),
        "stacking": ModelSpec(
            "Stacking (OOF Random Forest + Extra Trees)",
            lambda X: StackingClassifier(
                estimators=[
                    ("rf", Pipeline([("preprocessor", make_preprocessor(X)), ("classifier", RandomForestClassifier(**{**RANDOM_FOREST_CONFIG, "n_estimators": 75, "random_state": random_state, "n_jobs": 1}))])),
                    ("extra", Pipeline([("preprocessor", make_preprocessor(X)), ("classifier", ExtraTreesClassifier(**{**extra_config, "n_estimators": 75, "n_jobs": 1}))])),
                ],
                final_estimator=LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state),
                stack_method="predict_proba",
                cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=random_state),
                n_jobs=1,
            ),
            {"cv": 3, "cv_strategy": "StratifiedKFold(shuffle=True, random_state=42)", "stack_method": "predict_proba", "meta_model": "LogisticRegression", "base_estimators": "75-tree Random Forest and Extra Trees", "n_jobs": 1, "random_state": random_state},
            True,
        ),
    }


def _artifact_size_bytes(model: BaseEstimator) -> int:
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as handle:
        temporary_path = Path(handle.name)
    try:
        joblib.dump(model, temporary_path)
        return temporary_path.stat().st_size
    finally:
        temporary_path.unlink(missing_ok=True)


def _calibration_metrics(y_true: pd.Series, probability: np.ndarray) -> dict[str, Any]:
    fraction_positive, mean_predicted = calibration_curve(y_true, probability, n_bins=10, strategy="uniform")
    return {
        "brier_score": float(brier_score_loss(y_true, probability)),
        "calibration_bins": [
            {"mean_predicted_probability": float(predicted), "observed_attack_fraction": float(observed)}
            for predicted, observed in zip(mean_predicted, fraction_positive)
        ],
    }


def evaluate_fitted_model(
    name: str,
    model: BaseEstimator,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    training_time_seconds: float | None,
    configuration: dict[str, Any],
    supports_probability: bool,
) -> dict[str, Any]:
    """Measure one fitted model using the untouched official test partition."""
    start = time.perf_counter()
    predictions = model.predict(X_test)
    full_inference_seconds = time.perf_counter() - start
    batch_size = min(1024, len(X_test))
    batch_start = time.perf_counter()
    model.predict(X_test.iloc[:batch_size])
    batch_seconds = time.perf_counter() - batch_start
    result = evaluate_predictions(y_test, predictions, training_time_seconds=training_time_seconds)
    result.update({
        "name": name,
        "configuration": configuration,
        "inference_full_test_seconds": float(full_inference_seconds),
        "inference_seconds_per_record": float(full_inference_seconds / len(X_test)),
        "inference_batch_size": int(batch_size),
        "inference_batch_seconds": float(batch_seconds),
        "inference_batch_seconds_per_record": float(batch_seconds / batch_size),
        "model_size_bytes": _artifact_size_bytes(model),
        "probability_supported": supports_probability,
    })
    if supports_probability:
        probabilities = model.predict_proba(X_test)[:, 1]
        result["calibration"] = _calibration_metrics(y_test, probabilities)
    return result


def _phase4_baseline(bundle: DatasetSplit, model_path: Path, metadata_path: Path) -> dict[str, Any]:
    model = load_model(model_path)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if tuple(model.feature_names_in_) != tuple(bundle.feature_names):
        raise ValueError("Phase 4 saved-model feature order differs from the loaded dataset.")
    return evaluate_fitted_model(
        "Random Forest (Phase 4 baseline)", model, bundle.X_test, bundle.y_test,
        metadata.get("metrics", {}).get("training_time_seconds"),
        metadata.get("random_forest_config", RANDOM_FOREST_CONFIG), True,
    )


def run_comparison(
    bundle: DatasetSplit,
    selected_models: tuple[str, ...] | None = None,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    metadata_path: str | Path = DEFAULT_METADATA_PATH,
    random_state: int = RANDOM_STATE,
) -> dict[str, Any]:
    """Run fixed offline experiments; model selection never reads test labels."""
    specs = model_specs(random_state)
    selected = selected_models or tuple(specs)
    unknown = set(selected) - set(specs)
    if unknown:
        raise ValueError(f"Unknown comparison model(s): {sorted(unknown)}")
    results = [_phase4_baseline(bundle, Path(model_path), Path(metadata_path))]
    for key in selected:
        spec = specs[key]
        model = spec.factory(bundle.X_train)
        start = time.perf_counter()
        model.fit(bundle.X_train, bundle.y_train)
        training_seconds = time.perf_counter() - start
        results.append(evaluate_fitted_model(
            spec.name, model, bundle.X_test, bundle.y_test, training_seconds,
            spec.configuration, spec.supports_probability,
        ))
    return {
        "study": "UNSW-NB15 offline supervised model comparison",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "random_state": random_state,
        "split": {
            "type": bundle.split_type,
            "dataset_files": list(bundle.dataset_files),
            "train_samples": len(bundle.X_train),
            "test_samples": len(bundle.X_test),
            "cross_split_identical_feature_rows": bundle.cross_split_feature_overlap_rows,
            "cross_split_conflicting_labels": bundle.cross_split_conflicting_label_rows,
        },
        "environment": {
            "python": platform.python_version(), "scikit_learn": sklearn.__version__,
            "logical_cpus": os.cpu_count(), "physical_cpus": psutil.cpu_count(logical=False),
            "memory_total_bytes": psutil.virtual_memory().total,
        },
        "excluded_models": {
            "XGBoost": "xgboost is not installed in the existing environment.",
            "LSTM": "No TensorFlow/PyTorch dependency is installed; supplied model CSVs omit chronological and entity fields needed for valid sequences.",
            "Autoencoder": "No deep-learning dependency is installed; no normal-only threshold experiment was run.",
        },
        "results": results,
        "live_inference_note": "Offline results do not change the Phase 6 live-feature compatibility gate; live ML inference remains disabled.",
    }


def save_comparison(metadata: dict[str, Any], output_dir: str | Path = DEFAULT_COMPARISON_DIR) -> Path:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "comparison_metrics.json"
    output.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run offline UNSW-NB15 classifier comparison experiments.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_COMPARISON_DIR)
    parser.add_argument("--models", nargs="*", choices=tuple(model_specs()), default=None)
    args = parser.parse_args(argv)
    result = run_comparison(load_dataset(args.dataset), tuple(args.models) if args.models else None)
    output = save_comparison(result, args.output_dir)
    print(f"Saved comparison metadata: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
