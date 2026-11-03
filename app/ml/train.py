"""Train and save the UNSW-NB15 Random Forest baseline pipeline."""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import sklearn

from app.ml.data_loader import DEFAULT_DATASET_DIR, DatasetSplit, class_distribution, load_dataset
from app.ml.evaluate import evaluate_model
from app.ml.predict import DEFAULT_MODEL_PATH
from app.ml.preprocessor import RANDOM_FOREST_CONFIG, make_pipeline

DEFAULT_METADATA_PATH = DEFAULT_MODEL_PATH.with_name("training_metadata.json")


def _feature_types(features: pd.DataFrame) -> tuple[list[str], list[str]]:
    categorical = [
        name for name in features.columns
        if pd.api.types.is_object_dtype(features[name].dtype)
        or pd.api.types.is_string_dtype(features[name].dtype)
        or isinstance(features[name].dtype, pd.CategoricalDtype)
        or pd.api.types.is_bool_dtype(features[name].dtype)
    ]
    return categorical, [name for name in features.columns if name not in categorical]


def train_and_save(
    bundle: DatasetSplit,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    metadata_path: str | Path | None = None,
    random_state: int = 42,
) -> tuple[Any, dict[str, Any]]:
    """Fit only on the training partition, evaluate on test, then save artifacts."""
    model_file = Path(model_path)
    metadata_file = Path(metadata_path) if metadata_path else model_file.with_name("training_metadata.json")
    pipeline = make_pipeline(bundle.X_train, random_state=random_state)
    started = time.perf_counter()
    pipeline.fit(bundle.X_train, bundle.y_train)
    training_seconds = time.perf_counter() - started
    metrics = evaluate_model(
        pipeline,
        bundle.X_test,
        bundle.y_test,
        y_train=bundle.y_train,
        training_time_seconds=training_seconds,
    )

    model_file.parent.mkdir(parents=True, exist_ok=True)
    metadata_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_file)
    categorical, numerical = _feature_types(bundle.X_train)
    metadata: dict[str, Any] = {
        "dataset_name": "UNSW-NB15",
        "dataset_files": list(bundle.dataset_files),
        "split_type": bundle.split_type,
        "train_samples": len(bundle.X_train),
        "test_samples": len(bundle.X_test),
        "cross_split_feature_overlap_rows": bundle.cross_split_feature_overlap_rows,
        "cross_split_conflicting_label_rows": bundle.cross_split_conflicting_label_rows,
        "train_class_distribution": class_distribution(bundle.y_train),
        "test_class_distribution": class_distribution(bundle.y_test),
        "feature_names": bundle.feature_names,
        "categorical_features": categorical,
        "numerical_features": numerical,
        "excluded_columns": list(bundle.excluded_columns),
        "target_column": "label",
        "target_mapping": {"0": "Normal", "1": "Attack"},
        "model_type": "RandomForestClassifier",
        "random_forest_config": {**RANDOM_FOREST_CONFIG, "random_state": random_state},
        "training_time_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "metrics": metrics,
        "model_artifact": str(model_file),
        "evaluation_note": (
            "Official train/test partition preserved. Exact input-feature overlap and conflicting "
            "labels across matching feature rows are present; this affects test independence."
        ),
    }
    metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return pipeline, metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the SecureWork Random Forest IDS baseline.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--metadata", type=Path, default=None)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args(argv)
    bundle = load_dataset(args.dataset)
    _, metadata = train_and_save(bundle, args.model, args.metadata, args.random_state)
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
