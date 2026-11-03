"""Binary IDS metrics and standalone evaluation of a saved model."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from app.ml.data_loader import DEFAULT_DATASET_DIR, class_distribution, load_dataset
from app.ml.predict import DEFAULT_MODEL_PATH


def calculate_fpr(tn: int, fp: int) -> float:
    """Compute false positive rate safely when no normal samples exist."""
    denominator = int(tn) + int(fp)
    return int(fp) / denominator if denominator else 0.0


def evaluate_predictions(
    y_true: Any,
    y_pred: Any,
    y_train: Any | None = None,
    training_time_seconds: float | None = None,
    prediction_time_seconds: float | None = None,
) -> dict[str, Any]:
    """Calculate binary metrics with class 1 (Attack) treated as positive."""
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    result: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "confusion_matrix": {
            "labels": ["Normal", "Attack"],
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "false_positive_rate": calculate_fpr(tn, fp),
        "test_samples": int(len(y_true)),
        "test_class_distribution": class_distribution(pd.Series(y_true)),
    }
    if y_train is not None:
        result["train_samples"] = int(len(y_train))
        result["train_class_distribution"] = class_distribution(pd.Series(y_train))
    if training_time_seconds is not None:
        result["training_time_seconds"] = float(training_time_seconds)
    if prediction_time_seconds is not None:
        result["prediction_time_seconds"] = float(prediction_time_seconds)
    return result


def evaluate_model(model: Any, X_test: pd.DataFrame, y_test: pd.Series, **metadata: Any) -> dict[str, Any]:
    start = time.perf_counter()
    predictions = model.predict(X_test)
    elapsed = time.perf_counter() - start
    return evaluate_predictions(
        y_test,
        predictions,
        prediction_time_seconds=elapsed,
        **metadata,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the saved SecureWork IDS pipeline.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    args = parser.parse_args(argv)
    bundle = load_dataset(args.dataset)
    model = joblib.load(args.model)
    metrics = evaluate_model(
        model,
        bundle.X_test,
        bundle.y_test,
        y_train=bundle.y_train,
    )
    metadata_path = args.model.with_name("training_metadata.json")
    if metadata_path.is_file():
        stored_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metrics["training_time_seconds"] = stored_metadata.get("metrics", {}).get(
            "training_time_seconds"
        )
    metrics["dataset_files"] = list(bundle.dataset_files)
    metrics["split_type"] = bundle.split_type
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
