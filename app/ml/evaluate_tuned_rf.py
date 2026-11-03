
"""Compare the baseline and tuned Random Forest configurations.

This is an offline experiment. It never overwrites the deployed model.
"""
from __future__ import annotations

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from app.ml.data_loader import load_dataset
from app.ml.preprocessor import make_pipeline

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "models" / "comparison" / "rf_tuning"
OUTPUT_FILE = OUTPUT_DIR / "test_comparison.json"

CONFIGURATIONS = {
    "baseline": {
        "n_estimators": 100,
        "max_depth": 24,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced_subsample",
    },
    "tuned_winner": {
        "n_estimators": 100,
        "max_depth": 24,
        "min_samples_leaf": 2,
        "max_features": 0.7,
        "class_weight": "balanced_subsample",
    },
    "faster_challenger": {
        "n_estimators": 100,
        "max_depth": None,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "class_weight": "balanced_subsample",
    },
}


def evaluate_configuration(name, config, X_train, y_train, X_test, y_test):
    model = make_pipeline(X_train, random_state=42)
    model.set_params(**{
        f"classifier__{key}": value
        for key, value in config.items()
    })

    start = time.perf_counter()
    model.fit(X_train, y_train)
    training_seconds = time.perf_counter() - start

    start = time.perf_counter()
    predictions = model.predict(X_test)
    inference_seconds = time.perf_counter() - start

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    # Measure the serialized artifact without saving it as the active model.
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as file:
        temporary_path = Path(file.name)

    try:
        joblib.dump(model, temporary_path)
        artifact_size = temporary_path.stat().st_size
    finally:
        temporary_path.unlink(missing_ok=True)

    result = {
        "name": name,
        "configuration": config,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "attack_precision": float(precision_score(
            y_test, predictions, pos_label=1, zero_division=0
        )),
        "attack_recall": float(recall_score(
            y_test, predictions, pos_label=1, zero_division=0
        )),
        "attack_f1": float(f1_score(
            y_test, predictions, pos_label=1, zero_division=0
        )),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "training_seconds": training_seconds,
        "full_test_inference_seconds": inference_seconds,
        "artifact_size_bytes": int(artifact_size),
    }

    print(
        f"{name}: F1={result['attack_f1']:.5f}, "
        f"recall={result['attack_recall']:.5f}, "
        f"FPR={result['false_positive_rate']:.5f}, "
        f"training={training_seconds:.1f}s"
    )
    return result


def main():
    bundle = load_dataset()
    print(f"Training rows: {len(bundle.X_train):,}")
    print(f"Test rows: {len(bundle.X_test):,}")
    print("Fitting three configurations; existing model artifacts are unchanged.\n")

    results = []
    for name, config in CONFIGURATIONS.items():
        results.append(evaluate_configuration(
            name,
            config,
            bundle.X_train,
            bundle.y_train,
            bundle.X_test,
            bundle.y_test,
        ))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "experiment": "Random Forest baseline versus tuned candidates",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "UNSW-NB15 official train/test partition",
        "warning": (
            "The official test partition was used in previous experiments. "
            "Treat these results as comparative evidence, not an untouched final test."
        ),
        "results": results,
    }
    OUTPUT_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("\nComparison saved to:")
    print(OUTPUT_FILE)
    print("\nAttack F1 ranking:")
    for result in sorted(results, key=lambda item: item["attack_f1"], reverse=True):
        print(
            f"{result['name']:20} "
            f"F1={result['attack_f1']:.5f} "
            f"precision={result['attack_precision']:.5f} "
            f"recall={result['attack_recall']:.5f} "
            f"FPR={result['false_positive_rate']:.5f}"
        )


if __name__ == "__main__":
    main()
