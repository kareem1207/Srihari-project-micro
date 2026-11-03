"""Offline UNSW-NB15 model demonstration; intentionally separate from live IDS."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.ml.data_loader import DEFAULT_DATASET_DIR, DatasetError, DatasetSplit, load_dataset
from app.ml.evaluate import evaluate_model
from app.ml.predict import CLASS_NAMES, DEFAULT_MODEL_PATH, load_model, predict


DEMONSTRATION_LABEL = "OFFLINE DATASET DEMONSTRATION — NOT LIVE NETWORK DETECTION"


class OfflineDemoError(ValueError):
    """Raised when an offline model demonstration cannot be safely performed."""


def _validate_model_schema(model: Any, bundle: DatasetSplit) -> None:
    """Require the saved pipeline and dataset to share one exact ordered schema."""
    expected = tuple(bundle.feature_names)
    actual = tuple(str(name) for name in getattr(model, "feature_names_in_", ()))
    if actual != expected:
        raise OfflineDemoError(
            "Saved model feature schema does not exactly match the offline dataset feature order."
        )
    if bundle.target_mapping != CLASS_NAMES:
        raise OfflineDemoError("Offline dataset does not use the required 0=Normal, 1=Attack mapping.")


def run_offline_demo(
    dataset_dir: str | Path = DEFAULT_DATASET_DIR,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    sample_index: int = 0,
) -> dict[str, Any]:
    """Evaluate the existing saved pipeline and predict one held-out dataset record.

    This function reads only the supplied local dataset and existing model artifact.
    It does not train, write artifacts, invoke live capture, persist events, or
    interact with the live IDS compatibility gate.
    """
    if sample_index < 0:
        raise OfflineDemoError("sample_index must be zero or greater.")

    bundle = load_dataset(dataset_dir)
    if sample_index >= len(bundle.X_test):
        raise OfflineDemoError(
            f"sample_index {sample_index} is outside the held-out test partition "
            f"(0 through {len(bundle.X_test) - 1})."
        )

    model = load_model(model_path)
    _validate_model_schema(model, bundle)
    metrics = evaluate_model(model, bundle.X_test, bundle.y_test, y_train=bundle.y_train)
    prediction = predict(bundle.X_test.iloc[[sample_index]], model=model)[0]
    true_class_id = int(bundle.y_test.iloc[sample_index])

    return {
        "demonstration": DEMONSTRATION_LABEL,
        "scope": "offline_dataset_only",
        "dataset_files": list(bundle.dataset_files),
        "split_type": bundle.split_type,
        "feature_count": len(bundle.feature_names),
        "metrics": metrics,
        "sample": {
            "test_partition_index": sample_index,
            "true_class_id": true_class_id,
            "true_label": CLASS_NAMES[true_class_id],
            "predicted_class_id": prediction.class_id,
            "predicted_label": prediction.label,
            "attack_probability": prediction.probability,
        },
        "limitations": [
            "This is an offline dataset demonstration, not live network detection.",
            "It does not enable live IDS inference, packet capture, event persistence, or export.",
            "Offline test metrics do not establish real-world detection performance or live-feature compatibility.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=DEMONSTRATION_LABEL)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--sample-index", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        report = run_offline_demo(args.dataset, args.model, args.sample_index)
    except (DatasetError, FileNotFoundError, OfflineDemoError, TypeError, ValueError) as exc:
        print(f"Offline demonstration failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
