"""Reusable prediction API for later phases; not connected to live capture."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "securework_ids.joblib"
CLASS_NAMES = {0: "Normal", 1: "Attack"}


@dataclass(frozen=True)
class Prediction:
    class_id: int
    label: str
    probability: float | None


def load_model(model_path: str | Path = DEFAULT_MODEL_PATH) -> Any:
    """Load a complete preprocessing and classifier pipeline from joblib."""
    path = Path(model_path)
    if not path.is_file():
        raise FileNotFoundError(f"SecureWork IDS model not found: {path}")
    model = joblib.load(path)
    if not callable(getattr(model, "predict", None)):
        raise ValueError(f"Model artifact does not provide predict(): {path}")
    return model


def _as_frame(features: pd.DataFrame | dict[str, Any] | list[dict[str, Any]]) -> pd.DataFrame:
    if isinstance(features, pd.DataFrame):
        frame = features.copy()
    elif isinstance(features, dict):
        frame = pd.DataFrame([features])
    elif isinstance(features, list) and all(isinstance(item, dict) for item in features):
        frame = pd.DataFrame(features)
    else:
        raise TypeError("features must be a DataFrame, a feature mapping, or a list of mappings.")
    if frame.empty:
        raise ValueError("At least one feature record is required.")
    return frame


def predict(
    features: pd.DataFrame | dict[str, Any] | list[dict[str, Any]],
    model: Any | None = None,
    model_path: str | Path = DEFAULT_MODEL_PATH,
) -> list[Prediction]:
    """Predict Normal/Attack records and include Attack probability when available."""
    estimator = model if model is not None else load_model(model_path)
    frame = _as_frame(features)
    classes = list(getattr(estimator, "classes_", []))
    probabilities = estimator.predict_proba(frame) if callable(getattr(estimator, "predict_proba", None)) else None
    output: list[Prediction] = []
    for index, value in enumerate(estimator.predict(frame)):
        class_id = int(value)
        probability = None
        if probabilities is not None and 1 in classes:
            probability = float(probabilities[index][classes.index(1)])
        output.append(Prediction(class_id, CLASS_NAMES.get(class_id, str(class_id)), probability))
    return output


def predict_proba(
    features: pd.DataFrame | dict[str, Any] | list[dict[str, Any]],
    model: Any | None = None,
    model_path: str | Path = DEFAULT_MODEL_PATH,
) -> list[dict[str, float]]:
    """Return per-record probabilities keyed by Normal and Attack."""
    estimator = model if model is not None else load_model(model_path)
    if not callable(getattr(estimator, "predict_proba", None)):
        raise TypeError("The loaded model does not support probability predictions.")
    frame = _as_frame(features)
    classes = list(estimator.classes_)
    probabilities = estimator.predict_proba(frame)
    return [
        {CLASS_NAMES.get(int(class_id), str(class_id)): float(value)
         for class_id, value in zip(classes, row)}
        for row in probabilities
    ]
