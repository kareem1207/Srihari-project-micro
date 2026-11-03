"""Safe Phase 5 IDS compatibility gate, inference service, and event records."""
from __future__ import annotations

import logging
import math
import numbers
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from app.ml.predict import Prediction, load_model as load_phase4_model, predict as predict_with_pipeline
from app.security.feature_compatibility import (
    CompatibilityAssessment,
    FeatureCompatibilityReport,
    MODEL_FEATURES,
)
from app.security.flow_aggregator import CompletedFlow

logger = logging.getLogger(__name__)

CATEGORICAL_FEATURES = frozenset({"proto", "service", "state"})


class IDSServiceError(RuntimeError):
    """Base error for safe IDS service operations."""


class ModelUnavailableError(IDSServiceError):
    """The model artifact is absent, corrupt, or has an unexpected schema."""


class MissingFeatureError(IDSServiceError):
    """A complete feature record is missing one or more required values."""


class MalformedFeatureError(IDSServiceError):
    """A feature record contains invalid types or values."""


class FeatureCompatibilityError(IDSServiceError):
    """Live data does not have verified UNSW-NB15-compatible semantics."""


@dataclass(frozen=True)
class IDSResult:
    flow_id: str
    prediction: str
    is_attack: bool
    attack_probability: float | None
    timestamp: str


@dataclass(frozen=True)
class FlowReview:
    flow_id: str
    status: str
    reason: str
    missing_features: tuple[str, ...]
    blocked_features: tuple[str, ...]
    prediction: IDSResult | None = None


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    severity: str
    prediction: str
    attack_probability: float | None
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    flow_duration: float
    packet_count: int
    byte_count: int
    flow_id: str
    message: str

    @classmethod
    def from_prediction(cls, flow: CompletedFlow, result: IDSResult) -> SecurityEvent:
        """Make a metadata-only event; an Attack prediction is a signal, not proof."""
        if result.flow_id != flow.flow_id:
            raise ValueError("Prediction flow_id does not match the completed flow.")
        is_attack = result.is_attack
        severity = "SUSPICIOUS" if is_attack else "NORMAL"
        message = (
            "Model classified this flow as Attack; this is a detection signal, not confirmation of compromise."
            if is_attack
            else "Model classified this flow as Normal."
        )
        return cls(
            timestamp=result.timestamp,
            severity=severity,
            prediction=result.prediction,
            attack_probability=result.attack_probability,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            source_port=flow.source_port,
            destination_port=flow.destination_port,
            protocol=flow.protocol,
            flow_duration=flow.duration,
            packet_count=flow.packet_count,
            byte_count=flow.total_bytes,
            flow_id=flow.flow_id,
            message=message,
        )


class IDSService:
    """Load the fixed Phase 4 model and fail closed when live features mismatch."""

    def __init__(
        self,
        model_path: str | Path,
        compatibility: FeatureCompatibilityReport | None = None,
        model_loader=load_phase4_model,
        event_store=None,
    ) -> None:
        self.model_path = Path(model_path)
        self.compatibility = compatibility or FeatureCompatibilityReport()
        self._model_loader = model_loader
        if event_store is None:
            from app.security.event_store import SecurityEventStore
            event_store = SecurityEventStore()
        self.event_store = event_store
        self._model: Any | None = None
        self._model_status = "CHECKING"
        self._model_error: str | None = None
        self._events: list[SecurityEvent] = []
        self._flows_checked = 0
        self._analysis_active = False
        self._lock = threading.RLock()

    @property
    def model_status(self) -> str:
        with self._lock:
            return self._model_status

    @property
    def model_error(self) -> str | None:
        with self._lock:
            return self._model_error

    @property
    def model_artifact_present(self) -> bool:
        return self.model_path.is_file()

    @property
    def inference_enabled(self) -> bool:
        with self._lock:
            return self._model is not None and self.compatibility.live_prediction_enabled

    @property
    def analysis_active(self) -> bool:
        with self._lock:
            return self._analysis_active

    @property
    def flows_checked(self) -> int:
        with self._lock:
            return self._flows_checked

    @property
    def detections(self) -> int:
        with self._lock:
            return sum(event.severity == "SUSPICIOUS" for event in self._events)

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def latest_event(self) -> SecurityEvent | None:
        with self._lock:
            return self._events[-1] if self._events else None

    @property
    def status_message(self) -> str:
        with self._lock:
            model_status = self._model_status
            model_error = self._model_error
        if model_status != "LOADED":
            return model_error or f"IDS model status: {model_status.lower()}"
        if not self.compatibility.live_prediction_enabled:
            return "Live IDS inference unavailable: feature compatibility incomplete."
        return "IDS model loaded; compatible feature inference is ready."

    def load_model(self) -> bool:
        """Load the saved pipeline without training; errors become visible status."""
        try:
            model = self._model_loader(self.model_path)
            model_names = tuple(str(name) for name in getattr(model, "feature_names_in_", ()))
            if model_names != MODEL_FEATURES:
                raise ModelUnavailableError(
                    "Saved model feature schema does not match the Phase 4 42-feature contract."
                )
        except FileNotFoundError as exc:
            with self._lock:
                self._model = None
                self._model_status = "MISSING"
                self._model_error = str(exc)
            logger.warning("IDS model unavailable: %s", exc)
            return False
        except Exception as exc:
            with self._lock:
                self._model = None
                self._model_status = "ERROR"
                self._model_error = f"IDS model could not be loaded: {exc}"
            logger.exception("IDS model load failed")
            return False

        with self._lock:
            self._model = model
            self._model_status = "LOADED"
            self._model_error = None
        logger.info("Phase 4 IDS model loaded; live compatibility=%s", self.compatibility.live_prediction_enabled)
        return True

    def reset_session(self) -> None:
        with self._lock:
            self._flows_checked = 0
            self._events.clear()
            self._analysis_active = False

    def start_analysis(self) -> None:
        if not self.inference_enabled:
            raise FeatureCompatibilityError(self.status_message)
        with self._lock:
            self._analysis_active = True

    def stop_analysis(self) -> None:
        with self._lock:
            self._analysis_active = False

    def load_recent_events(self, limit: int = 100) -> tuple[SecurityEvent, ...]:
        """Load recent security events saved in SQLite."""
        try:
            return self.event_store.get_recent_events(limit=limit)
        except Exception:
            logger.exception("Failed to load saved security events")
            return ()

    def inspect_completed_flow(self, flow: CompletedFlow) -> FlowReview:
        """Assess a completed live flow; predict only if the full schema is valid."""
        with self._lock:
            self._flows_checked += 1
        try:
            candidate = flow.candidate_features()
            assessment = self.compatibility.assess(candidate)
            if not assessment.compatible:
                return FlowReview(
                    flow.flow_id,
                    "COMPATIBILITY_INCOMPLETE",
                    assessment.reason,
                    assessment.missing_features,
                    assessment.blocked_features,
                )
            if not self.analysis_active:
                return FlowReview(
                    flow.flow_id,
                    "ANALYSIS_STOPPED",
                    "IDS analysis is stopped.",
                    (),
                    (),
                )
            result = self.predict_features(candidate, flow.flow_id)
            event = SecurityEvent.from_prediction(flow, result)

            with self._lock:
                self._events.append(event)

            try:
                self.event_store.save_event(event)
            except Exception:
                logger.exception(
                    "Failed to save security event to SQLite"
                )

            return FlowReview(
                flow.flow_id,
                "PREDICTED",
                "Prediction completed.",
                (),
                (),
                result,
            )
        except Exception as exc:
            logger.exception(
                "Unable to analyze completed flow %s", flow.flow_id
            )
            return FlowReview(
                flow.flow_id,
                "ERROR",
                str(exc),
                (),
                self.compatibility.blocked_feature_names,
            )

    def predict_features(self, features: Mapping[str, object], flow_id: str = "manual") -> IDSResult:
        """Predict a complete record only when this adapter certifies its semantics."""
        clean = validate_feature_record(features, self.compatibility.required_features)
        assessment = self.compatibility.assess(clean)
        if not assessment.compatible:
            raise FeatureCompatibilityError(assessment.reason)
        with self._lock:
            model = self._model
            status = self._model_status
        if model is None:
            if not self.load_model():
                raise ModelUnavailableError(self.model_error or f"IDS model status: {status}")
            with self._lock:
                model = self._model
        if model is None:
            raise ModelUnavailableError("IDS model is unavailable.")

        prediction: Prediction = predict_with_pipeline(clean, model=model)[0]
        return IDSResult(
            flow_id=flow_id,
            prediction=prediction.label,
            is_attack=prediction.class_id == 1,
            attack_probability=prediction.probability,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


def validate_feature_record(
    features: Mapping[str, object],
    required_features: tuple[str, ...] = MODEL_FEATURES,
) -> dict[str, object]:
    """Validate one complete model record without filling or coercing values."""
    if not isinstance(features, Mapping):
        raise MalformedFeatureError("A feature record must be a mapping of field names to values.")
    missing = [name for name in required_features if name not in features]
    if missing:
        raise MissingFeatureError(f"Missing required model feature(s): {', '.join(missing)}")
    extras = [name for name in features if name not in required_features]
    if extras:
        raise MalformedFeatureError(f"Unexpected model feature(s): {', '.join(sorted(extras))}")

    clean: dict[str, object] = {}
    for name in required_features:
        value = features[name]
        if name in CATEGORICAL_FEATURES:
            if not isinstance(value, str) or not value.strip():
                raise MalformedFeatureError(f"Categorical feature {name!r} must be a non-empty string.")
        else:
            if isinstance(value, bool) or not isinstance(value, numbers.Real):
                raise MalformedFeatureError(f"Numeric feature {name!r} must be a finite number.")
            if not math.isfinite(float(value)):
                raise MalformedFeatureError(f"Numeric feature {name!r} must be a finite number.")
        clean[name] = value
    return clean
