"""Load and score with an optional supervised or unsupervised sklearn model."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping

ML_FEATURES = [
    "packet_count", "byte_count", "duration_seconds", "bytes_per_second",
    "packets_per_second", "connection_count", "failed_connection_count",
    "syn_count", "rst_count", "average_packet_size", "failure_ratio",
    "syn_ratio", "unique_destination_ports", "unique_destination_ips", "connection_rate",
]
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "random_forest_model.joblib"


def feature_vector(features: Mapping[str, Any], feature_names: list[str] | None = None) -> list[float]:
    names = feature_names or ML_FEATURES
    vector = []
    for name in names:
        value = float(features.get(name, 0.0) or 0.0)
        if not math.isfinite(value):
            value = 0.0
        vector.append(value)
    return vector


def load_model(path: str | Path = DEFAULT_MODEL_PATH) -> dict[str, Any] | None:
    """Return None when optional ML dependencies/artifact are not installed."""
    model_path = Path(path)
    if not model_path.exists():
        return None
    try:
        import joblib
        bundle = joblib.load(model_path)
        if not isinstance(bundle, dict) or "model" not in bundle:
            raise ValueError("Model artifact is not a SentinelFlow model bundle")
        return bundle
    except ImportError:
        return None


def predict_probability(bundle: Mapping[str, Any], features: Mapping[str, Any]) -> float:
    """Return P(suspicious) or an anomaly-derived probability in [0, 1]."""
    model = bundle["model"]
    names = list(bundle.get("feature_names", ML_FEATURES))
    vector = [feature_vector(features, names)]
    model_name = str(bundle.get("model_name", "random_forest"))
    if model_name == "isolation_forest":
        decision = float(model.decision_function(vector)[0])
        # IsolationForest's more-negative scores indicate more anomalous samples.
        return 1.0 / (1.0 + math.exp(max(-40.0, min(40.0, decision * 8.0))))
    probabilities = model.predict_proba(vector)[0]
    classes = list(getattr(model, "classes_", [0, 1]))
    if 1 in classes:
        return float(probabilities[classes.index(1)])
    return float(probabilities[-1])
