"""Robust statistical anomaly scoring using a normal-traffic baseline."""

from __future__ import annotations

import math
from typing import Any, Iterable, Mapping

ANOMALY_FEATURES = (
    "packets_per_second",
    "bytes_per_second",
    "connection_rate",
    "failure_ratio",
    "unique_destination_ports",
)

# Fallback training assumptions keep the project usable before a dataset is fit.
DEFAULT_BASELINE: dict[str, dict[str, float]] = {
    "packets_per_second": {"mean": 8.0, "std": 5.0, "q1": 3.0, "q3": 12.0},
    "bytes_per_second": {"mean": 8_000.0, "std": 9_000.0, "q1": 2_000.0, "q3": 14_000.0},
    "connection_rate": {"mean": 0.8, "std": 1.0, "q1": 0.2, "q3": 1.4},
    "failure_ratio": {"mean": 0.02, "std": 0.06, "q1": 0.0, "q3": 0.0},
    "unique_destination_ports": {"mean": 1.2, "std": 1.0, "q1": 1.0, "q3": 1.0},
}


def _quantile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] * (high - position) + ordered[high] * (position - low)


class AnomalyDetector:
    """Fit baseline statistics on records known to represent normal activity."""

    def __init__(self, baseline: Mapping[str, Mapping[str, float]] | None = None) -> None:
        self.baseline = {key: dict(value) for key, value in (baseline or DEFAULT_BASELINE).items()}
        self.fitted = baseline is not None

    def fit(self, normal_feature_rows: Iterable[Mapping[str, Any]]) -> "AnomalyDetector":
        rows = list(normal_feature_rows)
        if not rows:
            self.baseline = {key: dict(value) for key, value in DEFAULT_BASELINE.items()}
            self.fitted = False
            return self
        fitted: dict[str, dict[str, float]] = {}
        for feature in ANOMALY_FEATURES:
            values = [float(row.get(feature, 0.0) or 0.0) for row in rows]
            mean = sum(values) / len(values)
            variance = sum((value - mean) ** 2 for value in values) / max(len(values), 1)
            fitted[feature] = {
                "mean": mean,
                "std": math.sqrt(variance),
                "q1": _quantile(values, 0.25),
                "q3": _quantile(values, 0.75),
            }
        self.baseline = fitted
        self.fitted = True
        return self

    def explain(self, features: Mapping[str, Any]) -> dict[str, Any]:
        """Return a bounded score and per-feature baseline evidence for triage."""
        details: list[dict[str, float | str]] = []
        for name in ANOMALY_FEATURES:
            value = float(features.get(name, 0.0) or 0.0)
            stats = self.baseline.get(name, DEFAULT_BASELINE[name])
            mean = float(stats.get("mean", 0.0))
            q1 = float(stats.get("q1", mean))
            q3 = float(stats.get("q3", mean))
            std = float(stats.get("std", 0.0))
            floor = {
                "packets_per_second": 0.75,
                "bytes_per_second": 1_000.0,
                "connection_rate": 0.25,
                "failure_ratio": 0.05,
                "unique_destination_ports": 0.5,
            }[name]
            scale = max(std, (q3 - q1) / 1.349, floor)
            # Detection is focused on upward deviations for these telemetry features.
            z_score = max(0.0, (value - mean) / scale)
            # Below ~1.5 robust deviations is treated as routine baseline variation.
            component = min(100.0, max(0.0, (z_score - 1.5) * 24.0))
            details.append({
                "feature": name,
                "value": round(value, 4),
                "baseline_mean": round(mean, 4),
                "standard_deviation": round(std, 4),
                "robust_scale": round(scale, 4),
                "positive_z_score": round(z_score, 3),
                "component_score": int(round(component)),
            })
        components = [float(item["component_score"]) for item in details]
        score = 0.60 * max(components, default=0.0) + 0.40 * (sum(components) / max(len(components), 1))
        return {
            "score": int(round(max(0.0, min(100.0, score)))),
            "features": sorted(details, key=lambda item: float(item["component_score"]), reverse=True),
        }

    def score(self, features: Mapping[str, Any]) -> int:
        return int(self.explain(features)["score"])


def calculate_anomaly_score(
    features: Mapping[str, Any],
    baseline: Mapping[str, Mapping[str, float]] | None = None,
) -> int:
    """Convenience wrapper used in tests, scripts, and the dashboard pipeline."""
    detector = AnomalyDetector(baseline=baseline)
    return detector.score(features)
