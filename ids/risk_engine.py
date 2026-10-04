"""Hybrid signal weighting, risk classification, and severity mapping."""

from __future__ import annotations

from typing import Mapping

from ids.config import DEFAULT_WEIGHTS_WITH_ML, DEFAULT_WEIGHTS_WITHOUT_ML


def calculate_rule_risk(matched_rules: list[dict]) -> int:
    """Map rule severity to a bounded score, with a small corroboration uplift."""
    severity_points = {"INFO": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 75, "CRITICAL": 95}
    if not matched_rules:
        return 0
    strongest = max(severity_points.get(str(rule.get("severity", "LOW")).upper(), 30) for rule in matched_rules)
    corroboration = min(10, max(0, (len(matched_rules) - 1) * 5))
    return min(100, strongest + corroboration)


def calculate_risk_score(
    rule_score: float,
    anomaly_score: float,
    ml_probability: float | None = None,
    weights: Mapping[str, float] | None = None,
) -> int:
    """Blend rule, statistical, and optional ML signals into an integer 0–100.

    ``ml_probability`` is in the 0.0–1.0 range. Weights are normalized so custom
    values do not need to add up to exactly one.
    """
    rule_value = max(0.0, min(100.0, float(rule_score)))
    anomaly_value = max(0.0, min(100.0, float(anomaly_score)))
    if ml_probability is None:
        selected = dict(weights or DEFAULT_WEIGHTS_WITHOUT_ML)
        signals = {"rules": rule_value, "anomaly": anomaly_value}
    else:
        probability = max(0.0, min(1.0, float(ml_probability)))
        selected = dict(weights or DEFAULT_WEIGHTS_WITH_ML)
        signals = {"rules": rule_value, "anomaly": anomaly_value, "ml": probability * 100.0}
    usable = {key: max(0.0, float(value)) for key, value in selected.items() if key in signals}
    total_weight = sum(usable.values())
    if total_weight <= 0:
        raise ValueError("At least one positive weight must be configured")
    score = sum(signals[key] * weight for key, weight in usable.items()) / total_weight
    return int(round(max(0.0, min(100.0, score))))


def classify_risk(score: float) -> str:
    value = max(0.0, min(100.0, float(score)))
    if value <= 20:
        return "NORMAL"
    if value <= 40:
        return "LOW RISK"
    if value <= 60:
        return "SUSPICIOUS"
    if value <= 80:
        return "HIGH RISK"
    return "CRITICAL INVESTIGATION"


def severity_for_risk(score: float) -> str:
    value = max(0.0, min(100.0, float(score)))
    if value <= 20:
        return "INFO"
    if value <= 40:
        return "LOW"
    if value <= 60:
        return "MEDIUM"
    if value <= 80:
        return "HIGH"
    return "CRITICAL"


def detection_classification(score: float, matched_rules: list[dict] | None = None) -> str:
    """Project-facing NORMAL / SUSPICIOUS / POTENTIAL INTRUSION label."""
    if matched_rules or float(score) > 40:
        return "POTENTIAL INTRUSION" if float(score) > 60 else "SUSPICIOUS"
    return "NORMAL"
