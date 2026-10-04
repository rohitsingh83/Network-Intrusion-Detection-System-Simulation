"""One-flow hybrid detection pipeline: validate → rules → anomaly/ML → risk → alert."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from ids.alert_engine import generate_alert
from ids.anomaly_detector import AnomalyDetector
from ids.feature_extractor import extract_network_features
from ids.risk_engine import (
    calculate_rule_risk,
    calculate_risk_score,
    classify_risk,
    detection_classification,
    severity_for_risk,
)
from ids.rule_engine import analyze_flow

MLScorer = Callable[[Mapping[str, Any]], float]


class DetectionPipeline:
    def __init__(
        self,
        anomaly_detector: AnomalyDetector | None = None,
        ml_scorer: MLScorer | None = None,
        weights: Mapping[str, float] | None = None,
    ) -> None:
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.ml_scorer = ml_scorer
        self.weights = weights

    def analyze(
        self,
        flow: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
        configured_rules: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        features = extract_network_features(flow, context)
        matched_rules = analyze_flow(features, configured_rules)
        anomaly_result = self.anomaly_detector.explain(features)
        anomaly_score = int(anomaly_result["score"])
        ml_probability = None
        if self.ml_scorer is not None:
            try:
                ml_probability = max(0.0, min(1.0, float(self.ml_scorer(features))))
            except Exception:
                # ML is an enrichment layer; an optional-model error must not stop rules.
                ml_probability = None
        rule_score = calculate_rule_risk(matched_rules)
        risk_score = calculate_risk_score(
            rule_score, anomaly_score, ml_probability=ml_probability, weights=self.weights
        )
        evaluation = {
            "features": features,
            "matched_rules": matched_rules,
            "rule_score": rule_score,
            "anomaly_score": anomaly_score,
            "anomaly_evidence": anomaly_result["features"],
            "ml_probability": ml_probability,
            "risk_score": risk_score,
            "risk_band": classify_risk(risk_score),
            "classification": detection_classification(risk_score, matched_rules),
            "severity": severity_for_risk(risk_score),
        }
        evaluation["alert"] = generate_alert(flow, evaluation)
        return evaluation
