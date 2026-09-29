import pytest

def test_normal_classification(risk_engine):
    result = risk_engine.evaluate(rule_matches=[], anomaly_score=10, ml_prob=0.1)
    assert result["level"] == "NORMAL"

def test_suspicious_classification(risk_engine):
    result = risk_engine.evaluate(rule_matches=[{"rule_id": "IDS-005"}], anomaly_score=40, ml_prob=0.4)
    assert result["level"] == "SUSPICIOUS"

def test_high_risk_classification(risk_engine):
    result = risk_engine.evaluate(rule_matches=[{"rule_id": "IDS-001"}], anomaly_score=70, ml_prob=0.8)
    assert result["level"] in ["HIGH RISK", "CRITICAL INVESTIGATION"]

def test_critical_classification(risk_engine):
    result = risk_engine.evaluate(rule_matches=[{"rule_id": "IDS-001"}, {"rule_id": "IDS-006"}], anomaly_score=95, ml_prob=0.95)
    assert result["level"] == "CRITICAL INVESTIGATION"

def test_weight_configuration(risk_engine):
    assert "rule" in risk_engine.weights
