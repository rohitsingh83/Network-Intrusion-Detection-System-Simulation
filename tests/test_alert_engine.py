import pytest

def test_alert_creation(alert_engine, sample_suspicious_flow):
    risk_result = {"level": "HIGH RISK", "score": 85}
    alert = alert_engine.process(sample_suspicious_flow, risk_result)
    assert alert is not None

def test_no_alert_low_risk(alert_engine, sample_normal_flow):
    risk_result = {"level": "NORMAL", "score": 10}
    alert = alert_engine.process(sample_normal_flow, risk_result)
    assert alert is None

def test_alert_id_format(alert_engine, sample_suspicious_flow):
    risk_result = {"level": "HIGH RISK", "score": 85}
    alert = alert_engine.process(sample_suspicious_flow, risk_result)
    assert alert["alert_id"].startswith("ALT-")

def test_alert_severity_assignment(alert_engine, sample_suspicious_flow):
    risk_result = {"level": "CRITICAL INVESTIGATION", "score": 95}
    alert = alert_engine.process(sample_suspicious_flow, risk_result)
    assert alert["severity"] == "CRITICAL"

def test_investigation_steps(alert_engine, sample_suspicious_flow):
    risk_result = {"level": "HIGH RISK", "score": 85, "triggers": ["IDS-001"]}
    alert = alert_engine.process(sample_suspicious_flow, risk_result)
    assert len(alert.get("investigation_steps", [])) > 0
