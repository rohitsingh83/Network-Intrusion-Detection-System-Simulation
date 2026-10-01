"""
Comprehensive 30-Scenario Defense Test Suite
============================================
Implements all 30 scenarios mandated by Section 26 of the Master IDS Specification:
  1. Normal TCP flow
  2. Normal UDP flow
  3. Normal DNS flow
  4. Normal HTTPS flow
  5. High connection rate
  6. Repeated failed connections
  7. Multi-port pattern
  8. SYN-heavy pattern
  9. High traffic volume
 10. Invalid source IP
 11. Invalid destination IP
 12. Invalid source port
 13. Invalid destination port
 14. Unsupported protocol
 15. Missing packet count
 16. Zero duration
 17. Feature extraction
 18. Rule detection
 19. Anomaly score
 20. Risk score
 21. Alert creation
 22. Alert correlation
 23. Alert status update
 24. Analyst note
 25. Database storage
 26. Dashboard statistics
 27. ML prediction
 28. API validation
 29. Empty dataset
 30. Duplicate event handling
"""

import pytest
import datetime
from fastapi.testclient import TestClient
from backend.app import app
from ids.feature_extractor import extract_features, validate_flow
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelator
from backend.database import DatabaseManager

client = TestClient(app)


# ---------------------------------------------------------------------------
# Tests 1 - 4: Normal Traffic Scenarios
# ---------------------------------------------------------------------------
def test_01_normal_tcp_flow():
    flow = {"source_ip": "192.0.2.10", "destination_ip": "198.51.100.20", "source_port": 50123, "destination_port": 80, "protocol": "TCP", "packet_count": 15, "byte_count": 12000, "duration": 1.5, "connection_count": 1, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0}
    feats = extract_features(flow)
    re = RuleEngine()
    matches = re.analyze_flow(feats, raw_flow=flow)
    assert len(matches) == 0, f"Normal TCP flow should trigger 0 rules, got: {matches}"

def test_02_normal_udp_flow():
    flow = {"source_ip": "192.0.2.11", "destination_ip": "198.51.100.53", "source_port": 51234, "destination_port": 53, "protocol": "UDP", "packet_count": 2, "byte_count": 160, "duration": 0.05, "connection_count": 1, "failed_connection_count": 0, "syn_count": 0, "rst_count": 0}
    feats = extract_features(flow)
    assert feats["protocol"] == "UDP"
    assert feats["byte_count"] == 160

def test_03_normal_dns_flow():
    flow = {"source_ip": "192.0.2.12", "destination_ip": "198.51.100.53", "source_port": 49152, "destination_port": 53, "protocol": "UDP", "packet_count": 4, "byte_count": 320, "duration": 0.1, "connection_count": 1, "failed_connection_count": 0, "syn_count": 0, "rst_count": 0}
    is_valid, _ = validate_flow(flow)
    assert is_valid is True
    feats = extract_features(flow)
    assert feats["destination_port"] == 53

def test_04_normal_https_flow():
    flow = {"source_ip": "192.0.2.14", "destination_ip": "198.51.100.44", "source_port": 52100, "destination_port": 443, "protocol": "TCP", "packet_count": 25, "byte_count": 18500, "duration": 2.1, "connection_count": 2, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0}
    feats = extract_features(flow)
    re = RuleEngine()
    assert len(re.analyze_flow(feats, raw_flow=flow)) == 0


# ---------------------------------------------------------------------------
# Tests 5 - 9: Attack-like Synthetic Anomalies
# ---------------------------------------------------------------------------
def test_05_high_connection_rate():
    flow = {"source_ip": "192.0.2.20", "destination_ip": "198.51.100.20", "source_port": 41234, "destination_port": 80, "protocol": "TCP", "packet_count": 50, "byte_count": 4000, "duration": 0.1, "connection_count": 100, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0}
    feats = extract_features(flow)
    re = RuleEngine()
    matches = re.analyze_flow(feats, raw_flow=flow)
    rule_ids = [m["rule_id"] for m in matches]
    assert "IDS-001" in rule_ids or "IDS-007" in rule_ids

def test_06_repeated_failed_connections():
    flow = {"source_ip": "192.0.2.21", "destination_ip": "198.51.100.22", "source_port": 42222, "destination_port": 22, "protocol": "TCP", "packet_count": 30, "byte_count": 1800, "duration": 1.0, "connection_count": 25, "failed_connection_count": 20, "syn_count": 5, "rst_count": 15}
    feats = extract_features(flow)
    re = RuleEngine()
    matches = re.analyze_flow(feats, raw_flow=flow)
    assert any(m["rule_id"] == "IDS-002" for m in matches)

def test_07_multi_port_pattern():
    flow = {"source_ip": "192.0.2.22", "destination_ip": "198.51.100.30", "source_port": 43333, "destination_port": 80, "protocol": "TCP", "packet_count": 10, "byte_count": 500, "duration": 0.5, "connection_count": 20, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0, "unique_destination_ports": 25}
    feats = extract_features(flow)
    re = RuleEngine()
    matches = re.analyze_flow(feats, raw_flow=flow)
    assert any(m["rule_id"] == "IDS-003" for m in matches)

def test_08_syn_heavy_pattern():
    flow = {"source_ip": "192.0.2.23", "destination_ip": "198.51.100.80", "source_port": 44444, "destination_port": 80, "protocol": "TCP", "packet_count": 200, "byte_count": 12000, "duration": 1.0, "connection_count": 1, "failed_connection_count": 0, "syn_count": 180, "rst_count": 0}
    feats = extract_features(flow)
    re = RuleEngine()
    matches = re.analyze_flow(feats, raw_flow=flow)
    assert any(m["rule_id"] == "IDS-004" for m in matches)

def test_09_high_traffic_volume():
    flow = {"source_ip": "192.0.2.24", "destination_ip": "198.51.100.90", "source_port": 45555, "destination_port": 443, "protocol": "TCP", "packet_count": 50000, "byte_count": 75000000, "duration": 10.0, "connection_count": 1, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0}
    feats = extract_features(flow)
    re = RuleEngine()
    matches = re.analyze_flow(feats, raw_flow=flow)
    assert any(m["rule_id"] == "IDS-006" for m in matches)


# ---------------------------------------------------------------------------
# Tests 10 - 16: Input Validation & Edge Cases
# ---------------------------------------------------------------------------
def test_10_invalid_source_ip():
    flow = {"source_ip": "999.999.999.999", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": 80, "protocol": "TCP"}
    is_valid, _ = validate_flow(flow)
    assert is_valid is False

def test_11_invalid_destination_ip():
    flow = {"source_ip": "192.0.2.1", "destination_ip": "invalid-ip-string", "source_port": 1024, "destination_port": 80, "protocol": "TCP"}
    is_valid, _ = validate_flow(flow)
    assert is_valid is False

def test_12_invalid_source_port():
    flow = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 70000, "destination_port": 80, "protocol": "TCP"}
    is_valid, _ = validate_flow(flow)
    assert is_valid is False

def test_13_invalid_destination_port():
    flow = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": -1, "protocol": "TCP"}
    is_valid, _ = validate_flow(flow)
    assert is_valid is False

def test_14_unsupported_protocol():
    flow = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": 80, "protocol": "BOGUS"}
    is_valid, _ = validate_flow(flow)
    assert is_valid is False

def test_15_missing_packet_count():
    flow = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": 80, "protocol": "TCP"}
    feats = extract_features(flow)
    assert feats["packet_count"] == 0

def test_16_zero_duration():
    flow = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": 80, "protocol": "TCP", "byte_count": 1000, "duration": 0.0}
    feats = extract_features(flow)
    assert feats["bytes_per_second"] >= 0
    assert not (feats["bytes_per_second"] == float("inf"))


# ---------------------------------------------------------------------------
# Tests 17 - 22: Engine Algorithms & Pipeline
# ---------------------------------------------------------------------------
def test_17_feature_extraction():
    raw = {"source_ip": "192.0.2.50", "destination_ip": "198.51.100.50", "source_port": 50000, "destination_port": 80, "protocol": "TCP", "packet_count": 10, "byte_count": 1000, "duration": 2.0, "connection_count": 4, "failed_connection_count": 2, "syn_count": 2, "rst_count": 1}
    f = extract_features(raw)
    assert f["bytes_per_second"] == 500.0
    assert f["packets_per_second"] == 5.0
    assert f["failure_ratio"] == 0.5
    assert f["syn_ratio"] == 0.2

def test_18_rule_detection():
    re = RuleEngine()
    unusual = {"destination_port": 4444}
    matches = re.analyze_flow({"unique_destination_ports": 0}, raw_flow=unusual)
    assert any(m["rule_id"] == "IDS-005" for m in matches)

def test_19_anomaly_score():
    ad = AnomalyDetector()
    normals = [{"packets_per_second": 10, "bytes_per_second": 1000, "connection_rate": 1, "failure_ratio": 0.0, "syn_ratio": 0.1, "average_packet_size": 100} for _ in range(20)]
    ad.update_baseline(normals)
    outlier = {"packets_per_second": 10000, "bytes_per_second": 1000000, "connection_rate": 500, "failure_ratio": 0.9, "syn_ratio": 0.9, "average_packet_size": 1000}
    res = ad.calculate_anomaly_score(outlier)
    assert res["anomaly_score"] > 50

def test_20_risk_score():
    risk = RiskEngine(ml_enabled=False, weights={"rule": 0.6, "anomaly": 0.4, "ml": 0.0})
    res = risk.calculate_risk(rule_results=[{"severity": "HIGH"}], anomaly_result={"anomaly_score": 80})
    assert res["risk_score"] > 60
    assert res["classification"] in ["HIGH RISK", "CRITICAL INVESTIGATION"]

def test_21_alert_creation():
    ae = AlertEngine()
    flow = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1234, "destination_port": 80, "protocol": "TCP"}
    risk = {"risk_score": 75, "classification": "HIGH RISK", "severity": "HIGH"}
    rules = [{"rule_id": "IDS-001", "name": "High Connection Rate", "description": "Burst"}]
    alert = ae.generate_alert(flow, risk, rule_results=rules, anomaly_result={"anomaly_score": 60})
    assert alert is not None
    assert alert["severity"] == "HIGH"
    assert "ALT-" in alert["alert_id"]

def test_22_alert_correlation():
    corr = AlertCorrelator(time_window=60)
    a1 = {"alert_id": "ALT-1", "source_ip": "192.0.2.99", "alert_type": "SYN Flood", "timestamp": "2026-10-01T12:00:01"}
    a2 = {"alert_id": "ALT-2", "source_ip": "192.0.2.99", "alert_type": "SYN Flood", "timestamp": "2026-10-01T12:00:15"}
    groups = corr.correlate([a1, a2])
    assert len(groups) == 1
    incident = corr.create_incident(groups[0])
    assert incident.get("alert_count") == 2


# ---------------------------------------------------------------------------
# Tests 23 - 26: State Management & Database Operations
# ---------------------------------------------------------------------------
def test_23_alert_status_update():
    db = DatabaseManager(":memory:")
    db.initialize()
    alert_record = {"alert_id": "ALT-TEST-1", "flow_id": "F-1", "rule_id": "IDS-001", "alert_type": "Test", "severity": "HIGH", "description": "desc", "risk_score": 70, "anomaly_score": 20, "ml_score": 0.5, "status": "NEW", "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "protocol": "TCP", "source_port": 100, "destination_port": 80, "created_at": datetime.datetime.now().isoformat(), "updated_at": datetime.datetime.now().isoformat()}
    db.insert_alert(alert_record)
    db.update_alert_status("ALT-TEST-1", "INVESTIGATING", analyst="Jane Doe")
    updated = db.get_alert("ALT-TEST-1")
    assert updated["status"] == "INVESTIGATING"

def test_24_analyst_note():
    db = DatabaseManager(":memory:")
    db.initialize()
    alert_record = {"alert_id": "ALT-TEST-2", "flow_id": "F-2", "rule_id": "IDS-001", "alert_type": "Test", "severity": "MEDIUM", "description": "desc", "risk_score": 50, "anomaly_score": 10, "ml_score": 0.2, "status": "NEW", "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "protocol": "TCP", "source_port": 100, "destination_port": 80, "created_at": datetime.datetime.now().isoformat(), "updated_at": datetime.datetime.now().isoformat()}
    db.insert_alert(alert_record)
    db.insert_note({"note_id": "N-1", "alert_id": "ALT-TEST-2", "analyst": "John Doe", "note": "False positive due to routine backup.", "action": "RESOLVE", "created_at": datetime.datetime.now().isoformat()})
    notes = db.get_alert_notes("ALT-TEST-2")
    assert len(notes) >= 1
    assert "routine backup" in notes[0]["note"]

def test_25_database_storage():
    db = DatabaseManager(":memory:")
    db.initialize()
    db.insert_flow({"flow_id": "F-STORAGE", "timestamp": datetime.datetime.now().isoformat(), "source_ip": "192.0.2.5", "destination_ip": "198.51.100.5", "source_port": 1234, "destination_port": 80, "protocol": "TCP", "packet_count": 10, "byte_count": 500, "duration": 1.0, "connection_count": 1, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0, "average_packet_size": 50.0, "risk_score": 10.0, "classification": "NORMAL", "created_at": datetime.datetime.now().isoformat()})
    fetched = db.get_flow("F-STORAGE")
    assert fetched is not None
    assert fetched["source_ip"] == "192.0.2.5"

def test_26_dashboard_statistics():
    db = DatabaseManager(":memory:")
    db.initialize()
    db.insert_flow({"flow_id": "F-D1", "timestamp": "2026-10-01", "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1, "destination_port": 80, "protocol": "TCP", "packet_count": 1, "byte_count": 1, "duration": 1, "connection_count": 1, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0, "average_packet_size": 1, "risk_score": 10, "classification": "NORMAL", "created_at": "2026-10-01"})
    stats = db.get_dashboard_stats()
    assert stats["total_flows"] == 1
    assert stats["normal_flows"] == 1


# ---------------------------------------------------------------------------
# Tests 27 - 30: ML, API, Empty State & Idempotency
# ---------------------------------------------------------------------------
def test_27_ml_prediction_fallback():
    from ml.predict import MLPredictor
    pred = MLPredictor("non_existent_model.joblib", lazy=True)
    res = pred.predict({"packets_per_second": 10})
    assert "prediction" in res

def test_28_api_validation():
    # Sending invalid data (e.g. invalid port) to POST /api/flows
    bad_payload = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 99999, "destination_port": 80}
    res = client.post("/api/flows", json=bad_payload)
    assert res.status_code == 422, "Out of bounds port must trigger 422 Unprocessable Entity"

def test_29_empty_dataset_handling():
    ad = AnomalyDetector()
    ad.update_baseline([])  # Empty baseline
    res = ad.calculate_anomaly_score({"packets_per_second": 100})
    assert res["anomaly_score"] == 0, "Empty baseline must yield 0 score gracefully"

def test_30_duplicate_event_handling():
    db = DatabaseManager(":memory:")
    db.initialize()
    flow = {"flow_id": "F-DUP", "timestamp": "2026-10-01T10:00:00", "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1234, "destination_port": 80, "protocol": "TCP", "packet_count": 5, "byte_count": 200, "duration": 1.0, "connection_count": 1, "failed_connection_count": 0, "syn_count": 1, "rst_count": 0, "average_packet_size": 40.0, "risk_score": 5.0, "classification": "NORMAL", "created_at": "2026-10-01T10:00:00"}
    db.insert_flow(flow)
    db.insert_flow(flow)  # Re-insert same flow
    flows = db.get_flows(limit=10)
    assert len(flows) == 1, "Duplicate flow_id must update/replace without throwing error"
