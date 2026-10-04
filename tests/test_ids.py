"""Forty-two regression tests covering the synthetic IDS end-to-end."""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.database import init_db
from backend.services import DuplicateFlowError, IDSService
from ids.alert_engine import generate_alert
from ids.anomaly_detector import calculate_anomaly_score
from ids.correlation import alerts_should_correlate, correlation_key
from ids.feature_extractor import extract_network_features
from ids.pipeline import DetectionPipeline
from ids.risk_engine import calculate_risk_score, classify_risk
from ids.rule_engine import analyze_flow
from ml.predict import predict_probability
from simulator.generate_dataset import generate_records
from simulator.scenarios import make_synthetic_flow
from simulator.traffic_simulator import validate_local_api_url


@pytest.fixture
def temp_app(tmp_path):
    database = tmp_path / "test_ids.sqlite"
    app = create_app(db_path=database, dataset_path=tmp_path / "missing.csv", seed_demo=False)
    with TestClient(app) as client:
        yield client, app.state.service


def safe_flow(scenario: str = "NORMAL_WEB", flow_id: str = "TEST-FLOW", **overrides):
    record = make_synthetic_flow(scenario, flow_id=flow_id)
    record.update(overrides)
    return record


def test_01_normal_tcp_flow():
    features = extract_network_features(safe_flow("NORMAL_WEB"))
    assert features["protocol"] == "TCP"
    assert features["destination_port"] in (80, 443)


def test_02_normal_udp_flow():
    features = extract_network_features(safe_flow("NORMAL_DNS"))
    assert features["protocol"] == "UDP"


def test_03_normal_dns_flow():
    flow = safe_flow("NORMAL_DNS")
    features = extract_network_features(flow)
    assert flow["destination_port"] == 53 and features["failure_ratio"] == 0


def test_04_normal_https_flow():
    flow = safe_flow("NORMAL_WEB")
    flow["destination_port"] = 443
    assert extract_network_features(flow)["destination_port"] == 443


def test_05_high_connection_rate_triggers_rule():
    features = extract_network_features(safe_flow("HIGH_CONNECTION_RATE"))
    assert "IDS-001" in {rule["rule_id"] for rule in analyze_flow(features)}


def test_06_repeated_failures_triggers_rule():
    features = extract_network_features(safe_flow("REPEATED_FAILED_CONNECTIONS"))
    assert "IDS-002" in {rule["rule_id"] for rule in analyze_flow(features)}


def test_07_multi_port_pattern_triggers_rule():
    features = extract_network_features(safe_flow("MULTI_PORT_PROBING_PATTERN"))
    assert features["unique_destination_ports"] >= 12
    assert "IDS-003" in {rule["rule_id"] for rule in analyze_flow(features)}


def test_08_syn_heavy_pattern_triggers_rule():
    features = extract_network_features(safe_flow("SYN_HEAVY_PATTERN"))
    assert "IDS-004" in {rule["rule_id"] for rule in analyze_flow(features)}


def test_09_high_volume_triggers_rule():
    features = extract_network_features(safe_flow("HIGH_TRAFFIC_VOLUME"))
    assert "IDS-006" in {rule["rule_id"] for rule in analyze_flow(features)}


def test_10_invalid_source_ip_rejected():
    flow = safe_flow()
    flow["source_ip"] = "999.2.2.1"
    with pytest.raises(ValueError, match="source_ip"):
        extract_network_features(flow)


def test_11_invalid_destination_ip_rejected():
    flow = safe_flow()
    flow["destination_ip"] = "not-an-ip"
    with pytest.raises(ValueError, match="destination_ip"):
        extract_network_features(flow)


def test_12_invalid_source_port_rejected():
    flow = safe_flow()
    flow["source_port"] = 65536
    with pytest.raises(ValueError, match="source_port"):
        extract_network_features(flow)


def test_13_invalid_destination_port_rejected():
    flow = safe_flow()
    flow["destination_port"] = -1
    with pytest.raises(ValueError, match="destination_port"):
        extract_network_features(flow)


def test_14_unsupported_protocol_rejected():
    flow = safe_flow()
    flow["protocol"] = "SCTP-UNKNOWN"
    with pytest.raises(ValueError, match="protocol"):
        extract_network_features(flow)


def test_15_missing_packet_count_is_safe():
    flow = safe_flow()
    flow.pop("packet_count")
    features = extract_network_features(flow)
    assert features["packet_count"] == 0
    assert math.isfinite(features["packets_per_second"])


def test_16_zero_duration_is_finite():
    flow = safe_flow()
    flow.update(duration_seconds=0, packet_count=3, byte_count=30)
    features = extract_network_features(flow)
    assert features["packets_per_second"] == 3000
    assert math.isfinite(features["bytes_per_second"])


def test_17_feature_extraction_derives_rates_and_ratios():
    flow = safe_flow()
    flow.update(packet_count=20, byte_count=2000, duration_seconds=2,
                connection_count=8, failed_connection_count=2, syn_count=10)
    features = extract_network_features(flow)
    assert features["bytes_per_second"] == 1000
    assert features["packets_per_second"] == 10
    assert features["failure_ratio"] == 0.25
    assert features["syn_ratio"] == 0.5
    assert features["connection_rate"] == 4


def test_18_signature_match_contains_evidence():
    features = extract_network_features(safe_flow("HIGH_CONNECTION_RATE"))
    matches = analyze_flow(features)
    assert matches and matches[0]["rule_id"].startswith("IDS-")
    assert matches[0]["evidence"]


def test_19_anomaly_score_is_bounded():
    features = extract_network_features(safe_flow("HIGH_TRAFFIC_VOLUME"))
    score = calculate_anomaly_score(features)
    assert 0 <= score <= 100
    explanation = DetectionPipeline().analyze(safe_flow("HIGH_TRAFFIC_VOLUME"))["anomaly_evidence"]
    assert explanation and explanation[0]["feature"]


def test_20_risk_score_is_bounded():
    assert calculate_risk_score(140, -20) == 60
    assert calculate_risk_score(10, 10, 0.5) == 22


def test_21_alert_creation_has_triage_fields():
    flow = safe_flow("HIGH_CONNECTION_RATE")
    evaluation = DetectionPipeline().analyze(flow)
    alert = generate_alert(flow, evaluation)
    assert alert is not None
    assert {"alert_id", "timestamp", "source_ip", "severity", "risk_score", "status"} <= set(alert)


def test_22_alerts_with_same_source_and_type_correlate():
    first = {"source_ip": "192.0.2.5", "alert_type": "Repeated failures", "timestamp": "2026-01-01T00:00:00Z"}
    second = {"source_ip": "192.0.2.5", "alert_type": "Repeated failures", "timestamp": "2026-01-01T00:00:30Z"}
    assert alerts_should_correlate(first, second, 60)


def test_23_alerts_from_different_sources_do_not_correlate():
    first = {"source_ip": "192.0.2.5", "alert_type": "Repeated failures", "timestamp": "2026-01-01T00:00:00Z"}
    second = {"source_ip": "192.0.2.6", "alert_type": "Repeated failures", "timestamp": "2026-01-01T00:00:30Z"}
    assert not alerts_should_correlate(first, second, 60)


def test_24_correlation_key_normalizes_alert_type():
    assert correlation_key("192.0.2.1", "High Rate") == correlation_key("192.0.2.1", "HIGH RATE")


def test_25_database_storage_and_duplicate_handling(tmp_path):
    path = tmp_path / "store.sqlite"
    init_db(path)
    service = IDSService(path, dataset_path=tmp_path / "missing.csv")
    flow = safe_flow("NORMAL_WEB", "UNIQUE-FLOW-25")
    service.ingest_flow(flow)
    assert service.get_flow("UNIQUE-FLOW-25") is not None
    with pytest.raises(DuplicateFlowError):
        service.ingest_flow(flow)


def test_26_dashboard_stats_endpoint(temp_app):
    client, _ = temp_app
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    assert response.json()["total_flows"] == 0


def test_27_ml_prediction_returns_probability():
    class FakeModel:
        classes_ = [0, 1]
        def predict_proba(self, X):
            return [[0.2, 0.8]]
    probability = predict_probability({"model": FakeModel(), "model_name": "random_forest"}, {"packet_count": 10})
    assert probability == pytest.approx(0.8)


def test_28_api_rejects_malformed_ip(temp_app):
    client, _ = temp_app
    flow = safe_flow("NORMAL_WEB", "API-IP")
    flow["source_ip"] = "bad-ip"
    response = client.post("/api/flows", json=flow)
    assert response.status_code == 422


def test_29_empty_dataset_generator_returns_empty_list():
    assert generate_records(count=0, seed=42) == []


def test_30_duplicate_event_api_returns_conflict(temp_app):
    client, _ = temp_app
    flow = safe_flow("NORMAL_WEB", "API-DUPLICATE")
    assert client.post("/api/flows", json=flow).status_code == 201
    assert client.post("/api/flows", json=flow).status_code == 409


def test_31_api_rejects_out_of_range_port(temp_app):
    client, _ = temp_app
    flow = safe_flow("NORMAL_WEB", "API-PORT")
    flow["destination_port"] = 99999
    assert client.post("/api/flows", json=flow).status_code == 422


def test_32_status_update_and_incident_timeline(temp_app):
    client, _ = temp_app
    flow = safe_flow("HIGH_CONNECTION_RATE", "API-STATUS")
    response = client.post("/api/flows", json=flow)
    alert = response.json()["alert"]
    assert alert
    updated = client.put(f"/api/alerts/{alert['alert_id']}/status", json={"status": "INVESTIGATING", "note": "Reviewed synthetic context"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "INVESTIGATING"
    assert updated.json()["timeline"]


def test_33_analyst_note_is_persisted(temp_app):
    client, _ = temp_app
    response = client.post("/api/flows", json=safe_flow("REPEATED_FAILED_CONNECTIONS", "API-NOTE"))
    alert_id = response.json()["alert"]["alert_id"]
    note = client.post(f"/api/alerts/{alert_id}/notes", json={"note": "Reviewed auth metadata", "author": "student"})
    assert note.status_code == 201
    assert note.json()["notes"][0]["note"] == "Reviewed auth metadata"


def test_34_rules_endpoint_can_change_threshold(temp_app):
    client, _ = temp_app
    response = client.put("/api/rules/IDS-001", json={"threshold": 18, "enabled": True})
    assert response.status_code == 200
    assert response.json()["threshold"] == 18


def test_35_flow_api_get_returns_engineered_features(temp_app):
    client, _ = temp_app
    flow = safe_flow("NORMAL_WEB", "API-GET")
    assert client.post("/api/flows", json=flow).status_code == 201
    response = client.get("/api/flows/API-GET")
    assert response.status_code == 200
    assert "features" in response.json()


def test_36_invalid_status_transition_returns_conflict(temp_app):
    client, _ = temp_app
    result = client.post("/api/flows", json=safe_flow("HIGH_CONNECTION_RATE", "API-TRANSITION")).json()
    alert_id = result["alert"]["alert_id"]
    client.put(f"/api/alerts/{alert_id}/status", json={"status": "RESOLVED"})
    response = client.put(f"/api/alerts/{alert_id}/status", json={"status": "FALSE_POSITIVE"})
    assert response.status_code == 409


def test_37_detection_classification_is_explainable():
    low = calculate_risk_score(0, 0)
    high = calculate_risk_score(75, 80)
    assert classify_risk(low) == "NORMAL"
    assert classify_risk(high) in {"HIGH RISK", "CRITICAL INVESTIGATION"}


def test_38_synthetic_generator_uses_documentation_ip_ranges():
    flow = safe_flow("NORMAL_WEB")
    assert flow["source_ip"].startswith("192.0.2.")
    assert flow["destination_ip"].startswith(("198.51.100.", "203.0.113."))


def test_39_simulation_replay_endpoint_is_data_only(temp_app):
    client, _ = temp_app
    response = client.post("/api/simulation/replay", json={"mode": "mixed", "count": 6, "seed": 4})
    assert response.status_code == 200
    assert response.json()["records_processed"] == 6
    assert "No packets" in response.json()["notice"]


def test_40_health_endpoint_is_available(temp_app):
    client, _ = temp_app
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "synthetic-data-only"


def test_41_repeated_flows_are_grouped_and_linked(temp_app):
    client, _ = temp_app
    first = safe_flow("HIGH_CONNECTION_RATE", "CORR-FLOW-1", source_ip="192.0.2.77")
    second = safe_flow("HIGH_CONNECTION_RATE", "CORR-FLOW-2", source_ip="192.0.2.77")
    first_result = client.post("/api/flows", json=first).json()
    second_result = client.post("/api/flows", json=second).json()
    assert first_result["alert"]["correlated"] is False
    assert second_result["alert"]["correlated"] is True
    detail = client.get(f"/api/alerts/{first_result['alert']['alert_id']}").json()
    assert detail["occurrence_count"] == 2
    assert len(detail["occurrences"]) == 2


def test_42_simulator_rejects_non_loopback_api():
    with pytest.raises(ValueError, match="loopback"):
        validate_local_api_url("https://example.com")
    assert validate_local_api_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
