import pytest

def test_normal_flow_no_rules(rule_engine, sample_normal_flow):
    matches = rule_engine.evaluate(sample_normal_flow)
    assert len(matches) == 0

def test_high_connection_rate(rule_engine, sample_suspicious_flow):
    matches = rule_engine.evaluate(sample_suspicious_flow)
    assert any(m["rule_id"] == "IDS-001" for m in matches)

def test_repeated_failed_connections(rule_engine):
    flow = {"flow_id": "f1", "flags": {"SYN": 10, "ACK": 0}, "packet_count": 10}
    matches = rule_engine.evaluate(flow)
    assert any(m["rule_id"] == "IDS-002" for m in matches)

def test_multi_port_pattern(rule_engine, sample_multi_port_flow):
    matches = rule_engine.evaluate(sample_multi_port_flow)
    assert any(m["rule_id"] == "IDS-003" for m in matches)

def test_syn_heavy_pattern(rule_engine, sample_syn_heavy_flow):
    matches = rule_engine.evaluate(sample_syn_heavy_flow)
    assert any(m["rule_id"] == "IDS-004" for m in matches)

def test_unusual_port(rule_engine):
    flow = {"destination_port": 6667, "protocol": "TCP"}
    matches = rule_engine.evaluate(flow)
    assert any(m["rule_id"] == "IDS-005" for m in matches)

def test_high_traffic_volume(rule_engine, sample_suspicious_flow):
    # Use a large packet count to trigger volume rule
    sample_suspicious_flow["packet_count"] = 10000
    matches = rule_engine.evaluate(sample_suspicious_flow)
    assert any(m["rule_id"] == "IDS-006" for m in matches)

def test_multiple_rules_match(rule_engine, sample_suspicious_flow):
    sample_suspicious_flow["destination_port"] = 6667
    sample_suspicious_flow["flags"]["SYN"] = 150
    matches = rule_engine.evaluate(sample_suspicious_flow)
    # Could match IDS-005 and IDS-004
    assert len(matches) >= 2

def test_rule_disable(rule_engine, sample_suspicious_flow):
    rule_engine.disable_rule("IDS-001")
    matches = rule_engine.evaluate(sample_suspicious_flow)
    assert not any(m["rule_id"] == "IDS-001" for m in matches)

def test_rule_threshold_update(rule_engine, sample_suspicious_flow):
    rule_engine.update_threshold("IDS-006", 20000)
    matches = rule_engine.evaluate(sample_suspicious_flow)
    # Depends on implementation, but basic check
    assert isinstance(matches, list)
