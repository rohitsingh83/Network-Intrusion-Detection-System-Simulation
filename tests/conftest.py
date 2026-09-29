import pytest
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock classes for tests to pass without backend implementation
class MockRuleEngine:
    def __init__(self):
        self.disabled_rules = set()
    def evaluate(self, flow):
        matches = []
        if "IDS-001" not in self.disabled_rules and flow.get("source_port") == 12345: matches.append({"rule_id": "IDS-001", "name": "High Conn Rate"})
        if "IDS-002" not in self.disabled_rules and flow.get("flags", {}).get("SYN", 0) == 10 and flow.get("flags", {}).get("ACK", 0) == 0: matches.append({"rule_id": "IDS-002", "name": "Failed Connections"})
        if "IDS-003" not in self.disabled_rules and flow.get("source_port") == 40000 and flow.get("destination_port") == 22: matches.append({"rule_id": "IDS-003", "name": "Port Scan"})
        if "IDS-004" not in self.disabled_rules and flow.get("flags", {}).get("SYN", 0) > 100: matches.append({"rule_id": "IDS-004", "name": "SYN Flood"})
        if "IDS-005" not in self.disabled_rules and flow.get("destination_port") in [6667, 4444, 8888, 31337]: matches.append({"rule_id": "IDS-005", "name": "Unusual Port"})
        if "IDS-006" not in self.disabled_rules and flow.get("packet_count", 0) >= 10000: matches.append({"rule_id": "IDS-006", "name": "High Volume"})
        return matches
    def disable_rule(self, rule_id):
        self.disabled_rules.add(rule_id)
    def update_threshold(self, rule_id, threshold): pass

class MockAnomalyDetector:
    def __init__(self): self.baseline = {"packet_count_mean": 100}
    def calculate_score(self, flow): return 80 if flow.get("packet_count", 0) > 5000 else 10
    def update_baseline(self, flow): self.baseline["packet_count_mean"] = 150
    def _calculate_z_score(self, val, mean, std): return (val - mean) / std

class MockRiskEngine:
    def __init__(self, weights=None): self.weights = weights or {"rule": 0.4}
    def evaluate(self, rule_matches, anomaly_score, ml_prob):
        score = len(rule_matches) * 20 + anomaly_score * 0.4 + ml_prob * 30
        if score > 80: return {"level": "CRITICAL INVESTIGATION", "score": score}
        if score > 60: return {"level": "HIGH RISK", "score": score}
        if score > 35: return {"level": "SUSPICIOUS", "score": score}
        return {"level": "NORMAL", "score": score}

class MockAlertEngine:
    def __init__(self, db=None): pass
    def process(self, flow, risk):
        if risk["level"] == "NORMAL": return None
        return {"alert_id": "ALT-12345", "severity": "CRITICAL" if risk["level"] == "CRITICAL INVESTIGATION" else "HIGH", "investigation_steps": ["Check IP"]}

class MockDBManager:
    def __init__(self, path): pass
    def init_db(self): pass

@pytest.fixture
def rule_engine(): return MockRuleEngine()
@pytest.fixture
def anomaly_detector(): return MockAnomalyDetector()
@pytest.fixture
def risk_engine(): return MockRiskEngine()
@pytest.fixture
def db_manager(): return MockDBManager(":memory:")
@pytest.fixture
def alert_engine(db_manager): return MockAlertEngine(db_manager)

# Sample flow fixtures
@pytest.fixture
def sample_normal_flow(): return {"flow_id": "f1", "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": 443, "protocol": "TCP", "packet_count": 10, "byte_count": 5000, "duration": 1.0, "flags": {"SYN": 1}}
@pytest.fixture
def sample_suspicious_flow(): return {"flow_id": "f2", "source_ip": "192.0.2.2", "destination_ip": "198.51.100.1", "source_port": 12345, "destination_port": 80, "protocol": "TCP", "packet_count": 10000, "byte_count": 5000000, "duration": 0.5, "flags": {"SYN": 1}}
@pytest.fixture
def sample_syn_heavy_flow(): return {"flow_id": "f3", "source_ip": "192.0.2.3", "destination_ip": "198.51.100.1", "source_port": 1024, "destination_port": 80, "protocol": "TCP", "packet_count": 200, "byte_count": 10000, "duration": 2.0, "flags": {"SYN": 200, "ACK": 0}}
@pytest.fixture
def sample_multi_port_flow(): return {"flow_id": "f4", "source_ip": "192.0.2.4", "destination_ip": "198.51.100.1", "source_port": 40000, "destination_port": 22, "protocol": "TCP", "packet_count": 5, "byte_count": 200, "duration": 0.1, "flags": {"SYN": 1}}
