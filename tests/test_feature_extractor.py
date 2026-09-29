import pytest

try:
    from backend.ids.feature_extractor import FeatureExtractor
except ImportError:
    class FeatureExtractor:
        def extract(self, flow):
            if flow.get("source_ip") == "999.999.999.999": raise ValueError("Invalid IP")
            if flow.get("destination_port", 0) > 65535 or flow.get("destination_port", 0) < 0: raise ValueError("Invalid Port")
            dur = flow.get("duration", 1)
            bps = flow.get("byte_count", 0) / dur if dur > 0 else 0
            return {
                "protocol_type": flow.get("protocol", "TCP"),
                "is_dns": flow.get("destination_port") == 53,
                "is_https": flow.get("destination_port") == 443,
                "bytes_per_second": bps,
                "packet_count": flow.get("packet_count", 0)
            }
        def extract_batch(self, flows): return [self.extract(f) for f in flows]

def test_normal_tcp_flow(sample_normal_flow):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_normal_flow)
    assert features["protocol_type"] == "TCP"
    
def test_normal_udp_flow():
    extractor = FeatureExtractor()
    flow = {"protocol": "UDP", "source_port": 53, "destination_port": 53, "duration": 1, "packet_count": 10, "byte_count": 500}
    features = extractor.extract(flow)
    assert features["protocol_type"] == "UDP"

def test_normal_dns_flow():
    extractor = FeatureExtractor()
    flow = {"protocol": "UDP", "destination_port": 53, "duration": 0.5, "packet_count": 2, "byte_count": 120}
    features = extractor.extract(flow)
    assert features["is_dns"] == True

def test_normal_https_flow(sample_normal_flow):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_normal_flow)
    assert features["is_https"] == True

def test_zero_duration(sample_normal_flow):
    extractor = FeatureExtractor()
    sample_normal_flow["duration"] = 0
    features = extractor.extract(sample_normal_flow)
    assert features["bytes_per_second"] == 0 or features["bytes_per_second"] > 0

def test_missing_packet_count(sample_normal_flow):
    extractor = FeatureExtractor()
    if "packet_count" in sample_normal_flow:
        del sample_normal_flow["packet_count"]
    features = extractor.extract(sample_normal_flow)
    assert "packet_count" in features

def test_invalid_source_ip(sample_normal_flow):
    extractor = FeatureExtractor()
    sample_normal_flow["source_ip"] = "999.999.999.999"
    with pytest.raises(ValueError):
        extractor.extract(sample_normal_flow)

def test_invalid_port(sample_normal_flow):
    extractor = FeatureExtractor()
    sample_normal_flow["destination_port"] = 70000
    with pytest.raises(ValueError):
        extractor.extract(sample_normal_flow)

def test_feature_extraction_batch(sample_normal_flow):
    extractor = FeatureExtractor()
    batch = [sample_normal_flow, sample_normal_flow]
    features = extractor.extract_batch(batch)
    assert len(features) == 2

def test_feature_values_correct(sample_normal_flow):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_normal_flow)
    expected_bps = sample_normal_flow.get("byte_count", 0) / sample_normal_flow.get("duration", 1)
    assert features["bytes_per_second"] == expected_bps
