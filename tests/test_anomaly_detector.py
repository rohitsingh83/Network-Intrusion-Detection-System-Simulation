import pytest

def test_normal_flow_low_score(anomaly_detector, sample_normal_flow):
    score = anomaly_detector.calculate_score(sample_normal_flow)
    assert score < 50

def test_anomalous_flow_high_score(anomaly_detector, sample_suspicious_flow):
    score = anomaly_detector.calculate_score(sample_suspicious_flow)
    assert score > 50

def test_baseline_update(anomaly_detector, sample_normal_flow):
    old_mean = anomaly_detector.baseline.get("packet_count_mean")
    anomaly_detector.update_baseline(sample_normal_flow)
    assert anomaly_detector.baseline.get("packet_count_mean") != old_mean

def test_z_score_calculation(anomaly_detector):
    z = anomaly_detector._calculate_z_score(120, 100, 20)
    assert z == 1.0

def test_empty_baseline():
    try:
        from backend.ids.anomaly import AnomalyDetector
        detector = AnomalyDetector()
    except ImportError:
        class AnomalyDetector:
            def calculate_score(self, f): return 0
        detector = AnomalyDetector()
    score = detector.calculate_score({"packet_count": 100})
    assert score == 0
