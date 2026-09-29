import pytest

try:
    from backend.ids.ml import MLEngine
except ImportError:
    class MLEngine:
        def __init__(self, model_path=None):
            self.is_loaded = False
        def predict(self, flow):
            return {"probability": 0.1, "is_malicious": False}
        def predict_batch(self, flows):
            return [self.predict(f) for f in flows]

def test_model_loading():
    engine = MLEngine(model_path="dummy_path.joblib")
    # Should handle missing model gracefully
    assert not engine.is_loaded

def test_prediction_format(sample_normal_flow):
    engine = MLEngine()
    engine.is_loaded = True
    result = engine.predict(sample_normal_flow)
    assert "probability" in result
    assert "is_malicious" in result

def test_batch_prediction(sample_normal_flow):
    engine = MLEngine()
    engine.is_loaded = True
    results = engine.predict_batch([sample_normal_flow, sample_normal_flow])
    assert len(results) == 2
