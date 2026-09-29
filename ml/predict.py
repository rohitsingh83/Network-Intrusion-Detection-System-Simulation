"""
ML prediction module for Network IDS.

Provides the MLPredictor class to load a trained model bundle and perform
predictions on new network traffic data. Gracefully handles cases where ML
is disabled or model files are missing.
"""

import os
import logging
import numpy as np

try:
    import joblib
except ImportError:
    pass  # Handled below

logger = logging.getLogger(__name__)

class MLPredictor:
    """
    Machine Learning Predictor for Network Traffic.
    
    Loads a saved model bundle (including the model, scaler, and feature names)
    and provides methods to predict whether traffic is NORMAL or SUSPICIOUS.
    """
    
    def __init__(self, model_path: str = 'models/ids_model.joblib'):
        """
        Initializes the MLPredictor.
        
        Args:
            model_path: Path to the joblib model bundle.
        """
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.model_name = "Unknown"
        self.is_ready = False
        
        self.load_model()
        
    def load_model(self) -> None:
        """
        Loads the joblib bundle. Handles missing files gracefully.
        """
        if not os.path.exists(self.model_path):
            logger.warning(f"Model file not found at {self.model_path}. ML predictions disabled.")
            return
            
        try:
            bundle = joblib.load(self.model_path)
            self.model = bundle.get('model')
            self.scaler = bundle.get('scaler')
            self.feature_names = bundle.get('feature_names', [])
            self.model_name = bundle.get('model_name', type(self.model).__name__)
            
            if self.model and self.scaler and self.feature_names:
                self.is_ready = True
                logger.info(f"Successfully loaded {self.model_name} model from {self.model_path}")
            else:
                logger.error("Model bundle is missing required components (model, scaler, or feature_names).")
        except Exception as e:
            logger.error(f"Failed to load model from {self.model_path}: {e}")
            
    def _prepare_features(self, features: dict) -> np.ndarray:
        """
        Prepares raw feature dictionary into a scaled numpy array for prediction.
        Computes derived features if necessary and handles missing values.
        
        Args:
            features: Dictionary of raw features.
            
        Returns:
            Numpy array of scaled features shaped (1, n_features).
        """
        # Ensure we compute derived features if not present
        if 'bytes_per_second' not in features:
            dur = features.get('duration_seconds', 1.0)
            dur = max(dur, 0.001)
            features['bytes_per_second'] = features.get('byte_count', 0) / dur
            
        if 'packets_per_second' not in features:
            dur = features.get('duration_seconds', 1.0)
            dur = max(dur, 0.001)
            features['packets_per_second'] = features.get('packet_count', 0) / dur
            
        if 'failure_ratio' not in features:
            conn = features.get('connection_count', 1)
            conn = max(conn, 1)
            features['failure_ratio'] = features.get('failed_connection_count', 0) / conn
            
        if 'syn_ratio' not in features:
            pkts = features.get('packet_count', 1)
            pkts = max(pkts, 1)
            features['syn_ratio'] = features.get('syn_count', 0) / pkts
            
        if 'connection_rate' not in features:
            dur = features.get('duration_seconds', 1.0)
            dur = max(dur, 0.001)
            features['connection_rate'] = features.get('connection_count', 0) / dur

        # Extract features in the correct order
        feature_vector = []
        for fn in self.feature_names:
            val = features.get(fn, 0.0)
            # Handle inf or nan
            if not isinstance(val, (int, float)) or np.isnan(val) or np.isinf(val):
                val = 0.0
            feature_vector.append(val)
            
        # Reshape for single prediction and scale
        X = np.array(feature_vector).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        return X_scaled

    def predict(self, features: dict) -> dict:
        """
        Predicts if a single traffic instance is normal or suspicious.
        
        Args:
            features: Dictionary of traffic features.
            
        Returns:
            Dictionary containing prediction, probability, confidence, model_name, etc.
        """
        if not self.is_ready:
            return {
                'prediction': 'UNKNOWN',
                'probability': 0.0,
                'confidence': 'LOW',
                'model_name': 'None',
                'error': 'Model not loaded or unavailable.'
            }
            
        try:
            X_scaled = self._prepare_features(features)
            
            # Prediction
            pred = self.model.predict(X_scaled)[0]
            
            # Isolation forest returns -1 for outliers, 1 for inliers
            if "Isolation" in self.model_name or hasattr(self.model, 'offset_'):
                is_suspicious = (pred == -1)
                # Estimate probability based on decision function
                decision = self.model.decision_function(X_scaled)[0]
                # Lower is more anomalous. Convert to pseudo-probability.
                prob = float(min(max(-decision, 0.0), 1.0)) 
            else:
                is_suspicious = bool(pred == 1)
                if hasattr(self.model, 'predict_proba'):
                    prob = float(self.model.predict_proba(X_scaled)[0][1])
                elif hasattr(self.model, 'decision_function'):
                    decision = self.model.decision_function(X_scaled)[0]
                    # sigmoid approximation
                    prob = 1 / (1 + np.exp(-decision))
                else:
                    prob = 1.0 if is_suspicious else 0.0
            
            # Confidence logic
            confidence = 'LOW'
            if prob > 0.8 or prob < 0.2:
                confidence = 'HIGH'
            elif prob > 0.6 or prob < 0.4:
                confidence = 'MEDIUM'
                
            prediction_label = 'SUSPICIOUS' if is_suspicious else 'NORMAL'
            
            return {
                'prediction': prediction_label,
                'probability': prob,
                'confidence': confidence,
                'model_name': self.model_name,
                'features_used': self.feature_names
            }
            
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            return {
                'prediction': 'ERROR',
                'probability': 0.0,
                'confidence': 'LOW',
                'model_name': self.model_name,
                'error': str(e)
            }

    def predict_batch(self, features_list: list[dict]) -> list[dict]:
        """
        Predicts a batch of traffic instances.
        
        Args:
            features_list: List of dictionaries of traffic features.
            
        Returns:
            List of prediction dictionaries.
        """
        return [self.predict(f) for f in features_list]
