import json
import os
import math

class AnomalyDetector:
    """Statistical anomaly detection engine."""
    
    def __init__(self):
        self.baseline = {}
        self.metrics = [
            'packets_per_second', 'bytes_per_second', 'connection_rate', 
            'failure_ratio', 'syn_ratio', 'average_packet_size'
        ]
        
    def update_baseline(self, features_list: list[dict]):
        """Calculate mean and std for each metric from a list of normal flow features."""
        if not features_list:
            return
            
        n = len(features_list)
        for metric in self.metrics:
            values = [f.get(metric, 0) for f in features_list]
            mean = sum(values) / n
            variance = sum((x - mean) ** 2 for x in values) / n
            std = math.sqrt(variance)
            
            # Add small epsilon to std to prevent division by zero
            self.baseline[metric] = {'mean': mean, 'std': std + 0.0001}
            
    def _z_score(self, value, mean, std) -> float:
        """Calculate standard z-score."""
        return abs(value - mean) / std
        
    def _iqr_check(self, value, q1, q3) -> bool:
        """Check if value is outside the interquartile range."""
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        return value < lower_bound or value > upper_bound

    def calculate_anomaly_score(self, features: dict) -> dict:
        """Calculate anomaly score based on deviations from baseline."""
        if not self.baseline:
            return {'anomaly_score': 0, 'is_anomaly': False, 'deviations': {}, 'method': 'z-score'}
            
        deviations = {}
        total_z = 0
        
        for metric in self.metrics:
            val = features.get(metric, 0)
            base = self.baseline.get(metric, {'mean': 0, 'std': 1})
            z = self._z_score(val, base['mean'], base['std'])
            
            # Cap z-score to prevent one extreme metric from completely dominating
            capped_z = min(z, 10.0)
            total_z += capped_z
            
            deviations[metric] = {
                'value': val,
                'mean': base['mean'],
                'std': base['std'],
                'z_score': round(z, 2)
            }
            
        # Average z-score across metrics, then scale to 0-100
        avg_z = total_z / len(self.metrics)
        # Empirical scaling: an average Z of 3 implies ~100 score
        score = min((avg_z / 3.0) * 100, 100.0)
        
        return {
            'anomaly_score': round(score, 2),
            'is_anomaly': score > 50.0,
            'deviations': deviations,
            'method': 'z-score'
        }
        
    def load_baseline(self, filepath: str):
        """Load baseline from a JSON file."""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                self.baseline = json.load(f)
                
    def save_baseline(self, filepath: str):
        """Save current baseline to a JSON file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(self.baseline, f, indent=2)
