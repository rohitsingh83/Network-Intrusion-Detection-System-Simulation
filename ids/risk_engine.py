class RiskEngine:
    """Hybrid risk scoring engine combining rules, anomalies, and ML."""
    
    def __init__(self, ml_enabled=False, weights=None):
        self.ml_enabled = ml_enabled
        if weights:
            self.weights = weights
        elif ml_enabled:
            self.weights = {'rule': 0.4, 'anomaly': 0.3, 'ml': 0.3}
        else:
            self.weights = {'rule': 0.6, 'anomaly': 0.4}
            
    def calculate_risk_score(self, rule_results: list, anomaly_result: dict, ml_result: float = None) -> dict:
        """
        Calculate final hybrid risk score and classification.
        """
        # Calculate Rule Score (max severity of all triggered rules)
        severity_map = {'CRITICAL': 95, 'HIGH': 80, 'MEDIUM': 60, 'LOW': 40, 'INFO': 20}
        rule_score = 0
        if rule_results:
            rule_score = max(severity_map.get(r.get('severity', 'INFO'), 0) for r in rule_results)
            
        # Anomaly score
        anomaly_score = anomaly_result.get('anomaly_score', 0)
        
        # ML score
        ml_score = (ml_result * 100) if ml_result is not None else 0
        
        # Calculate final weighted score
        final_score = (rule_score * self.weights.get('rule', 0) + 
                       anomaly_score * self.weights.get('anomaly', 0))
                       
        if self.ml_enabled and ml_result is not None:
            final_score += ml_score * self.weights.get('ml', 0)
            
        # Classifications and Severity Map
        if final_score <= 20:
            classification = 'NORMAL'
            severity = 'INFO'
        elif final_score <= 40:
            classification = 'LOW RISK'
            severity = 'LOW'
        elif final_score <= 60:
            classification = 'SUSPICIOUS'
            severity = 'MEDIUM'
        elif final_score <= 80:
            classification = 'HIGH RISK'
            severity = 'HIGH'
        else:
            classification = 'CRITICAL INVESTIGATION'
            severity = 'CRITICAL'
            
        return {
            'risk_score': round(final_score, 2),
            'classification': classification,
            'severity': severity,
            'components': {
                'rule_score': rule_score,
                'anomaly_score': anomaly_score,
                'ml_score': ml_score if ml_result is not None else None
            },
            'weights_used': self.weights
        }
