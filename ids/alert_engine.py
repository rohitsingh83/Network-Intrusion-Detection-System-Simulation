import uuid
from datetime import datetime

class AlertEngine:
    """Alert generation engine."""
    
    def __init__(self):
        self._alert_counter = 10000

    def _assign_alert_id(self) -> str:
        """Format ALT-XXXXX"""
        self._alert_counter += 1
        return f"ALT-{self._alert_counter}"

    def get_investigation_steps(self, alert: dict) -> list[str]:
        """Return recommended steps based on alert type/severity."""
        steps = [
            f"Review historical activity for source IP {alert.get('source_ip')}.",
            "Check for corresponding endpoint alerts if applicable."
        ]
        
        severity = alert.get('severity', 'INFO')
        if severity in ['HIGH', 'CRITICAL']:
            steps.append("Block source IP on firewall pending investigation.")
            steps.append("Check internal logs for lateral movement from destination IP.")
            
        rule_ids = alert.get('rule_ids', [])
        if 'IDS-004' in rule_ids:
            steps.append("Verify if target application is experiencing degradation (SYN Flood).")
        if 'IDS-006' in rule_ids:
            steps.append("Review destination IP reputation. Possible data exfiltration.")
            
        return steps

    def generate_alert(self, flow: dict, features: dict = None, risk_result: dict = None, rule_results: list = None, anomaly_result: dict = None, ml_result=None) -> dict:
        """Only generate alert if risk_score > 20"""
        if risk_result is None and isinstance(features, dict) and "risk_score" in features:
            risk_result = features
            features = {}
        elif risk_result is None:
            risk_result = {}

        if rule_results is None:
            rule_results = []
        if anomaly_result is None:
            anomaly_result = {}
            
        if risk_result.get('risk_score', 0) <= 20:
            return None
            
        rule_ids = [r['rule_id'] for r in rule_results]
        
        # Determine alert_type and description based on findings
        if rule_results:
            alert_type = rule_results[0]['name']
            description = rule_results[0]['description']
        elif anomaly_result.get('is_anomaly'):
            alert_type = "Statistical Anomaly"
            description = "Multiple metrics deviated significantly from baseline."
        else:
            alert_type = "High Risk Traffic"
            description = "Traffic classified as high risk by scoring engine."
            
        alert = {
            'alert_id': self._assign_alert_id(),
            'timestamp': flow.get('timestamp', datetime.now().isoformat()),
            'source_ip': flow.get('source_ip'),
            'destination_ip': flow.get('destination_ip'),
            'protocol': flow.get('protocol'),
            'source_port': flow.get('source_port'),
            'destination_port': flow.get('destination_port'),
            'rule_ids': rule_ids,
            'alert_type': alert_type,
            'severity': risk_result.get('severity', 'LOW'),
            'risk_score': risk_result.get('risk_score', 0),
            'description': description,
            'status': 'NEW',
            'anomaly_score': anomaly_result.get('anomaly_score', 0),
            'ml_score': ml_result,
            'analyst_notes': [],
            'resolution': None
        }
        
        alert['investigation_steps'] = self.get_investigation_steps(alert)
        
        return alert
