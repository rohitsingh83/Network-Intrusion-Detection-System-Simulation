from datetime import datetime

class AlertCorrelator:
    """Alert correlation engine."""
    
    def __init__(self, time_window=60, max_group_size=100):
        self.time_window = time_window
        self.max_group_size = max_group_size
        self._incident_counter = 0
        
    def _parse_time(self, time_str):
        try:
            time_str = time_str.replace('Z', '+00:00')
            return datetime.fromisoformat(time_str)
        except Exception:
            return datetime.now()

    def _should_correlate(self, alert1: dict, alert2: dict) -> bool:
        """Same source IP + same alert type + within time window."""
        if alert1.get('source_ip') != alert2.get('source_ip'):
            return False
            
        if alert1.get('alert_type') != alert2.get('alert_type'):
            return False
            
        t1 = self._parse_time(alert1.get('timestamp'))
        t2 = self._parse_time(alert2.get('timestamp'))
        
        diff = abs((t1 - t2).total_seconds())
        return diff <= self.time_window

    def correlate(self, alerts: list[dict]) -> list[dict]:
        """Group related alerts into lists of alerts."""
        if not alerts:
            return []
            
        groups = []
        assigned = set()
        
        for i, a1 in enumerate(alerts):
            if i in assigned:
                continue
                
            current_group = [a1]
            assigned.add(i)
            
            for j in range(i + 1, len(alerts)):
                if j in assigned:
                    continue
                a2 = alerts[j]
                
                # Check against the first alert in the group
                if self._should_correlate(a1, a2):
                    current_group.append(a2)
                    assigned.add(j)
                    if len(current_group) >= self.max_group_size:
                        break
                        
            groups.append(current_group)
            
        return groups

    def create_incident(self, correlated_group: list[dict]) -> dict:
        """Create an incident from a group of correlated alerts."""
        if not correlated_group:
            return {}
            
        self._incident_counter += 1
        incident_id = f"INC-{self._incident_counter:03d}"
        
        try:
            sorted_alerts = sorted(correlated_group, key=lambda x: self._parse_time(x.get('timestamp')))
        except Exception:
            sorted_alerts = correlated_group
            
        severity_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        highest_severity = 'INFO'
        max_rank = -1
        
        for a in correlated_group:
            rank = severity_rank.get(a.get('severity', 'INFO'), 0)
            if rank > max_rank:
                max_rank = rank
                highest_severity = a.get('severity', 'INFO')

        first_alert = sorted_alerts[0]

        return {
            'incident_id': incident_id,
            'alert_count': len(correlated_group),
            'first_seen': sorted_alerts[0].get('timestamp'),
            'last_seen': sorted_alerts[-1].get('timestamp'),
            'source_ip': first_alert.get('source_ip'),
            'alert_type': first_alert.get('alert_type'),
            'severity': highest_severity,
            'alerts': correlated_group,
            'status': 'NEW'
        }
