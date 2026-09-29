import json
import os

class RuleEngine:
    """Signature/rule-based detection engine."""
    
    def __init__(self, config_path=None):
        self.rules = self._get_default_rules()
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
            
    def _get_default_rules(self):
        return [
            {
                'rule_id': 'IDS-001',
                'name': 'High Connection Rate',
                'severity': 'HIGH',
                'description': 'Connection rate significantly exceeded normal limits.',
                'enabled': True,
                'thresholds': {'connection_rate': 50}
            },
            {
                'rule_id': 'IDS-002',
                'name': 'Repeated Failed Connections',
                'severity': 'HIGH',
                'description': 'High ratio of failed connections, indicating brute force or scanning.',
                'enabled': True,
                'thresholds': {'failure_ratio': 0.5, 'failed': 10}
            },
            {
                'rule_id': 'IDS-003',
                'name': 'Multi-Port Activity',
                'severity': 'MEDIUM',
                'description': 'Probing multiple ports, indicating scanning.',
                'enabled': True,
                'thresholds': {'unique_destination_ports': 15}
            },
            {
                'rule_id': 'IDS-004',
                'name': 'SYN-Heavy Pattern',
                'severity': 'HIGH',
                'description': 'High SYN packet ratio, indicating SYN flood.',
                'enabled': True,
                'thresholds': {'syn_ratio': 0.8, 'syn_count': 100}
            },
            {
                'rule_id': 'IDS-005',
                'name': 'Unusual Port Activity',
                'severity': 'MEDIUM',
                'description': 'Activity on known suspicious ports.',
                'enabled': True,
                'thresholds': {'suspicious_ports': [4444, 8888, 31337]}
            },
            {
                'rule_id': 'IDS-006',
                'name': 'High Traffic Volume',
                'severity': 'HIGH',
                'description': 'Excessive data transfer, possible exfiltration.',
                'enabled': True,
                'thresholds': {'bytes_per_second': 1000000}
            },
            {
                'rule_id': 'IDS-007',
                'name': 'Connection Burst',
                'severity': 'MEDIUM',
                'description': 'High number of connections in a short time.',
                'enabled': True,
                'thresholds': {'connection_count': 100, 'max_duration': 2.0}
            },
            {
                'rule_id': 'IDS-008',
                'name': 'RST Flood',
                'severity': 'HIGH',
                'description': 'High number of RST packets.',
                'enabled': True,
                'thresholds': {'rst_count': 50, 'rst_ratio': 0.5}
            }
        ]
        
    def _load_config(self, config_path):
        with open(config_path, 'r') as f:
            custom_config = json.load(f)
            # Update rules with custom configs
            for rule in self.rules:
                if rule['rule_id'] in custom_config:
                    rule.update(custom_config[rule['rule_id']])
                    
    def analyze_flow(self, features: dict, raw_flow: dict = None) -> list[dict]:
        """Check all rules, return matched rules."""
        matches = []
        raw = raw_flow or {}
        
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            matched = False
            details = {}
            t = rule['thresholds']
            rid = rule['rule_id']
            
            if rid == 'IDS-001':
                cr = features.get('connection_rate', 0)
                if cr > t['connection_rate']:
                    matched = True
                    details = {'connection_rate': cr, 'threshold': t['connection_rate']}
            elif rid == 'IDS-002':
                fr = features.get('failure_ratio', 0)
                fc = features.get('failed_connection_count', 0)
                if fr > t['failure_ratio'] and fc > t['failed']:
                    matched = True
                    details = {'failure_ratio': fr, 'failed_connections': fc}
            elif rid == 'IDS-003':
                up = features.get('unique_destination_ports', 0)
                if up > t['unique_destination_ports']:
                    matched = True
                    details = {'unique_ports': up, 'threshold': t['unique_destination_ports']}
            elif rid == 'IDS-004':
                sr = features.get('syn_ratio', 0)
                sc = features.get('syn_count', 0)
                if sr > t['syn_ratio'] and sc > t['syn_count']:
                    matched = True
                    details = {'syn_ratio': sr, 'syn_count': sc}
            elif rid == 'IDS-005':
                dp = int(raw.get('destination_port', -1))
                if dp in t['suspicious_ports']:
                    matched = True
                    details = {'destination_port': dp}
            elif rid == 'IDS-006':
                bps = features.get('bytes_per_second', 0)
                if bps > t['bytes_per_second']:
                    matched = True
                    details = {'bytes_per_second': bps, 'threshold': t['bytes_per_second']}
            elif rid == 'IDS-007':
                cc = features.get('connection_count', 0)
                dur = features.get('duration', 9999)
                if cc > t['connection_count'] and dur < t['max_duration']:
                    matched = True
                    details = {'connection_count': cc, 'duration': dur}
            elif rid == 'IDS-008':
                rc = features.get('rst_count', 0)
                pc = max(features.get('packet_count', 1), 1)
                rr = rc / pc
                if rc > t['rst_count'] and rr > t['rst_ratio']:
                    matched = True
                    details = {'rst_count': rc, 'rst_ratio': rr}
                    
            if matched:
                matches.append({
                    'rule_id': rule['rule_id'],
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'matched': True,
                    'details': details
                })
                
        return matches

    def get_rules(self) -> list[dict]:
        return self.rules

    def update_rule(self, rule_id: str, **kwargs):
        for rule in self.rules:
            if rule['rule_id'] == rule_id:
                rule.update(kwargs)
                break

    def enable_rule(self, rule_id: str, enabled: bool):
        self.update_rule(rule_id, enabled=enabled)
