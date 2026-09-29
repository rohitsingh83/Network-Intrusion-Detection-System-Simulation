import sqlite3
import threading
import os
import json
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

class DatabaseManager:
    """Manages SQLite database connections and operations for the IDS Simulation."""
    
    def __init__(self, db_path='data/ids_database.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        # Thread-local storage for connections
        self._local = threading.local()
        
    @property
    def connection(self):
        """Get or create a thread-local SQLite connection."""
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor."""
        cursor = self.connection.cursor()
        try:
            yield cursor
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            raise e
        finally:
            cursor.close()

    def initialize(self):
        """Create all required tables and indexes."""
        with self.get_cursor() as cursor:
            # NETWORK_FLOWS table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS NETWORK_FLOWS (
                    flow_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INT,
                    destination_port INT,
                    protocol TEXT,
                    packet_count INT,
                    byte_count INT,
                    duration REAL,
                    connection_count INT,
                    failed_connection_count INT,
                    syn_count INT,
                    rst_count INT,
                    average_packet_size REAL,
                    risk_score REAL,
                    classification TEXT,
                    created_at TEXT
                )
            ''')
            
            # ALERTS table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ALERTS (
                    alert_id TEXT PRIMARY KEY,
                    flow_id TEXT,
                    rule_id TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    description TEXT,
                    risk_score REAL,
                    anomaly_score REAL,
                    ml_score REAL,
                    status TEXT DEFAULT 'NEW',
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    source_port INT,
                    destination_port INT,
                    created_at TEXT,
                    updated_at TEXT,
                    FOREIGN KEY(flow_id) REFERENCES NETWORK_FLOWS(flow_id)
                )
            ''')

            # RULES table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS RULES (
                    rule_id TEXT PRIMARY KEY,
                    rule_name TEXT,
                    description TEXT,
                    severity TEXT,
                    threshold REAL,
                    enabled INT DEFAULT 1,
                    created_at TEXT
                )
            ''')

            # INCIDENT_NOTES table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS INCIDENT_NOTES (
                    note_id TEXT PRIMARY KEY,
                    alert_id TEXT,
                    analyst TEXT,
                    note TEXT,
                    action TEXT,
                    created_at TEXT,
                    FOREIGN KEY(alert_id) REFERENCES ALERTS(alert_id)
                )
            ''')

            # MODEL_RESULTS table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS MODEL_RESULTS (
                    result_id TEXT PRIMARY KEY,
                    flow_id TEXT,
                    model_name TEXT,
                    prediction TEXT,
                    probability REAL,
                    created_at TEXT,
                    FOREIGN KEY(flow_id) REFERENCES NETWORK_FLOWS(flow_id)
                )
            ''')

            # Indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON NETWORK_FLOWS(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_source_ip ON NETWORK_FLOWS(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_severity ON ALERTS(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_status ON ALERTS(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_created_at ON ALERTS(created_at)')

    def insert_rule(self, rule: Dict[str, Any]):
        """Insert or update a detection rule."""
        with self.get_cursor() as cursor:
            keys = ', '.join(rule.keys())
            placeholders = ', '.join(['?'] * len(rule))
            query = f'INSERT OR IGNORE INTO RULES ({keys}) VALUES ({placeholders})'
            cursor.execute(query, tuple(rule.values()))

    def insert_flow(self, flow: Dict[str, Any]):
        with self.get_cursor() as cursor:
            keys = ', '.join(flow.keys())
            placeholders = ', '.join(['?'] * len(flow))
            query = f'INSERT OR REPLACE INTO NETWORK_FLOWS ({keys}) VALUES ({placeholders})'
            cursor.execute(query, tuple(flow.values()))

    def insert_alert(self, alert: Dict[str, Any]):
        with self.get_cursor() as cursor:
            keys = ', '.join(alert.keys())
            placeholders = ', '.join(['?'] * len(alert))
            query = f'INSERT OR REPLACE INTO ALERTS ({keys}) VALUES ({placeholders})'
            cursor.execute(query, tuple(alert.values()))

    def insert_note(self, note: Dict[str, Any]):
        with self.get_cursor() as cursor:
            keys = ', '.join(note.keys())
            placeholders = ', '.join(['?'] * len(note))
            query = f'INSERT INTO INCIDENT_NOTES ({keys}) VALUES ({placeholders})'
            cursor.execute(query, tuple(note.values()))

    def insert_model_result(self, result: Dict[str, Any]):
        with self.get_cursor() as cursor:
            keys = ', '.join(result.keys())
            placeholders = ', '.join(['?'] * len(result))
            query = f'INSERT INTO MODEL_RESULTS ({keys}) VALUES ({placeholders})'
            cursor.execute(query, tuple(result.values()))

    def get_flows(self, limit=100, offset=0, filters=None) -> List[Dict[str, Any]]:
        query = 'SELECT * FROM NETWORK_FLOWS'
        params = []
        
        if filters:
            conditions = []
            for k, v in filters.items():
                if v is not None:
                    conditions.append(f"{k} = ?")
                    params.append(v)
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
                
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM NETWORK_FLOWS WHERE flow_id = ?', (flow_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_alerts(self, limit=100, offset=0, filters=None) -> List[Dict[str, Any]]:
        query = 'SELECT * FROM ALERTS'
        params = []
        
        if filters:
            conditions = []
            for k, v in filters.items():
                if v is not None:
                    conditions.append(f"{k} = ?")
                    params.append(v)
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
                
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM ALERTS WHERE alert_id = ?', (alert_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_alert_status(self, alert_id: str, status: str, analyst: str = None):
        with self.get_cursor() as cursor:
            cursor.execute('''
                UPDATE ALERTS 
                SET status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE alert_id = ?
            ''', (status, alert_id))
            
            if analyst:
                # Add automatic note
                import uuid
                cursor.execute('''
                    INSERT INTO INCIDENT_NOTES (note_id, alert_id, analyst, note, action, created_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), alert_id, analyst, f'Status updated to {status}', 'STATUS_UPDATE'))

    def get_alert_notes(self, alert_id: str) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM INCIDENT_NOTES WHERE alert_id = ? ORDER BY created_at DESC', (alert_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM NETWORK_FLOWS')
            total_flows = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM NETWORK_FLOWS WHERE UPPER(classification) = "NORMAL"')
            normal_flows = cursor.fetchone()[0]
            
            suspicious_flows = total_flows - normal_flows
            
            cursor.execute('SELECT COUNT(*) FROM ALERTS WHERE status != "RESOLVED" AND status != "FALSE_POSITIVE"')
            open_alerts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM ALERTS WHERE severity = "CRITICAL"')
            critical_alerts = cursor.fetchone()[0]
            
            cursor.execute('SELECT AVG(risk_score) FROM NETWORK_FLOWS')
            avg_risk = cursor.fetchone()[0] or 0.0
            
            return {
                'total_flows': total_flows,
                'normal_flows': normal_flows,
                'suspicious_flows': suspicious_flows,
                'open_alerts': open_alerts,
                'critical_alerts': critical_alerts,
                'avg_risk_score': round(avg_risk, 2)
            }

    def get_traffic_timeline(self, hours=24) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            query = '''
                SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket, COUNT(*) as count
                FROM NETWORK_FLOWS 
                WHERE timestamp >= datetime('now', ?)
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            '''
            cursor.execute(query, (f'-{hours} hours',))
            return [dict(row) for row in cursor.fetchall()]

    def get_alert_timeline(self, hours=24) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            query = '''
                SELECT strftime('%Y-%m-%d %H:00:00', created_at) as time_bucket, severity, COUNT(*) as count
                FROM ALERTS 
                WHERE created_at >= datetime('now', ?)
                GROUP BY time_bucket, severity
                ORDER BY time_bucket ASC
            '''
            cursor.execute(query, (f'-{hours} hours',))
            return [dict(row) for row in cursor.fetchall()]

    def get_protocol_distribution(self) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT protocol, COUNT(*) as count FROM NETWORK_FLOWS GROUP BY protocol ORDER BY count DESC')
            return [dict(row) for row in cursor.fetchall()]

    def get_top_source_ips(self, limit=10) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM ALERTS 
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_severity_distribution(self) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT severity, COUNT(*) as count FROM ALERTS GROUP BY severity')
            return [dict(row) for row in cursor.fetchall()]

    def get_port_distribution(self, limit=20) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT destination_port as port, COUNT(*) as count 
                FROM NETWORK_FLOWS 
                GROUP BY destination_port 
                ORDER BY count DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_rules(self) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM RULES')
            return [dict(row) for row in cursor.fetchall()]

    def update_rule(self, rule_id: str, **kwargs):
        if not kwargs:
            return
        
        set_clause = ', '.join([f'{k} = ?' for k in kwargs.keys()])
        values = list(kwargs.values())
        values.append(rule_id)
        
        with self.get_cursor() as cursor:
            cursor.execute(f'UPDATE RULES SET {set_clause} WHERE rule_id = ?', tuple(values))

    def get_risk_distribution(self) -> List[Dict[str, Any]]:
        with self.get_cursor() as cursor:
            # Grouping into buckets
            query = '''
                SELECT 
                    CASE 
                        WHEN risk_score < 20 THEN '0-20'
                        WHEN risk_score < 40 THEN '20-40'
                        WHEN risk_score < 60 THEN '40-60'
                        WHEN risk_score < 80 THEN '60-80'
                        ELSE '80-100'
                    END as bucket,
                    COUNT(*) as count
                FROM NETWORK_FLOWS
                GROUP BY bucket
            '''
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]
