export interface Flow {
  flow_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packet_count: number;
  byte_count: number;
  duration_seconds: number;
  classification: 'NORMAL' | 'SUSPICIOUS' | 'POTENTIAL_INTRUSION';
  risk_score: number;
  scenario_type?: string;
}

export interface Alert {
  alert_id: string;
  flow_id: string;
  timestamp: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  title: string;
  description: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  risk_score: number;
  triggered_rules: string[];
  anomaly_score?: number;
  ml_confidence?: number;
  recommended_actions?: string[];
  notes?: AlertNote[];
}

export interface AlertNote {
  note: string;
  analyst: string;
  action?: string;
  timestamp: string;
}

export interface DashboardStats {
  total_flows: number;
  normal_flows: number;
  suspicious_flows: number;
  open_alerts: number;
  total_alerts: number;
  critical_alerts: number;
  avg_risk_score: number;
}

export interface TrafficPoint {
  timestamp: string;
  count: number;
  suspicious: number;
}

export interface ProtocolDist {
  protocol: string;
  count: number;
}

export interface SeverityDist {
  severity: string;
  count: number;
}

export interface PortDist {
  port: number;
  count: number;
}

export interface SourceDist {
  source_ip: string;
  count: number;
}

export interface HealthStatus {
  status: string;
  version: string;
  uptime_seconds: number;
  database: string;
  ml_enabled: boolean;
  ml_ready: boolean;
  active_rules: number;
  baseline_ready: boolean;
  total_flows: number;
  open_alerts: number;
}

export interface SSEEvent {
  type: 'new_flow' | 'new_alert';
  data: Flow | Alert;
}
