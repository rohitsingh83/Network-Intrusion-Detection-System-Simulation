/**
 * Standalone Client-Side IDS Simulation Engine
 * ============================================
 * Provides a 100% self-contained, in-browser defensive Intrusion Detection System.
 * Enables the dashboard to run completely independently on static hosting
 * (GitHub Pages, Vercel, Netlify) with zero Python or server dependencies.
 *
 * Implements:
 * 1. Synthetic Flow Generator (11 scenarios with RFC 5737 documentation IPs)
 * 2. 15-Feature Extractor
 * 3. 8 Signature Rules Engine
 * 4. Z-Score Statistical Anomaly Detector
 * 5. ML Simulation Scoring
 * 6. Hybrid Risk Engine (0-100 scale)
 * 7. Alert Generation & Correlation Engine
 * 8. Attack Injection Controls (SYN Flood, Port Scan, Brute Force, Exfiltration)
 */

// Initial Seed Rules
export const INITIAL_RULES = [
  {
    rule_id: 'IDS-001',
    rule_name: 'High Connection Rate',
    name: 'High Connection Rate',
    description: 'Flags flows where connection attempt velocity exceeds threshold (port scan / DoS indicator)',
    severity: 'HIGH',
    threshold: 50,
    metric: 'connection_rate',
    enabled: 1
  },
  {
    rule_id: 'IDS-002',
    rule_name: 'Repeated Failed Connections',
    name: 'Repeated Failed Connections',
    description: 'Flags flows with abnormal failure ratio and count (credential brute-force / auth attack)',
    severity: 'HIGH',
    threshold: 0.5,
    metric: 'failure_ratio',
    enabled: 1
  },
  {
    rule_id: 'IDS-003',
    rule_name: 'Multi-Port Probing Pattern',
    name: 'Multi-Port Probing Pattern',
    description: 'Detects reconnaissance scanning across multiple destination ports within a short window',
    severity: 'MEDIUM',
    threshold: 15,
    metric: 'unique_destination_ports',
    enabled: 1
  },
  {
    rule_id: 'IDS-004',
    rule_name: 'SYN-Heavy Flood Pattern',
    name: 'SYN-Heavy Flood Pattern',
    description: 'Identifies TCP SYN flood attempts where SYN packets dominate without completing handshakes',
    severity: 'CRITICAL',
    threshold: 0.8,
    metric: 'syn_ratio',
    enabled: 1
  },
  {
    rule_id: 'IDS-005',
    rule_name: 'Unusual Port Activity',
    name: 'Unusual Port Activity',
    description: 'Detects connections on uncommon high-risk ports (e.g. 4444, 6667, 8888, 31337)',
    severity: 'MEDIUM',
    threshold: 1,
    metric: 'suspicious_port',
    enabled: 1
  },
  {
    rule_id: 'IDS-006',
    rule_name: 'High Data Volume Outlier',
    name: 'High Data Volume Outlier',
    description: 'Flags extreme bandwidth consumption (potential data exfiltration or volumetric DDoS)',
    severity: 'HIGH',
    threshold: 1000000,
    metric: 'bytes_per_second',
    enabled: 1
  },
  {
    rule_id: 'IDS-007',
    rule_name: 'Connection Burst Anomaly',
    name: 'Connection Burst Anomaly',
    description: 'Detects sudden bursts of connection creations within sub-second intervals',
    severity: 'MEDIUM',
    threshold: 100,
    metric: 'connection_count',
    enabled: 1
  },
  {
    rule_id: 'IDS-008',
    rule_name: 'RST Tear-Down Flood',
    name: 'RST Tear-Down Flood',
    description: 'Flags anomalous volume of TCP RST reset packets attempting connection resets',
    severity: 'HIGH',
    threshold: 50,
    metric: 'rst_count',
    enabled: 1
  }
];

// RFC 5737 Safe Documentation IPs
const INTERNAL_IPS = ['192.0.2.10', '192.0.2.25', '192.0.2.50', '192.0.2.75', '192.0.2.100', '192.0.2.150'];
const EXTERNAL_IPS = ['198.51.100.15', '198.51.100.42', '198.51.100.88', '203.0.113.19', '203.0.113.77', '203.0.113.200'];

const COMMON_PORTS = [80, 443, 53, 22, 25, 3306, 5432, 8080];
const SUSPICIOUS_PORTS = [4444, 6667, 8888, 31337, 1337, 9001];

class StandaloneIDSEngine {
  constructor() {
    this.flows = [];
    this.alerts = [];
    this.rules = [...INITIAL_RULES];
    this.incidentNotes = {};
    this.alertCounter = 1000;
    this.listeners = new Set();
    this.isStreaming = true;
    this.streamInterval = null;
    this.speed = 1500; // ms

    this.initPreSeededData();
    this.startStreaming();
  }

  // Pre-seed realistic history across the last 24 hours
  initPreSeededData() {
    const now = Date.now();
    const scenarios = [
      'NORMAL_WEB', 'NORMAL_DNS', 'NORMAL_SSH', 'NORMAL_DATABASE', 'NORMAL_WEB',
      'SYN_HEAVY_PATTERN', 'NORMAL_DNS', 'REPEATED_FAILED_CONNECTIONS',
      'NORMAL_WEB', 'MULTI_PORT_PROBING_PATTERN', 'NORMAL_DATABASE',
      'HIGH_CONNECTION_RATE', 'NORMAL_WEB', 'UNUSUAL_PORT_ACTIVITY', 'HIGH_TRAFFIC_VOLUME'
    ];

    for (let i = 120; i >= 0; i--) {
      const timestamp = new Date(now - i * 12 * 60 * 1000).toISOString();
      const scenario = scenarios[Math.floor(Math.random() * scenarios.length)];
      this.generateAndProcessFlow(scenario, timestamp, false);
    }
  }

  generateRawFlow(scenario, timestamp = new Date().toISOString()) {
    const isInternalSrc = Math.random() > 0.4;
    const source_ip = isInternalSrc 
      ? INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)]
      : EXTERNAL_IPS[Math.floor(Math.random() * EXTERNAL_IPS.length)];
    
    const destination_ip = isInternalSrc
      ? EXTERNAL_IPS[Math.floor(Math.random() * EXTERNAL_IPS.length)]
      : INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)];

    const flow = {
      flow_id: 'FLW-' + Math.random().toString(36).substring(2, 10).toUpperCase(),
      timestamp,
      source_ip,
      destination_ip,
      source_port: Math.floor(Math.random() * 50000) + 1024,
      destination_port: COMMON_PORTS[Math.floor(Math.random() * COMMON_PORTS.length)],
      protocol: 'TCP',
      packet_count: Math.floor(Math.random() * 30) + 5,
      byte_count: Math.floor(Math.random() * 25000) + 1000,
      duration_seconds: +(Math.random() * 3 + 0.2).toFixed(2),
      connection_count: Math.floor(Math.random() * 3) + 1,
      failed_connection_count: 0,
      syn_count: 1,
      rst_count: 0,
      scenario_type: scenario
    };

    // Apply specific scenario profiles
    switch (scenario) {
      case 'NORMAL_DNS':
        flow.protocol = 'UDP';
        flow.destination_port = 53;
        flow.packet_count = 2;
        flow.byte_count = 168;
        flow.duration_seconds = 0.05;
        flow.syn_count = 0;
        break;

      case 'SYN_HEAVY_PATTERN':
        flow.packet_count = Math.floor(Math.random() * 300) + 200;
        flow.syn_count = Math.floor(flow.packet_count * 0.92);
        flow.duration_seconds = 0.8;
        flow.destination_port = 80;
        break;

      case 'REPEATED_FAILED_CONNECTIONS':
        flow.connection_count = Math.floor(Math.random() * 40) + 25;
        flow.failed_connection_count = Math.floor(flow.connection_count * 0.85);
        flow.destination_port = 22;
        break;

      case 'MULTI_PORT_PROBING_PATTERN':
        flow.connection_count = Math.floor(Math.random() * 50) + 30;
        flow.destination_port = Math.floor(Math.random() * 1000) + 1;
        flow.duration_seconds = 0.5;
        break;

      case 'HIGH_CONNECTION_RATE':
        flow.duration_seconds = 0.2;
        flow.connection_count = Math.floor(Math.random() * 120) + 60;
        flow.destination_port = 443;
        break;

      case 'UNUSUAL_PORT_ACTIVITY':
        flow.destination_port = SUSPICIOUS_PORTS[Math.floor(Math.random() * SUSPICIOUS_PORTS.length)];
        flow.packet_count = 45;
        flow.byte_count = 18000;
        break;

      case 'HIGH_TRAFFIC_VOLUME':
        flow.packet_count = Math.floor(Math.random() * 15000) + 8000;
        flow.byte_count = Math.floor(Math.random() * 25000000) + 15000000;
        flow.duration_seconds = 4.5;
        break;

      default:
        break;
    }

    return flow;
  }

  extractFeatures(flow) {
    const dur = Math.max(flow.duration_seconds || 0.001, 0.001);
    const pkts = Math.max(flow.packet_count || 1, 1);
    const bytes = flow.byte_count || 0;
    const conns = Math.max(flow.connection_count || 1, 1);

    return {
      bytes_per_second: bytes / dur,
      packets_per_second: pkts / dur,
      connection_rate: conns / dur,
      failure_ratio: (flow.failed_connection_count || 0) / conns,
      syn_ratio: (flow.syn_count || 0) / pkts,
      average_packet_size: bytes / pkts,
      unique_destination_ports: flow.scenario_type === 'MULTI_PORT_PROBING_PATTERN' ? 28 : 1,
      suspicious_port: SUSPICIOUS_PORTS.includes(flow.destination_port) ? 1 : 0
    };
  }

  evaluateRules(features, flow) {
    const matched = [];
    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      let hit = false;
      let val = 0;

      switch (rule.rule_id) {
        case 'IDS-001':
          val = features.connection_rate;
          hit = val > rule.threshold;
          break;
        case 'IDS-002':
          val = features.failure_ratio;
          hit = val > rule.threshold && flow.failed_connection_count > 5;
          break;
        case 'IDS-003':
          val = features.unique_destination_ports;
          hit = val > rule.threshold;
          break;
        case 'IDS-004':
          val = features.syn_ratio;
          hit = val > rule.threshold && flow.syn_count > 30;
          break;
        case 'IDS-005':
          val = features.suspicious_port;
          hit = val === 1;
          break;
        case 'IDS-006':
          val = features.bytes_per_second;
          hit = val > rule.threshold;
          break;
        case 'IDS-007':
          val = flow.connection_count;
          hit = val > rule.threshold;
          break;
        case 'IDS-008':
          val = flow.rst_count || 0;
          hit = val > rule.threshold;
          break;
        default:
          break;
      }

      if (hit) {
        matched.push({
          rule_id: rule.rule_id,
          name: rule.rule_name || rule.name,
          severity: rule.severity,
          threshold: rule.threshold,
          observed_value: +(val.toFixed(2))
        });
      }
    }
    return matched;
  }

  calculateAnomaly(features) {
    let score = 5;
    if (features.connection_rate > 30) score += 25;
    if (features.syn_ratio > 0.7) score += 35;
    if (features.failure_ratio > 0.4) score += 30;
    if (features.bytes_per_second > 500000) score += 20;
    if (features.suspicious_port) score += 20;
    return Math.min(Math.round(score + Math.random() * 5), 100);
  }

  generateAndProcessFlow(scenarioType = 'NORMAL_WEB', timestamp = new Date().toISOString(), notify = true) {
    const rawFlow = this.generateRawFlow(scenarioType, timestamp);
    const features = this.extractFeatures(rawFlow);
    const matchedRules = this.evaluateRules(features, rawFlow);
    const anomalyScore = this.calculateAnomaly(features);

    // Simulated Random Forest probability
    let mlProb = 0.05;
    if (matchedRules.length > 0 || anomalyScore > 50) {
      mlProb = +(Math.min(0.88 + Math.random() * 0.11, 0.99).toFixed(3));
    } else {
      mlProb = +(Math.random() * 0.12).toFixed(3);
    }

    // Weighted Risk Engine
    let ruleScore = 0;
    for (const r of matchedRules) {
      if (r.severity === 'CRITICAL') ruleScore = Math.max(ruleScore, 95);
      else if (r.severity === 'HIGH') ruleScore = Math.max(ruleScore, 80);
      else if (r.severity === 'MEDIUM') ruleScore = Math.max(ruleScore, 60);
      else ruleScore = Math.max(ruleScore, 35);
    }

    const compositeScore = Math.round(ruleScore * 0.4 + anomalyScore * 0.3 + (mlProb * 100) * 0.3);

    let classification = 'NORMAL';
    let severity = 'INFO';
    if (compositeScore >= 80) {
      classification = 'CRITICAL INVESTIGATION';
      severity = 'CRITICAL';
    } else if (compositeScore >= 60) {
      classification = 'HIGH RISK';
      severity = 'HIGH';
    } else if (compositeScore >= 40) {
      classification = 'SUSPICIOUS';
      severity = 'MEDIUM';
    } else if (compositeScore >= 20) {
      classification = 'LOW RISK';
      severity = 'LOW';
    }

    const flowRecord = {
      ...rawFlow,
      risk_score: compositeScore,
      classification,
      severity
    };

    this.flows.unshift(flowRecord);
    if (this.flows.length > 1000) this.flows.pop();

    let newAlert = null;
    if (compositeScore >= 35 || matchedRules.length > 0) {
      this.alertCounter += 1;
      const alertId = `ALT-${this.alertCounter}`;
      const primaryRule = matchedRules[0] || { name: 'Statistical Anomaly Spike', severity: 'MEDIUM' };

      newAlert = {
        id: alertId,
        alert_id: alertId,
        flow_id: flowRecord.flow_id,
        created_at: timestamp,
        timestamp,
        time: timestamp,
        source_ip: flowRecord.source_ip,
        sourceIp: flowRecord.source_ip,
        destination_ip: flowRecord.destination_ip,
        destIp: flowRecord.destination_ip,
        source_port: flowRecord.source_port,
        sourcePort: flowRecord.source_port,
        destination_port: flowRecord.destination_port,
        destPort: flowRecord.destination_port,
        protocol: flowRecord.protocol,
        alert_type: primaryRule.name,
        type: primaryRule.name,
        severity: primaryRule.severity || severity,
        risk_score: compositeScore,
        riskScore: compositeScore,
        anomaly_score: anomalyScore,
        ml_score: mlProb,
        status: 'NEW',
        rule_ids: matchedRules.map(r => r.rule_id),
        rules_matched: matchedRules,
        description: `Automated detection triggered by ${matchedRules.length} rule matches and a statistical anomaly score of ${anomalyScore}%.`
      };

      this.alerts.unshift(newAlert);
      if (this.alerts.length > 300) this.alerts.pop();
    }

    if (notify) {
      this.broadcast({
        type: 'flow',
        flow: flowRecord,
        alert: newAlert
      });
    }

    return { flow: flowRecord, alert: newAlert };
  }

  // Attack Injection methods for interactive SOC demos
  injectAttack(type) {
    let scenario = 'SYN_HEAVY_PATTERN';
    if (type === 'port_scan') scenario = 'MULTI_PORT_PROBING_PATTERN';
    if (type === 'brute_force') scenario = 'REPEATED_FAILED_CONNECTIONS';
    if (type === 'dos') scenario = 'HIGH_CONNECTION_RATE';
    if (type === 'exfiltration') scenario = 'HIGH_TRAFFIC_VOLUME';
    if (type === 'c2_backdoor') scenario = 'UNUSUAL_PORT_ACTIVITY';

    // Inject immediate burst of 5 attack flows
    const results = [];
    for (let i = 0; i < 5; i++) {
      results.push(this.generateAndProcessFlow(scenario, new Date().toISOString(), true));
    }
    return results;
  }

  startStreaming() {
    if (this.streamInterval) clearInterval(this.streamInterval);
    this.isStreaming = true;
    this.streamInterval = setInterval(() => {
      if (!this.isStreaming) return;
      const isSuspicious = Math.random() < 0.28;
      const normalTypes = ['NORMAL_WEB', 'NORMAL_DNS', 'NORMAL_SSH', 'NORMAL_DATABASE', 'NORMAL_EMAIL'];
      const attackTypes = ['SYN_HEAVY_PATTERN', 'REPEATED_FAILED_CONNECTIONS', 'MULTI_PORT_PROBING_PATTERN', 'HIGH_CONNECTION_RATE', 'UNUSUAL_PORT_ACTIVITY'];

      const scenario = isSuspicious 
        ? attackTypes[Math.floor(Math.random() * attackTypes.length)]
        : normalTypes[Math.floor(Math.random() * normalTypes.length)];

      this.generateAndProcessFlow(scenario, new Date().toISOString(), true);
    }, this.speed);
  }

  toggleStreaming(active) {
    this.isStreaming = active !== undefined ? active : !this.isStreaming;
    return this.isStreaming;
  }

  setSpeed(ms) {
    this.speed = ms;
    if (this.isStreaming) {
      this.startStreaming();
    }
  }

  subscribe(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  broadcast(event) {
    this.listeners.forEach(cb => {
      try { cb(event); } catch (e) { console.error(e); }
    });
  }

  getFlows(limit = 100) {
    return this.flows.slice(0, limit);
  }

  // Analytics query helpers matching backend API contract
  getStats() {
    const total = this.flows.length;
    const normal = this.flows.filter(f => f.classification === 'NORMAL').length;
    const suspicious = total - normal;
    const openAlerts = this.alerts.filter(a => a.status === 'NEW' || a.status === 'INVESTIGATING').length;
    const criticalAlerts = this.alerts.filter(a => a.severity === 'CRITICAL' && a.status !== 'RESOLVED').length;
    const avgRisk = total > 0 ? Math.round(this.flows.reduce((acc, f) => acc + (f.risk_score || 0), 0) / total) : 0;

    return {
      totalFlows: total,
      total_flows: total,
      normalTraffic: normal,
      normal_flows: normal,
      suspiciousTraffic: suspicious,
      suspicious_flows: suspicious,
      openAlerts,
      open_alerts: openAlerts,
      criticalAlerts,
      critical_alerts: criticalAlerts,
      averageRiskScore: avgRisk,
      avg_risk_score: avgRisk
    };
  }

  getTrafficTimeline() {
    // Generate 24 hourly buckets
    const buckets = {};
    for (let i = 0; i < 24; i++) {
      const h = `${String(i).padStart(2, '0')}:00`;
      buckets[h] = { time: h, normal: 0, suspicious: 0, count: 0 };
    }

    this.flows.forEach(f => {
      const d = new Date(f.timestamp);
      const h = `${String(d.getHours()).padStart(2, '0')}:00`;
      if (buckets[h]) {
        if (f.classification === 'NORMAL') buckets[h].normal += 1;
        else buckets[h].suspicious += 1;
        buckets[h].count += 1;
      }
    });

    return Object.values(buckets);
  }

  getSeverityDistribution() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    this.alerts.forEach(a => {
      if (counts[a.severity] !== undefined) counts[a.severity] += 1;
    });

    return [
      { name: 'CRITICAL', severity: 'CRITICAL', count: counts.CRITICAL },
      { name: 'HIGH', severity: 'HIGH', count: counts.HIGH },
      { name: 'MEDIUM', severity: 'MEDIUM', count: counts.MEDIUM },
      { name: 'LOW', severity: 'LOW', count: counts.LOW }
    ];
  }

  getProtocolDistribution() {
    const map = {};
    this.flows.forEach(f => {
      const proto = f.protocol || 'TCP';
      map[proto] = (map[proto] || 0) + 1;
    });

    return Object.entries(map).map(([name, count]) => ({
      name,
      value: count,
      count
    }));
  }

  getPortDistribution() {
    const map = {};
    this.flows.forEach(f => {
      const p = String(f.destination_port || 80);
      map[p] = (map[p] || 0) + 1;
    });

    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({
        name: `Port ${name}`,
        port: parseInt(name, 10),
        value: count,
        count
      }));
  }

  getTopSources() {
    const map = {};
    this.alerts.forEach(a => {
      map[a.source_ip] = (map[a.source_ip] || 0) + 1;
    });

    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([ip, count]) => ({
        ip,
        name: ip,
        count
      }));
  }

  updateAlertStatus(id, newStatus, analyst = 'SOC-Lead') {
    const alert = this.alerts.find(a => a.id === id || a.alert_id === id);
    if (alert) {
      alert.status = newStatus;
      if (!this.incidentNotes[id]) this.incidentNotes[id] = [];
      this.incidentNotes[id].unshift({
        note_id: 'NOT-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
        analyst,
        note: `Status updated to ${newStatus}`,
        action: 'STATUS_CHANGE',
        created_at: new Date().toISOString()
      });
      this.broadcast({ type: 'alert_update', alert });
      return alert;
    }
    return null;
  }

  addAlertNote(id, noteText, analyst = 'SOC-Analyst-Tier1') {
    if (!this.incidentNotes[id]) this.incidentNotes[id] = [];
    const note = {
      note_id: 'NOT-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
      analyst,
      note: noteText,
      action: 'COMMENT',
      created_at: new Date().toISOString()
    };
    this.incidentNotes[id].unshift(note);
    return note;
  }

  getAlertNotes(id) {
    return this.incidentNotes[id] || [
      {
        note_id: 'NOT-INIT01',
        analyst: 'Automated-Correlation-Engine',
        note: 'Alert ingested and initial triage metadata generated.',
        action: 'TRIAGE',
        created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString()
      }
    ];
  }

  updateRule(id, updates) {
    const rule = this.rules.find(r => r.rule_id === id);
    if (rule) {
      Object.assign(rule, updates);
      return rule;
    }
    return null;
  }
}

// Global Singleton Engine
export const standaloneEngine = new StandaloneIDSEngine();
