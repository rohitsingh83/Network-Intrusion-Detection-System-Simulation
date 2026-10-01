/**
 * mock-engine.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Full in-browser IDS simulation for GitHub Pages / standalone mode.
 * Mirrors the Python backend logic: traffic generation → feature extraction
 * → rule detection → anomaly scoring → risk scoring → alert generation.
 *
 * Uses RFC 5737 documentation IP ranges only (192.0.2.x, 198.51.100.x,
 * 203.0.113.x) — safe, synthetic, no real network traffic.
 */

import type {
  Flow, Alert, AlertNote, DashboardStats,
  TrafficPoint, ProtocolDist, SeverityDist, PortDist, SourceDist,
} from '@/types';

// ─── Deterministic seeded RNG (Mulberry32) ────────────────────────────────────
function mulberry32(seed: number) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

let _rng = mulberry32(Date.now() & 0xfffffff);
const rnd = () => _rng();
const rndInt = (min: number, max: number) => Math.floor(rnd() * (max - min + 1)) + min;
const rndChoice = <T>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)];

// ─── RFC 5737 IP pools ────────────────────────────────────────────────────────
const RFC5737 = ['192.0.2', '198.51.100', '203.0.113'];
function randIP(seed?: number): string {
  const base = seed !== undefined ? RFC5737[seed % RFC5737.length] : rndChoice(RFC5737);
  return `${base}.${rndInt(1, 254)}`;
}

// Well-known destination IPs (servers)
const SERVER_IPS = Array.from({ length: 12 }, (_, i) => randIP(i % 3) + '.' + (i * 10 + 10));
const CLIENT_IPS = Array.from({ length: 30 }, () => randIP());

const COMMON_DST_PORTS = [80, 443, 22, 53, 3306, 5432, 8080, 25, 110, 3389, 21, 8443];
const PROTOCOLS = ['TCP', 'UDP', 'ICMP'] as const;

// ─── Scenario definitions ─────────────────────────────────────────────────────
type ScenarioType =
  | 'NORMAL_WEB' | 'NORMAL_DNS' | 'NORMAL_SSH' | 'NORMAL_EMAIL' | 'NORMAL_DATABASE'
  | 'HIGH_CONNECTION_RATE' | 'REPEATED_FAILED_CONNECTIONS' | 'MULTI_PORT_PROBING_PATTERN'
  | 'SYN_HEAVY_PATTERN' | 'UNUSUAL_PORT_ACTIVITY' | 'HIGH_TRAFFIC_VOLUME';

interface ScenarioSpec {
  type: ScenarioType;
  label: 'NORMAL' | 'SUSPICIOUS' | 'POTENTIAL_INTRUSION';
  weight: number;
  dstPort: number | null;
  protocol: typeof PROTOCOLS[number];
  packetRange: [number, number];
  byteRange: [number, number];
  durationRange: [number, number];
  connRange: [number, number];
  failedConnRange: [number, number];
  synRange: [number, number];
  rstRange: [number, number];
}

const SCENARIOS: ScenarioSpec[] = [
  { type: 'NORMAL_WEB',   label: 'NORMAL',              weight: 30, dstPort: 443,  protocol: 'TCP',  packetRange: [5,40],   byteRange: [2000,50000],  durationRange: [0.1,5],   connRange: [1,5],    failedConnRange: [0,0], synRange: [1,3],   rstRange: [0,1] },
  { type: 'NORMAL_DNS',   label: 'NORMAL',              weight: 20, dstPort: 53,   protocol: 'UDP',  packetRange: [1,4],    byteRange: [60,500],      durationRange: [0.01,0.5],connRange: [1,2],    failedConnRange: [0,0], synRange: [0,0],   rstRange: [0,0] },
  { type: 'NORMAL_SSH',   label: 'NORMAL',              weight: 10, dstPort: 22,   protocol: 'TCP',  packetRange: [20,200], byteRange: [5000,80000],  durationRange: [10,300],  connRange: [1,2],    failedConnRange: [0,1], synRange: [1,2],   rstRange: [0,0] },
  { type: 'NORMAL_EMAIL', label: 'NORMAL',              weight: 8,  dstPort: 25,   protocol: 'TCP',  packetRange: [4,20],   byteRange: [1000,20000],  durationRange: [0.5,10],  connRange: [1,3],    failedConnRange: [0,0], synRange: [1,2],   rstRange: [0,0] },
  { type: 'NORMAL_DATABASE', label: 'NORMAL',           weight: 7,  dstPort: 3306, protocol: 'TCP',  packetRange: [10,100], byteRange: [500,50000],   durationRange: [0.1,2],   connRange: [1,10],   failedConnRange: [0,0], synRange: [1,5],   rstRange: [0,1] },
  { type: 'HIGH_CONNECTION_RATE',          label: 'SUSPICIOUS',         weight: 8,  dstPort: null, protocol: 'TCP', packetRange: [1,5],   byteRange: [100,2000],    durationRange: [0.001,0.1], connRange: [80,200],   failedConnRange: [5,30],  synRange: [50,150], rstRange: [10,50] },
  { type: 'REPEATED_FAILED_CONNECTIONS',   label: 'SUSPICIOUS',         weight: 7,  dstPort: 22,   protocol: 'TCP', packetRange: [1,3],   byteRange: [60,300],      durationRange: [0.01,0.5],  connRange: [10,50],   failedConnRange: [10,50], synRange: [5,30],   rstRange: [5,30] },
  { type: 'MULTI_PORT_PROBING_PATTERN',    label: 'POTENTIAL_INTRUSION', weight: 4,  dstPort: null, protocol: 'TCP', packetRange: [1,2],   byteRange: [40,200],      durationRange: [0.001,0.05],connRange: [50,150],  failedConnRange: [40,130],synRange: [50,150], rstRange: [40,130] },
  { type: 'SYN_HEAVY_PATTERN',             label: 'POTENTIAL_INTRUSION', weight: 3,  dstPort: 80,   protocol: 'TCP', packetRange: [1,2],   byteRange: [40,120],      durationRange: [0.001,0.01],connRange: [200,500], failedConnRange: [150,450],synRange: [200,500],rstRange: [150,450] },
  { type: 'UNUSUAL_PORT_ACTIVITY',         label: 'SUSPICIOUS',         weight: 2,  dstPort: null, protocol: 'TCP', packetRange: [2,10],  byteRange: [200,5000],    durationRange: [0.01,1],    connRange: [1,5],     failedConnRange: [0,2],   synRange: [1,5],    rstRange: [0,2] },
  { type: 'HIGH_TRAFFIC_VOLUME',           label: 'SUSPICIOUS',         weight: 1,  dstPort: 80,   protocol: 'TCP', packetRange: [500,5000],byteRange: [500000,5000000],durationRange: [0.5,5],   connRange: [1,3],     failedConnRange: [0,1],   synRange: [1,3],    rstRange: [0,1] },
];

const TOTAL_WEIGHT = SCENARIOS.reduce((s, sc) => s + sc.weight, 0);

function pickScenario(): ScenarioSpec {
  let r = rnd() * TOTAL_WEIGHT;
  for (const sc of SCENARIOS) {
    r -= sc.weight;
    if (r <= 0) return sc;
  }
  return SCENARIOS[0];
}

// ─── Flow generation ──────────────────────────────────────────────────────────
let _flowCounter = 1000;

export function generateFlow(tsOverride?: Date): Flow {
  const sc = pickScenario();
  const ts = tsOverride ?? new Date();
  const srcIp = rndChoice(CLIENT_IPS);
  const dstIp = rndChoice(SERVER_IPS);
  const dstPort = sc.dstPort ?? rndInt(1024, 65535);
  const srcPort = rndInt(49152, 65534);
  const packets = rndInt(...sc.packetRange);
  const bytes = rndInt(...sc.byteRange);
  const duration = parseFloat((rnd() * (sc.durationRange[1] - sc.durationRange[0]) + sc.durationRange[0]).toFixed(3));
  const conns = rndInt(...sc.connRange);
  const failedConns = rndInt(...sc.failedConnRange);
  const syns = rndInt(...sc.synRange);
  const rsts = rndInt(...sc.rstRange);

  // Risk score calculation (mirrors Python risk_engine)
  let risk = 0;
  if (sc.label !== 'NORMAL') risk += 30;
  if (sc.label === 'POTENTIAL_INTRUSION') risk += 30;
  if (failedConns > 20) risk += 15;
  if (syns > 100) risk += 10;
  if (conns > 100) risk += 10;
  risk = Math.min(100, risk + rndInt(0, 5));

  return {
    flow_id: `GH-${_flowCounter++}`,
    timestamp: ts.toISOString(),
    source_ip: srcIp,
    destination_ip: dstIp,
    source_port: srcPort,
    destination_port: dstPort,
    protocol: sc.protocol,
    packet_count: packets,
    byte_count: bytes,
    duration_seconds: duration,
    classification: sc.label,
    risk_score: risk,
    scenario_type: sc.type,
  };
}

// ─── Rule detection ───────────────────────────────────────────────────────────
const RULES = [
  { id: 'R001', name: 'Port Scan Detection',         fn: (f: Flow) => f.scenario_type === 'MULTI_PORT_PROBING_PATTERN' },
  { id: 'R002', name: 'SYN Flood Detection',          fn: (f: Flow) => f.scenario_type === 'SYN_HEAVY_PATTERN' },
  { id: 'R003', name: 'Brute Force SSH',              fn: (f: Flow) => f.scenario_type === 'REPEATED_FAILED_CONNECTIONS' },
  { id: 'R004', name: 'High Connection Rate',         fn: (f: Flow) => f.scenario_type === 'HIGH_CONNECTION_RATE' },
  { id: 'R005', name: 'Unusual Port Activity',        fn: (f: Flow) => f.scenario_type === 'UNUSUAL_PORT_ACTIVITY' },
  { id: 'R006', name: 'High Traffic Volume',          fn: (f: Flow) => f.scenario_type === 'HIGH_TRAFFIC_VOLUME' },
  { id: 'R007', name: 'Failed Connection Threshold',  fn: (f: Flow) => f.classification !== 'NORMAL' },
  { id: 'R008', name: 'Anomalous Packet Rate',        fn: (f: Flow) => f.risk_score > 60 },
];

function getTriggeredRules(flow: Flow): string[] {
  return RULES.filter(r => r.fn(flow)).map(r => r.name);
}

// ─── Alert generation ─────────────────────────────────────────────────────────
let _alertCounter = 100;

const SEVERITY_THRESHOLDS: Array<{ min: number; sev: Alert['severity'] }> = [
  { min: 80, sev: 'CRITICAL' },
  { min: 60, sev: 'HIGH' },
  { min: 40, sev: 'MEDIUM' },
  { min: 20, sev: 'LOW' },
  { min: 0,  sev: 'INFO' },
];

const PLAYBOOKS: Record<string, string[]> = {
  'Port Scan Detection':        ['Block source IP at perimeter firewall', 'Enable port scan protection on IPS', 'Notify SOC Tier 2 analyst', 'Check for lateral movement indicators'],
  'SYN Flood Detection':        ['Enable SYN cookies on affected hosts', 'Rate-limit TCP SYN packets from source', 'Activate DDoS mitigation profile', 'Alert network operations team'],
  'Brute Force SSH':            ['Block source IP for 24h', 'Enable fail2ban / account lockout', 'Review SSH authorized_keys', 'Audit successful logins from same IP'],
  'High Connection Rate':       ['Rate-limit connections from source', 'Check for botnet C2 indicators', 'Review firewall connection table', 'Investigate destination service logs'],
  'High Traffic Volume':        ['Capture and analyze packet sample', 'Check for data exfiltration patterns', 'Review bandwidth utilization trends', 'Alert data loss prevention team'],
  'DEFAULT':                    ['Investigate source IP in threat intelligence', 'Review network flow logs for 24h window', 'Escalate if pattern continues', 'Document findings in ticketing system'],
};

function getPlaybook(rules: string[]): string[] {
  for (const rule of rules) {
    if (PLAYBOOKS[rule]) return PLAYBOOKS[rule];
  }
  return PLAYBOOKS['DEFAULT'];
}

function severityFromRisk(risk: number): Alert['severity'] {
  return SEVERITY_THRESHOLDS.find(t => risk >= t.min)!.sev;
}

const TITLES: Record<string, string> = {
  MULTI_PORT_PROBING_PATTERN:   'Port Scan Detected',
  SYN_HEAVY_PATTERN:            'SYN Flood / DDoS Pattern',
  REPEATED_FAILED_CONNECTIONS:  'Brute Force Attempt Detected',
  HIGH_CONNECTION_RATE:         'Anomalous Connection Rate',
  HIGH_TRAFFIC_VOLUME:          'High Traffic Volume Detected',
  UNUSUAL_PORT_ACTIVITY:        'Unusual Port Activity',
};

export function generateAlert(flow: Flow): Alert | null {
  if (flow.classification === 'NORMAL' && flow.risk_score < 20) return null;
  const rules = getTriggeredRules(flow);
  if (rules.length === 0 && flow.classification === 'NORMAL') return null;

  const sev = severityFromRisk(flow.risk_score);
  const title = TITLES[flow.scenario_type ?? ''] ?? `Suspicious Activity: ${flow.source_ip}`;

  return {
    alert_id: `ALT-GH-${_alertCounter++}`,
    flow_id: flow.flow_id,
    timestamp: flow.timestamp,
    severity: sev,
    status: 'NEW',
    title,
    description: `Suspicious network flow detected from ${flow.source_ip}:${flow.source_port} → ${flow.destination_ip}:${flow.destination_port} (${flow.protocol}). Risk score: ${flow.risk_score}/100.`,
    source_ip: flow.source_ip,
    destination_ip: flow.destination_ip,
    source_port: flow.source_port,
    destination_port: flow.destination_port,
    protocol: flow.protocol,
    risk_score: flow.risk_score,
    triggered_rules: rules,
    anomaly_score: parseFloat((rnd() * 3 + (flow.risk_score / 50)).toFixed(2)),
    ml_confidence: flow.risk_score > 40 ? parseFloat((0.5 + rnd() * 0.45).toFixed(2)) : undefined,
    recommended_actions: getPlaybook(rules),
    notes: [],
  };
}

// ─── In-memory store ──────────────────────────────────────────────────────────
class MockStore {
  flows: Flow[] = [];
  alerts: Alert[] = [];
  startTime = Date.now();

  constructor() {
    // Pre-seed with historical data (last 30 minutes)
    const now = new Date();
    for (let i = 200; i >= 0; i--) {
      const ts = new Date(now.getTime() - i * 9000); // every 9 seconds
      const flow = generateFlow(ts);
      this.flows.push(flow);
      const alert = generateAlert(flow);
      if (alert) this.alerts.push(alert);
    }
  }

  addFlow(flow: Flow) {
    this.flows.unshift(flow);
    if (this.flows.length > 2000) this.flows.pop();
  }

  addAlert(alert: Alert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > 500) this.alerts.pop();
  }

  getStats(): DashboardStats {
    const normal = this.flows.filter(f => f.classification === 'NORMAL').length;
    const suspicious = this.flows.filter(f => f.classification !== 'NORMAL').length;
    const open = this.alerts.filter(a => a.status === 'NEW' || a.status === 'INVESTIGATING').length;
    const critical = this.alerts.filter(a => a.severity === 'CRITICAL').length;
    const avgRisk = this.flows.length > 0
      ? this.flows.reduce((s, f) => s + f.risk_score, 0) / this.flows.length
      : 0;
    return {
      total_flows: this.flows.length,
      normal_flows: normal,
      suspicious_flows: suspicious,
      open_alerts: open,
      total_alerts: this.alerts.length,
      critical_alerts: critical,
      avg_risk_score: parseFloat(avgRisk.toFixed(1)),
    };
  }

  getTraffic(): TrafficPoint[] {
    // Group flows into 5-minute buckets for last 2 hours
    const buckets = new Map<string, { count: number; suspicious: number }>();
    const now = Date.now();
    for (let i = 23; i >= 0; i--) {
      const t = new Date(now - i * 5 * 60 * 1000);
      const key = t.toISOString().slice(0, 15) + '0:00.000Z'; // 5-min bucket
      buckets.set(key, { count: 0, suspicious: 0 });
    }
    for (const f of this.flows) {
      const t = new Date(f.timestamp);
      const key = t.toISOString().slice(0, 15) + '0:00.000Z';
      if (buckets.has(key)) {
        const b = buckets.get(key)!;
        b.count++;
        if (f.classification !== 'NORMAL') b.suspicious++;
      }
    }
    return Array.from(buckets.entries()).map(([timestamp, b]) => ({
      timestamp,
      count: b.count,
      suspicious: b.suspicious,
    }));
  }

  getProtocols(): ProtocolDist[] {
    const counts: Record<string, number> = {};
    for (const f of this.flows) {
      counts[f.protocol] = (counts[f.protocol] ?? 0) + 1;
    }
    return Object.entries(counts).map(([protocol, count]) => ({ protocol, count }));
  }

  getSeverity(): SeverityDist[] {
    const counts: Record<string, number> = {};
    for (const a of this.alerts) {
      counts[a.severity] = (counts[a.severity] ?? 0) + 1;
    }
    return Object.entries(counts).map(([severity, count]) => ({ severity, count }));
  }

  getPorts(): PortDist[] {
    const counts: Record<number, number> = {};
    for (const f of this.flows) {
      counts[f.destination_port] = (counts[f.destination_port] ?? 0) + 1;
    }
    return Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([port, count]) => ({ port: Number(port), count }));
  }

  getSources(): SourceDist[] {
    const counts: Record<string, number> = {};
    for (const f of this.flows) {
      if (f.classification !== 'NORMAL') {
        counts[f.source_ip] = (counts[f.source_ip] ?? 0) + 1;
      }
    }
    return Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([source_ip, count]) => ({ source_ip, count }));
  }
}

// Singleton store
export const mockStore = new MockStore();

// ─── Subscriber system for live updates ───────────────────────────────────────
type FlowCb = (flow: Flow) => void;
type AlertCb = (alert: Alert) => void;
const flowSubs = new Set<FlowCb>();
const alertSubs = new Set<AlertCb>();

export function subscribeFlows(cb: FlowCb) { flowSubs.add(cb); return () => flowSubs.delete(cb); }
export function subscribeAlerts(cb: AlertCb) { alertSubs.add(cb); return () => alertSubs.delete(cb); }

// Global simulation timer (starts once)
let _simTimer: ReturnType<typeof setInterval> | null = null;

export function startSimulation() {
  if (_simTimer) return;
  _simTimer = setInterval(() => {
    const flow = generateFlow();
    mockStore.addFlow(flow);
    flowSubs.forEach(cb => cb(flow));

    const alert = generateAlert(flow);
    if (alert) {
      mockStore.addAlert(alert);
      alertSubs.forEach(cb => cb(alert));
    }
  }, 1500); // new flow every 1.5 seconds
}

// ─── Mock API (matches real api-client.ts interface) ──────────────────────────
export const mockApi = {
  health: async () => ({
    status: 'ok',
    version: '1.0.0 (demo)',
    uptime_seconds: (Date.now() - mockStore.startTime) / 1000,
    database: 'in-memory (GitHub Pages demo)',
    ml_enabled: true,
    ml_ready: true,
    active_rules: RULES.length,
    baseline_ready: true,
    total_flows: mockStore.flows.length,
    open_alerts: mockStore.alerts.filter(a => a.status === 'NEW').length,
  }),

  getFlows: async (params?: { limit?: number; offset?: number; protocol?: string; classification?: string }) => {
    let flows = [...mockStore.flows];
    if (params?.protocol) flows = flows.filter(f => f.protocol === params.protocol);
    if (params?.classification) flows = flows.filter(f => f.classification === params.classification);
    const offset = params?.offset ?? 0;
    const limit = params?.limit ?? 100;
    return flows.slice(offset, offset + limit);
  },

  getAlerts: async (params?: { limit?: number; severity?: string; status?: string }) => {
    let alerts = [...mockStore.alerts];
    if (params?.severity) alerts = alerts.filter(a => a.severity === params.severity);
    if (params?.status) alerts = alerts.filter(a => a.status === params.status);
    return alerts.slice(0, params?.limit ?? 100);
  },

  getAlert: async (id: string) => {
    const alert = mockStore.alerts.find(a => a.alert_id === id);
    if (!alert) throw new Error(`Alert ${id} not found`);
    return alert;
  },

  updateAlertStatus: async (id: string, status: string, _analyst: string) => {
    const alert = mockStore.alerts.find(a => a.alert_id === id);
    if (!alert) throw new Error(`Alert ${id} not found`);
    alert.status = status as Alert['status'];
    return { ...alert };
  },

  addNote: async (id: string, note: string, analyst: string, action?: string) => {
    const alert = mockStore.alerts.find(a => a.alert_id === id);
    if (!alert) throw new Error(`Alert ${id} not found`);
    const newNote: AlertNote = {
      note, analyst, action,
      timestamp: new Date().toISOString(),
    };
    alert.notes = [...(alert.notes ?? []), newNote];
    return { ...alert };
  },

  getStats: async () => mockStore.getStats(),
  getTraffic: async () => mockStore.getTraffic(),
  getProtocols: async () => mockStore.getProtocols(),
  getSeverity: async () => mockStore.getSeverity(),
  getPorts: async () => mockStore.getPorts(),
  getSources: async () => mockStore.getSources(),
  getRules: async () => RULES.map(r => ({ id: r.id, name: r.name, enabled: true })),
};
