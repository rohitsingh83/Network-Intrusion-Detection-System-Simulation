// Browser-only API shim for GitHub Pages. It mirrors the local FastAPI response
// shapes, but keeps demo state in this visitor's localStorage. It never calls an API.

export const STATIC_STORAGE_KEY = 'sentinelflow.github-pages-demo.v1';
const STORAGE_VERSION = 1;
const SEVERITY_POINTS = { INFO: 10, LOW: 30, MEDIUM: 55, HIGH: 75, CRITICAL: 95 };
const SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUSES = ['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
const TRANSITIONS = {
  NEW: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
  INVESTIGATING: ['NEW', 'RESOLVED', 'FALSE_POSITIVE'],
  RESOLVED: ['INVESTIGATING'],
  FALSE_POSITIVE: ['INVESTIGATING'],
};
const RECOMMENDED_STEPS = [
  'Review related flow and alert records in the selected time window.',
  'Check whether the source and destination are known, expected assets.',
  'Compare the behavior with the relevant service and historical baseline.',
  'Review authentication and firewall logs where authorized.',
  'Review endpoint telemetry through approved tools if the asset is in scope.',
  'Document the evidence and disposition; a statistical signal is not proof of compromise.',
];

const DEFAULT_RULES = [
  { rule_id: 'IDS-001', rule_name: 'High Connection Rate', description: 'The observed connection rate is above the configured baseline.', severity: 'HIGH', threshold: 12, enabled: true, config: {} },
  { rule_id: 'IDS-002', rule_name: 'Repeated Failed Connections', description: 'Repeated connection failures and a high failure ratio were observed.', severity: 'HIGH', threshold: 5, enabled: true, config: { minimum_failure_ratio: 0.45 } },
  { rule_id: 'IDS-003', rule_name: 'Destination Port Diversity', description: 'A source contacted an unusually broad set of destination ports.', severity: 'HIGH', threshold: 12, enabled: true, config: {} },
  { rule_id: 'IDS-004', rule_name: 'SYN-Heavy Flow', description: 'SYN activity represents an unusually large share of observed packets.', severity: 'MEDIUM', threshold: 15, enabled: true, config: { minimum_syn_ratio: 0.70 } },
  { rule_id: 'IDS-005', rule_name: 'Unexpected Service-Port Protocol', description: 'A management or database service port used an unexpected transport protocol.', severity: 'MEDIUM', threshold: 1, enabled: true, config: { ports: [22, 3389, 3306, 5432, 445] } },
  { rule_id: 'IDS-006', rule_name: 'High Traffic Volume', description: 'The flow volume or byte rate exceeded the configured limit.', severity: 'HIGH', threshold: 2000000, enabled: true, config: { bytes_per_second_threshold: 5000000 } },
];

// Educational fallback baseline. The Python app separately fits its baseline
// from the included NORMAL-labelled synthetic training records.
const BASELINE = {
  packets_per_second: { mean: 8, std: 5, q1: 3, q3: 12, floor: 0.75 },
  bytes_per_second: { mean: 8000, std: 9000, q1: 2000, q3: 14000, floor: 1000 },
  connection_rate: { mean: 0.8, std: 1, q1: 0.2, q3: 1.4, floor: 0.25 },
  failure_ratio: { mean: 0.02, std: 0.06, q1: 0, q3: 0, floor: 0.05 },
  unique_destination_ports: { mean: 1.2, std: 1, q1: 1, q3: 1, floor: 0.5 },
};

const CATALOG = [
  ['NORMAL_WEB', 'NORMAL'], ['NORMAL_DNS', 'NORMAL'], ['NORMAL_SSH', 'NORMAL'],
  ['NORMAL_DATABASE', 'NORMAL'], ['NORMAL_EMAIL', 'NORMAL'],
  ['HIGH_CONNECTION_RATE', 'SUSPICIOUS'], ['REPEATED_FAILED_CONNECTIONS', 'SUSPICIOUS'],
  ['MULTI_PORT_PROBING_PATTERN', 'SUSPICIOUS'], ['SYN_HEAVY_PATTERN', 'SUSPICIOUS'],
  ['HIGH_TRAFFIC_VOLUME', 'SUSPICIOUS'], ['UNUSUAL_PORT_ACTIVITY', 'SUSPICIOUS'],
];
const NORMAL_SCENARIOS = ['NORMAL_WEB', 'NORMAL_DNS', 'NORMAL_SSH', 'NORMAL_DATABASE', 'NORMAL_EMAIL'];

const deepCopy = (value) => JSON.parse(JSON.stringify(value));
const clamp = (value, min = 0, max = 100) => Math.max(min, Math.min(max, Number(value) || 0));
const iso = (value) => new Date(value).toISOString();

function initialState() {
  const state = { version: STORAGE_VERSION, nextFlow: 1, flows: [], alerts: [], rules: deepCopy(DEFAULT_RULES) };
  const now = Date.now();
  for (let index = 0; index < 48; index += 1) {
    const scenario = CATALOG[index % CATALOG.length][0];
    addScenario(state, scenario, now - (47 - index) * 30 * 60 * 1000, true);
  }
  return state;
}

function getState() {
  try {
    const saved = JSON.parse(localStorage.getItem(STATIC_STORAGE_KEY) || 'null');
    if (saved?.version === STORAGE_VERSION && Array.isArray(saved.flows) && Array.isArray(saved.alerts) && Array.isArray(saved.rules)) return saved;
  } catch { /* Start with a clean synthetic seed if browser storage was edited or unavailable. */ }
  const fresh = initialState();
  saveState(fresh);
  return fresh;
}

function saveState(state) {
  localStorage.setItem(STATIC_STORAGE_KEY, JSON.stringify(state));
}

function featureRecord(raw) {
  const duration = Math.max(Number(raw.duration_seconds) || 0, 0.001);
  const packetCount = Math.max(Number(raw.packet_count) || 0, 0);
  const byteCount = Math.max(Number(raw.byte_count) || 0, 0);
  const connectionCount = Math.max(Number(raw.connection_count) || 0, 0);
  const failedCount = Math.max(Number(raw.failed_connection_count) || 0, 0);
  const synCount = Math.max(Number(raw.syn_count) || 0, 0);
  return {
    source_ip: raw.source_ip,
    destination_ip: raw.destination_ip,
    source_port: Number(raw.source_port) || 0,
    destination_port: Number(raw.destination_port) || 0,
    protocol: raw.protocol || 'TCP',
    packet_count: packetCount,
    byte_count: byteCount,
    duration_seconds: Number(raw.duration_seconds) || 0,
    duration: Number(raw.duration_seconds) || 0,
    bytes_per_second: byteCount / duration,
    packets_per_second: packetCount / duration,
    average_packet_size: packetCount ? byteCount / packetCount : 0,
    connection_count: connectionCount,
    failed_connection_count: failedCount,
    failure_ratio: failedCount / Math.max(connectionCount, 1),
    syn_count: synCount,
    rst_count: Number(raw.rst_count) || 0,
    syn_ratio: synCount / Math.max(packetCount, 1),
    unique_destination_ports: Math.max(1, Number(raw.unique_destination_ports) || 1),
    unique_destination_ips: Math.max(1, Number(raw.unique_destination_ips) || 1),
    connection_rate: connectionCount / duration,
    scenario_type: raw.scenario_type || 'UNSPECIFIED',
  };
}

function anomalyEvidence(features) {
  const details = Object.entries(BASELINE).map(([name, baseline]) => {
    const value = Number(features[name]) || 0;
    const scale = Math.max(baseline.std, (baseline.q3 - baseline.q1) / 1.349, baseline.floor);
    const z = Math.max(0, (value - baseline.mean) / scale);
    const component = Math.round(clamp((z - 1.5) * 24));
    return {
      feature: name,
      value: Number(value.toFixed(4)),
      baseline_mean: Number(baseline.mean.toFixed(4)),
      standard_deviation: Number(baseline.std.toFixed(4)),
      robust_scale: Number(scale.toFixed(4)),
      positive_z_score: Number(z.toFixed(3)),
      component_score: component,
    };
  }).sort((a, b) => b.component_score - a.component_score);
  const components = details.map((item) => item.component_score);
  const score = Math.round(0.60 * Math.max(0, ...components) + 0.40 * components.reduce((sum, item) => sum + item, 0) / Math.max(1, components.length));
  return { score: clamp(score), evidence: details };
}

function matchingRules(features, rules) {
  const get = (id) => rules.find((rule) => rule.rule_id === id) || DEFAULT_RULES.find((rule) => rule.rule_id === id);
  const matches = [];
  const add = (id, evidence) => {
    const rule = get(id);
    if (rule?.enabled) matches.push({ rule_id: id, name: rule.rule_name, severity: rule.severity, description: rule.description, threshold: rule.threshold, evidence });
  };
  let rule = get('IDS-001');
  if (rule.enabled && features.connection_rate >= Number(rule.threshold)) add('IDS-001', `${features.connection_rate.toFixed(2)} connections/s >= ${Number(rule.threshold).toFixed(2)}`);
  rule = get('IDS-002');
  const minFailure = Number(rule.config?.minimum_failure_ratio ?? 0.45);
  if (rule.enabled && features.failed_connection_count >= Number(rule.threshold) && features.failure_ratio >= minFailure) add('IDS-002', `${features.failed_connection_count.toFixed(0)} failures; ratio ${features.failure_ratio.toFixed(2)} >= ${minFailure.toFixed(2)}`);
  rule = get('IDS-003');
  if (rule.enabled && features.unique_destination_ports >= Number(rule.threshold)) add('IDS-003', `${features.unique_destination_ports.toFixed(0)} unique destination ports >= ${Number(rule.threshold).toFixed(0)}`);
  rule = get('IDS-004');
  const minSyn = Number(rule.config?.minimum_syn_ratio ?? 0.7);
  if (rule.enabled && features.syn_count >= Number(rule.threshold) && features.syn_ratio >= minSyn) add('IDS-004', `${features.syn_count.toFixed(0)} SYNs; SYN/packet ratio ${features.syn_ratio.toFixed(2)} >= ${minSyn.toFixed(2)}`);
  rule = get('IDS-005');
  const ports = rule.config?.ports || [22, 3389, 3306, 5432, 445];
  if (rule.enabled && ports.includes(Number(features.destination_port)) && features.protocol !== 'TCP') add('IDS-005', `${features.protocol} observed on TCP-oriented service port ${features.destination_port}`);
  rule = get('IDS-006');
  const rateLimit = Number(rule.config?.bytes_per_second_threshold ?? 5000000);
  if (rule.enabled && (features.byte_count >= Number(rule.threshold) || features.bytes_per_second >= rateLimit)) add('IDS-006', `${features.byte_count.toFixed(0)} bytes or ${features.bytes_per_second.toFixed(0)} bytes/s crossed configured volume limits`);
  return matches;
}

function severityFor(score) {
  return score > 80 ? 'CRITICAL' : score > 60 ? 'HIGH' : score > 40 ? 'MEDIUM' : score > 20 ? 'LOW' : 'INFO';
}
function classificationFor(score, matches) {
  if (matches.length || score > 40) return score > 60 ? 'POTENTIAL INTRUSION' : 'SUSPICIOUS';
  return 'NORMAL';
}
function riskBandFor(score) {
  return score <= 20 ? '0–20' : score <= 40 ? '21–40' : score <= 60 ? '41–60' : score <= 80 ? '61–80' : '81–100';
}

function scenarioFields(scenario, sequence) {
  const sourcePool = ['192.0.2.15', '192.0.2.77', '192.0.2.110', '192.0.2.128', '192.0.2.166', '192.0.2.210'];
  const destinationPool = ['198.51.100.20', '198.51.100.36', '198.51.100.114', '203.0.113.37', '203.0.113.50', '203.0.113.86'];
  const common = {
    source_ip: scenario === 'HIGH_CONNECTION_RATE' || scenario === 'MULTI_PORT_PROBING_PATTERN' ? '192.0.2.77' : sourcePool[sequence % sourcePool.length],
    destination_ip: destinationPool[sequence % destinationPool.length],
    source_port: 49152 + (sequence * 37 % 15000),
    destination_port: 443,
    protocol: 'TCP',
    packet_count: 42,
    byte_count: 23000,
    duration_seconds: 12,
    connection_count: 4,
    failed_connection_count: 0,
    syn_count: 4,
    rst_count: 0,
    unique_destination_ports: 1,
    unique_destination_ips: 1,
    scenario_type: scenario,
    label: 'NORMAL',
  };
  const cases = {
    NORMAL_WEB: { destination_port: 443, packet_count: 42, byte_count: 23000, duration_seconds: 12, connection_count: 4, syn_count: 4 },
    NORMAL_DNS: { destination_port: 53, protocol: 'UDP', packet_count: 4, byte_count: 320, duration_seconds: 1.5, connection_count: 1, syn_count: 0 },
    NORMAL_SSH: { destination_port: 22, packet_count: 22, byte_count: 2400, duration_seconds: 15, connection_count: 2, syn_count: 2 },
    NORMAL_DATABASE: { destination_port: 3306, packet_count: 64, byte_count: 18000, duration_seconds: 18, connection_count: 3, syn_count: 3 },
    NORMAL_EMAIL: { destination_port: 587, packet_count: 30, byte_count: 9000, duration_seconds: 10, connection_count: 2, syn_count: 2 },
    HIGH_CONNECTION_RATE: { packet_count: 102, byte_count: 77552, duration_seconds: 2.12, connection_count: 94, syn_count: 16, label: 'SUSPICIOUS' },
    REPEATED_FAILED_CONNECTIONS: { destination_port: 443, packet_count: 34, byte_count: 9400, duration_seconds: 8, connection_count: 12, failed_connection_count: 10, syn_count: 12, rst_count: 8, label: 'SUSPICIOUS' },
    MULTI_PORT_PROBING_PATTERN: { packet_count: 44, byte_count: 11600, duration_seconds: 14, connection_count: 32, unique_destination_ports: 28, label: 'SUSPICIOUS' },
    SYN_HEAVY_PATTERN: { packet_count: 85, byte_count: 5200, duration_seconds: 18, connection_count: 5, syn_count: 72, rst_count: 21, label: 'SUSPICIOUS' },
    HIGH_TRAFFIC_VOLUME: { packet_count: 2800, byte_count: 3200000, duration_seconds: 42, connection_count: 18, syn_count: 10, label: 'SUSPICIOUS' },
    UNUSUAL_PORT_ACTIVITY: { destination_port: 3306, protocol: 'UDP', packet_count: 12, byte_count: 2600, duration_seconds: 5, connection_count: 2, syn_count: 0, label: 'SUSPICIOUS' },
  };
  return { ...common, ...(cases[scenario] || cases.NORMAL_WEB) };
}

function makeAlertId() {
  const random = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `ALT-${Date.now().toString(36).toUpperCase()}-${random}`;
}

function addScenario(state, scenario, timestamp = Date.now(), seeding = false) {
  const sequence = state.nextFlow++;
  const raw = scenarioFields(scenario, sequence);
  raw.flow_id = `WEB-${String(sequence).padStart(5, '0')}`;
  raw.timestamp = iso(timestamp);
  const features = featureRecord(raw);
  const anomaly = anomalyEvidence(features);
  const matchedRules = matchingRules(features, state.rules);
  const ruleScore = matchedRules.length
    ? Math.min(100, Math.max(...matchedRules.map((item) => SEVERITY_POINTS[item.severity] || 30)) + Math.min(10, Math.max(0, (matchedRules.length - 1) * 5)))
    : 0;
  const riskScore = Math.round(0.60 * ruleScore + 0.40 * anomaly.score);
  const classification = classificationFor(riskScore, matchedRules);
  const severity = severityFor(riskScore);
  const fullFeatures = { ...features, anomaly_evidence: anomaly.evidence };
  const flow = {
    ...raw,
    risk_score: riskScore,
    anomaly_score: anomaly.score,
    ml_probability: null,
    classification,
    features: fullFeatures,
    matched_rules: matchedRules,
  };
  state.flows.unshift(flow);
  if (state.flows.length > 500) state.flows.length = 500;
  let alert = null;
  if (matchedRules.length || riskScore >= 41) {
    const primary = matchedRules[0] || { rule_id: 'ANOMALY-001', name: 'Statistical Anomaly', severity, description: 'The synthetic flow differs from the browser demo baseline.', evidence: `Anomaly score ${anomaly.score}/100` };
    const existing = !seeding && state.alerts.find((item) => item.source_ip === raw.source_ip && item.alert_type === primary.name && Date.now() - Date.parse(item.last_seen) <= 60000 && !['RESOLVED', 'FALSE_POSITIVE'].includes(item.status));
    const occurrence = { flow_id: flow.flow_id, observed_at: flow.timestamp, destination_ip: flow.destination_ip, destination_port: flow.destination_port, protocol: flow.protocol };
    if (existing) {
      existing.occurrence_count += 1;
      existing.last_seen = flow.timestamp;
      existing.updated_at = flow.timestamp;
      existing.occurrences.push(occurrence);
      if (existing.occurrences.length > 200) existing.occurrences.splice(0, existing.occurrences.length - 200);
      existing.risk_score = Math.max(existing.risk_score, riskScore);
      existing.severity = severityFor(existing.risk_score);
      existing.matched_rules = matchedRules;
      alert = existing;
    } else {
      alert = {
        alert_id: makeAlertId(), flow_id: flow.flow_id,
        source_ip: raw.source_ip, destination_ip: raw.destination_ip,
        protocol: raw.protocol, source_port: raw.source_port, destination_port: raw.destination_port,
        rule_id: primary.rule_id, alert_type: primary.name, severity,
        description: `${primary.evidence || primary.description} Synthetic detection evidence requires analyst triage; it is not proof of compromise.`,
        risk_score: riskScore, anomaly_score: anomaly.score, ml_probability: null,
        status: 'NEW', occurrence_count: 1,
        created_at: flow.timestamp, last_seen: flow.timestamp, updated_at: flow.timestamp,
        resolution_notes: null, matched_rules: matchedRules,
        notes: [], timeline: [], occurrences: [occurrence],
      };
      state.alerts.unshift(alert);
      if (state.alerts.length > 200) state.alerts.length = 200;
    }
  }
  if (!seeding) saveState(state);
  return { flow, evaluation: { features: fullFeatures, matched_rules: matchedRules, rule_score: ruleScore, anomaly_score: anomaly.score, ml_probability: null, risk_score: riskScore, risk_band: riskBandFor(riskScore), severity, classification }, alert };
}

function trafficData(state, hours, bucketMinutes) {
  const recentCutoff = Date.now() - hours * 3600000;
  const flows = state.flows.filter((flow) => Date.parse(flow.timestamp) >= recentCutoff).slice().reverse();
  const alerts = state.alerts.filter((alert) => Date.parse(alert.created_at) >= recentCutoff);
  const buckets = new Map();
  const protocols = new Map();
  const ports = new Map();
  const risks = { '0–20': 0, '21–40': 0, '41–60': 0, '61–80': 0, '81–100': 0 };
  const size = bucketMinutes * 60000;
  for (const flow of flows) {
    const timestamp = Math.floor(Date.parse(flow.timestamp) / size) * size;
    const point = buckets.get(timestamp) || { timestamp: iso(timestamp), normal: 0, suspicious: 0, packets: 0, bytes: 0, connections: 0, failed: 0, risk: 0, count: 0, alerts: 0 };
    point.count += 1;
    point[flow.classification === 'NORMAL' ? 'normal' : 'suspicious'] += 1;
    point.packets += flow.features.packets_per_second;
    point.bytes += flow.features.bytes_per_second;
    point.connections += flow.connection_count;
    point.failed += flow.failed_connection_count;
    point.risk += flow.risk_score;
    buckets.set(timestamp, point);
    protocols.set(flow.protocol, (protocols.get(flow.protocol) || 0) + 1);
    ports.set(String(flow.destination_port), (ports.get(String(flow.destination_port)) || 0) + 1);
    risks[riskBandFor(flow.risk_score)] += 1;
  }
  for (const alert of alerts) {
    const timestamp = Math.floor(Date.parse(alert.created_at) / size) * size;
    const point = buckets.get(timestamp);
    if (point) point.alerts += 1;
  }
  const timeline = [...buckets.entries()].sort((a, b) => a[0] - b[0]).map(([, point]) => ({
    timestamp: point.timestamp,
    normal: point.normal,
    suspicious: point.suspicious,
    packets_per_second: Number((point.packets / point.count).toFixed(2)),
    bytes_per_second: Number((point.bytes / point.count).toFixed(2)),
    connections_per_minute: Number((point.connections / Math.max(bucketMinutes, 1)).toFixed(2)),
    failed_connections: Number(point.failed.toFixed(2)),
    average_risk_score: Number((point.risk / point.count).toFixed(1)),
    alerts: point.alerts,
  }));
  const countBy = (items, key) => {
    const map = new Map();
    for (const item of items) map.set(item[key], (map.get(item[key]) || 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, value]) => ({ name, value }));
  };
  const severityCounts = Object.fromEntries(SEVERITY_ORDER.map((name) => [name, alerts.filter((alert) => alert.severity === name).length]));
  return {
    hours, bucket_minutes: bucketMinutes, timeline,
    protocol_distribution: [...protocols.entries()].map(([name, value]) => ({ name, value })),
    port_distribution: [...ports.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, value]) => ({ name, value })),
    risk_distribution: Object.entries(risks).map(([name, value]) => ({ name, value })),
    severity_distribution: SEVERITY_ORDER.map((name) => ({ name, value: severityCounts[name] })),
    top_alert_types: countBy(alerts, 'alert_type'),
    top_source_ips: countBy(alerts, 'source_ip'),
    flow_rows: flows.length,
  };
}

function dashboardStats(state) {
  const normal = state.flows.filter((flow) => flow.classification === 'NORMAL').length;
  const open = state.alerts.filter((alert) => ['NEW', 'INVESTIGATING'].includes(alert.status));
  const avg = state.flows.length ? state.flows.reduce((sum, flow) => sum + flow.risk_score, 0) / state.flows.length : 0;
  return {
    total_flows: state.flows.length,
    normal_flows: normal,
    suspicious_flows: state.flows.length - normal,
    total_alerts: state.alerts.length,
    open_alerts: open.length,
    critical_alerts: open.filter((alert) => alert.severity === 'CRITICAL').length,
    average_risk_score: Number(avg.toFixed(1)),
    last_alert_at: state.alerts[0]?.last_seen || null,
  };
}

function getAlertDetail(state, alertId) {
  const alert = state.alerts.find((item) => item.alert_id === alertId);
  if (!alert) throw new Error('Alert not found');
  const flow = state.flows.find((item) => item.flow_id === alert.flow_id);
  return { ...deepCopy(alert), flow: flow ? deepCopy(flow) : null, recommended_steps: RECOMMENDED_STEPS };
}

function parseBody(options) {
  if (!options?.body) return {};
  try { return JSON.parse(options.body); } catch { return {}; }
}

export function resetStaticDemo() {
  localStorage.removeItem(STATIC_STORAGE_KEY);
}

export async function staticApi(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const url = new URL(path, window.location.origin);
  const pathname = url.pathname;
  const state = getState();
  let result;

  if (method === 'GET' && pathname.endsWith('/api/dashboard/stats')) {
    result = dashboardStats(state);
  } else if (method === 'GET' && pathname.endsWith('/api/dashboard/traffic')) {
    const hours = Math.max(1, Number(url.searchParams.get('hours') || 24));
    const bucketMinutes = Math.max(1, Number(url.searchParams.get('bucket_minutes') || (hours >= 24 ? 60 : 10)));
    result = trafficData(state, hours, bucketMinutes);
  } else if (method === 'GET' && pathname.endsWith('/api/system')) {
    result = { name: 'SentinelFlow', version: '1.0.0-pages', ml_enabled: false, ml_model: null, anomaly_baseline_fitted: true, data_mode: 'browser-local synthetic flow records', api_key_protected_writes: false, static_demo: true };
  } else if (method === 'GET' && pathname.endsWith('/api/alerts')) {
    const items = state.alerts.slice().sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
    result = { items: items.slice(0, Number(url.searchParams.get('limit') || 100)).map((alert) => deepCopy(alert)) };
  } else if (method === 'GET' && pathname.endsWith('/api/flows')) {
    const search = (url.searchParams.get('search') || '').toLowerCase();
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') || 100)));
    const items = state.flows.filter((flow) => !search || [flow.flow_id, flow.source_ip, flow.destination_ip, flow.scenario_type].some((value) => String(value).toLowerCase().includes(search)));
    result = { items: items.slice(0, limit).map((flow) => deepCopy(flow)), count: items.length };
  } else if (method === 'GET' && pathname.endsWith('/api/rules')) {
    result = { items: deepCopy(state.rules) };
  } else if (method === 'GET' && /\/api\/alerts\/[^/]+$/.test(pathname)) {
    const id = decodeURIComponent(pathname.split('/').pop());
    result = getAlertDetail(state, id);
  } else if (method === 'POST' && /\/api\/simulation\/scenario\/[^/]+$/.test(pathname)) {
    const scenario = decodeURIComponent(pathname.split('/').pop());
    if (!CATALOG.some(([name]) => name === scenario)) throw new Error('Unknown synthetic scenario');
    const count = Math.min(50, Math.max(1, Number(url.searchParams.get('count') || 1)));
    const items = Array.from({ length: count }, () => addScenario(state, scenario));
    result = { items, records_processed: count, no_packets_transmitted: true };
  } else if (method === 'POST' && pathname.endsWith('/api/simulation/replay')) {
    const body = parseBody(options);
    const count = Math.min(200, Math.max(1, Number(body.count || 12)));
    const mode = body.mode === 'normal' ? 'normal' : 'mixed';
    const items = [];
    for (let index = 0; index < count; index += 1) {
      const scenario = mode === 'normal' ? NORMAL_SCENARIOS[index % NORMAL_SCENARIOS.length] : (index % 6 === 5 ? CATALOG[5 + (Math.floor(index / 6) % 6)][0] : NORMAL_SCENARIOS[index % NORMAL_SCENARIOS.length]);
      items.push(addScenario(state, scenario, Date.now() + index));
    }
    result = { records_processed: count, alerts_created_or_correlated: items.filter((item) => item.alert).length, items, no_packets_transmitted: true };
  } else if (method === 'PUT' && /\/api\/alerts\/[^/]+\/status$/.test(pathname)) {
    const id = decodeURIComponent(pathname.split('/').at(-2));
    const alert = state.alerts.find((item) => item.alert_id === id);
    if (!alert) throw new Error('Alert not found');
    const body = parseBody(options);
    const nextStatus = String(body.status || '').toUpperCase();
    if (!STATUSES.includes(nextStatus)) throw new Error('Invalid incident status');
    if (nextStatus !== alert.status && !TRANSITIONS[alert.status]?.includes(nextStatus)) throw new Error(`Status transition ${alert.status} → ${nextStatus} is not allowed`);
    const previous = alert.status;
    alert.status = nextStatus;
    alert.updated_at = iso(Date.now());
    if (body.resolution_notes) alert.resolution_notes = body.resolution_notes;
    alert.timeline.push({ timeline_id: alert.timeline.length + 1, alert_id: id, from_status: previous, to_status: nextStatus, note: body.note || body.resolution_notes || null, actor: body.actor || 'analyst', created_at: alert.updated_at });
    saveState(state);
    result = getAlertDetail(state, id);
  } else if (method === 'POST' && /\/api\/alerts\/[^/]+\/notes$/.test(pathname)) {
    const id = decodeURIComponent(pathname.split('/').at(-2));
    const alert = state.alerts.find((item) => item.alert_id === id);
    if (!alert) throw new Error('Alert not found');
    const body = parseBody(options);
    const note = String(body.note || '').trim();
    if (!note || note.length > 2000) throw new Error('Note must be between 1 and 2000 characters');
    const timestamp = iso(Date.now());
    const author = String(body.author || 'analyst').slice(0, 80);
    alert.notes.push({ note_id: alert.notes.length + 1, alert_id: id, note, author, created_at: timestamp });
    alert.timeline.push({ timeline_id: alert.timeline.length + 1, alert_id: id, from_status: null, to_status: 'NOTE_ADDED', note, actor: author, created_at: timestamp });
    saveState(state);
    result = getAlertDetail(state, id);
  } else if (method === 'PUT' && /\/api\/rules\/[^/]+$/.test(pathname)) {
    const id = decodeURIComponent(pathname.split('/').pop());
    const rule = state.rules.find((item) => item.rule_id === id);
    if (!rule) throw new Error('Rule not found');
    const body = parseBody(options);
    if (typeof body.enabled === 'boolean') rule.enabled = body.enabled;
    if (Number.isFinite(Number(body.threshold))) rule.threshold = clamp(body.threshold, 0, 1e15);
    rule.updated_at = iso(Date.now());
    saveState(state);
    result = deepCopy(rule);
  } else {
    throw new Error(`Unsupported browser-demo request: ${method} ${pathname}`);
  }

  return result;
}
