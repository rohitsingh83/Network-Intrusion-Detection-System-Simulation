import { api, escapeHTML, fmtNumber, fmtDate, shortTime, IS_STATIC_DEMO, resetStaticDemo } from './services/api.js';

const state = {
  view: 'overview',
  stats: null,
  traffic: null,
  system: null,
  alerts: [],
  flows: [],
  rules: [],
  filters: { severity: '', protocol: '', status: '', hours: 24, alert_type: '' },
  flowSearch: '',
  selectedAlert: null,
  busy: false,
};

const $ = (selector, scope = document) => scope.querySelector(selector);

function icon(name, size = 18) {
  const paths = {
    grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/>',
    pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    sliders: '<path d="M4 21v-7m0-4V3m8 18v-9m0-4V3m8 18v-5m0-4V3M2 14h4m4-6h4m4 8h4"/>',
    flask: '<path d="M9 3h6m-5 0v7l-5.6 8.4A2.4 2.4 0 0 0 6.4 22h11.2a2.4 2.4 0 0 0 2-3.6L14 10V3"/><path d="M8 16h8"/>',
    arrow: '<path d="M7 17 17 7M7 7h10v10"/>',
    shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    chevron: '<path d="m9 18 6-6-6-6"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.7 9A7 7 0 0 1 18 6.7L20 12M4 12l2 5.3A7 7 0 0 0 18.3 15"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 8.7-8.7 2 2-2 2 2 2-3 3-2-2-2 2"/>',
    close: '<path d="m18 6-12 12M6 6l12 12"/>',
    note: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h6"/>',
    play: '<path d="m8 5 12 7-12 7z"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  };
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.grid}</svg>`;
}

function toast(message, kind = 'success') {
  const host = $('#toast-host');
  if (!host) return;
  const element = document.createElement('div');
  element.className = `toast toast-${kind}`;
  element.textContent = message;
  host.appendChild(element);
  setTimeout(() => element.remove(), 3600);
}

async function loadData() {
  try {
    const [stats, traffic, system, alerts] = await Promise.all([
      api('/api/dashboard/stats'),
      api(`/api/dashboard/traffic?hours=${state.filters.hours}&bucket_minutes=10`),
      api('/api/system'),
      api('/api/alerts?limit=200'),
    ]);
    state.stats = stats;
    state.traffic = traffic;
    state.system = system;
    state.alerts = alerts.items || [];
    if (state.view === 'flows') {
      const flows = await api(`/api/flows?limit=200&search=${encodeURIComponent(state.flowSearch)}`);
      state.flows = flows.items || [];
    }
    if (state.view === 'rules') {
      const rules = await api('/api/rules');
      state.rules = rules.items || [];
    }
    render();
  } catch (error) {
    render();
    toast(error.message || 'Could not connect to the IDS API.', 'error');
  }
}

const titles = {
  overview: ['Detection overview', 'Network behavior, alert pressure, and analyst-ready context.'],
  alerts: ['Alert queue', 'Triage synthetic detections and document disposition.'],
  flows: ['Flow explorer', 'Search flow metadata and compare risk signals.'],
  rules: ['Detection rules', 'Tune transparent thresholds for this simulation.'],
  lab: ['Replay lab', 'Create safe synthetic flow records—never network packets.'],
};

function shell(content) {
  const title = titles[state.view] || titles.overview;
  const activeAlerts = state.stats?.open_alerts || 0;
  return `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand-row">
          <div class="brand-symbol"><span></span><span></span><span></span></div>
          <div><div class="brand-name">Sentinel<span>Flow</span></div><div class="brand-caption">NETWORK DETECTION LAB</div></div>
          <button class="sidebar-close icon-button" data-action="close-menu" aria-label="Close menu">${icon('close')}</button>
        </div>
        <div class="workspace-chip"><span class="workspace-dot"></span><div><b>LAB / HYBRID IDS</b><small>${IS_STATIC_DEMO ? 'Saved in this browser' : 'Local simulation'}</small></div><span class="mono tiny">01</span></div>
        <div class="nav-label">WORKSPACE</div>
        <nav class="main-nav" aria-label="Primary navigation">
          ${navItem('overview', 'grid', 'Overview')}
          ${navItem('alerts', 'bell', 'Alert queue', activeAlerts ? `<span class="nav-count">${fmtNumber(activeAlerts)}</span>` : '')}
          ${navItem('flows', 'pulse', 'Flow explorer')}
          ${navItem('rules', 'sliders', 'Detection rules')}
          ${navItem('lab', 'flask', 'Replay lab')}
        </nav>
        <div class="sidebar-spacer"></div>
        <div class="safety-card"><div class="safety-icon">${icon('shield', 16)}</div><div><strong>Synthetic-only mode</strong><p>RFC 5737 documentation IPs. No packet capture or transmission.</p></div></div>
        <div class="sidebar-footer"><span class="status-pip"></span> ${IS_STATIC_DEMO ? 'Browser-local' : `API ${state.system ? 'connected' : 'connecting'}`} <span class="footer-version">v1.0</span></div>
      </aside>
      <div class="main-column">
        <header class="topbar">
          <button class="mobile-menu icon-button" data-action="open-menu" aria-label="Open menu">${icon('menu')}</button>
          <div class="breadcrumb"><span>SentinelFlow</span>${icon('chevron', 13)}<b>${escapeHTML(title[0])}</b></div>
          <div class="top-actions">
            <div class="live-indicator"><span></span> ${IS_STATIC_DEMO ? 'BROWSER-ONLY DEMO' : 'LIVE SIMULATION'}</div>
            ${IS_STATIC_DEMO ? '' : `<button class="quiet-button" data-action="set-key" title="Configure optional API key">${icon('key', 15)}<span>API key</span></button>`}
            <button class="primary-button" data-action="replay" ${state.busy ? 'disabled' : ''}>${icon('play', 15)}<span>${state.busy ? 'Replaying…' : 'Replay 12 flows'}</span></button>
          </div>
        </header>
        <main class="content-area">
          <div class="page-heading"><div><div class="eyebrow">SOC ANALYTICS <span>·</span> SYNTHETIC FLOW TELEMETRY</div><h1>${escapeHTML(title[0])}</h1><p>${escapeHTML(title[1])}</p></div><div class="page-heading-meta"><span class="refresh-dot"></span><span>Auto refresh <b>5s</b></span><span class="divider"></span><button class="icon-button refresh-button" data-action="refresh" aria-label="Refresh dashboard">${icon('refresh', 17)}</button></div></div>
          ${content}
          <footer class="page-footer"><span>${IS_STATIC_DEMO ? 'SentinelFlow · GitHub Pages browser demo' : 'SentinelFlow · Defensive cybersecurity education'}</span><span>${IS_STATIC_DEMO ? 'Saved only in this browser · No server or packets involved' : 'All alerts are signals for human review · No packets transmitted'}</span></footer>
        </main>
      </div>
      <div id="modal-root"></div>
      <div id="toast-host" aria-live="polite"></div>
    </div>`;
}

function navItem(view, iconName, label, suffix = '') {
  return `<button class="nav-item ${state.view === view ? 'active' : ''}" data-view="${view}">${icon(iconName, 17)}<span>${label}</span>${suffix}</button>`;
}

function metricCard(label, value, foot, iconName, tone = 'cyan') {
  return `<article class="metric-card tone-${tone}"><div class="metric-top"><span>${label}</span><span class="metric-icon">${icon(iconName, 17)}</span></div><div class="metric-value">${value}</div><div class="metric-foot">${foot}</div><div class="metric-accent"></div></article>`;
}

function panel(title, subtitle, body, extra = '') {
  return `<section class="panel ${extra}"><div class="panel-head"><div><h2>${title}</h2>${subtitle ? `<p>${subtitle}</p>` : ''}</div></div>${body}</section>`;
}

function svgEmpty(label = 'Waiting for flow telemetry') {
  return `<div class="chart-empty"><div class="empty-pulse">${icon('pulse', 22)}</div><strong>${escapeHTML(label)}</strong><span>Use Replay or start the local simulator.</span></div>`;
}

function lineChart(data, series) {
  if (!data?.length) return svgEmpty();
  const width = 720, height = 238, left = 38, right = 12, top = 16, bottom = 36;
  const plotW = width - left - right, plotH = height - top - bottom;
  const values = data.flatMap((point) => series.map((item) => Number(point[item.key] || 0)));
  const max = Math.max(1, ...values) * 1.12;
  const x = (index) => left + (data.length <= 1 ? plotW / 2 : (plotW * index / (data.length - 1)));
  const y = (value) => top + plotH - (Number(value || 0) / max) * plotH;
  const grid = [0, 0.33, 0.66, 1].map((fraction) => {
    const yy = top + plotH * fraction;
    return `<line x1="${left}" y1="${yy}" x2="${width - right}" y2="${yy}" class="chart-gridline"/><text x="${left - 8}" y="${yy + 4}" text-anchor="end" class="chart-axis">${fmtNumber(max * (1 - fraction), 0)}</text>`;
  }).join('');
  const lines = series.map((item) => {
    const points = data.map((point, index) => `${x(index)},${y(point[item.key])}`).join(' ');
    const circles = data.map((point, index) => `<circle cx="${x(index)}" cy="${y(point[item.key])}" r="2.8" fill="${item.color}" class="chart-point"><title>${escapeHTML(item.label)}: ${fmtNumber(point[item.key], 1)}</title></circle>`).join('');
    return `<polyline points="${points}" fill="none" stroke="${item.color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>${circles}`;
  }).join('');
  const labels = data.map((point, index) => index % Math.max(1, Math.ceil(data.length / 6)) === 0 || index === data.length - 1
    ? `<text x="${x(index)}" y="${height - 9}" text-anchor="middle" class="chart-axis">${escapeHTML(shortTime(point.timestamp))}</text>` : '').join('');
  const legend = series.map((item) => `<span class="legend-item"><i style="background:${item.color}"></i>${escapeHTML(item.label)}</span>`).join('');
  return `<div class="chart-legend">${legend}</div><svg class="chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Traffic over time">${grid}${lines}${labels}</svg>`;
}

function donutChart(rows) {
  const filtered = (rows || []).filter((row) => row.value > 0);
  if (!filtered.length) return svgEmpty('No protocol distribution yet');
  const palette = ['#35d7c3', '#7689ff', '#ffb65e', '#ec6e91'];
  const total = filtered.reduce((sum, row) => sum + row.value, 0);
  const radius = 47, circumference = 2 * Math.PI * radius;
  let offset = 0;
  const arcs = filtered.map((row, index) => {
    const amount = circumference * row.value / total;
    const arc = `<circle cx="70" cy="70" r="${radius}" fill="none" stroke="${palette[index % palette.length]}" stroke-width="13" stroke-dasharray="${amount} ${circumference - amount}" stroke-dashoffset="${-offset}" transform="rotate(-90 70 70)"/>`;
    offset += amount;
    return arc;
  }).join('');
  const legend = filtered.map((row, index) => `<div class="donut-legend-row"><span><i style="background:${palette[index % palette.length]}"></i>${escapeHTML(row.name)}</span><b>${fmtNumber(row.value)}</b></div>`).join('');
  return `<div class="donut-wrap"><svg viewBox="0 0 140 140" class="donut-svg">${arcs}<text x="70" y="67" class="donut-total">${fmtNumber(total)}</text><text x="70" y="84" class="donut-label">FLOWS</text></svg><div class="donut-legend">${legend}</div></div>`;
}

function barList(rows, tone = 'cyan', empty = 'No records in this time range') {
  const list = (rows || []).filter((row) => row.value > 0);
  if (!list.length) return svgEmpty(empty);
  const max = Math.max(1, ...list.map((row) => row.value));
  return `<div class="bar-list ${tone}">${list.slice(0, 7).map((row) => `<div class="bar-row"><div class="bar-label"><span>${escapeHTML(row.name)}</span><b>${fmtNumber(row.value)}</b></div><div class="bar-track"><i style="width:${Math.max(2, row.value / max * 100)}%"></i></div></div>`).join('')}</div>`;
}

function severityBars(rows) {
  const colors = { INFO: '#61748d', LOW: '#5db8a8', MEDIUM: '#e7bb5d', HIGH: '#ef8b51', CRITICAL: '#ef6479' };
  const max = Math.max(1, ...(rows || []).map((row) => row.value));
  return `<div class="severity-stack">${(rows || []).map((row) => `<div class="severity-row"><div class="severity-label"><span><i style="background:${colors[row.name] || '#789'}"></i>${row.name}</span><b>${fmtNumber(row.value)}</b></div><div class="bar-track"><i style="width:${row.value ? Math.max(3, row.value / max * 100) : 0}%;background:${colors[row.name] || '#789'}"></i></div></div>`).join('')}</div>`;
}

function riskDistribution(rows) {
  const colors = ['#53b7a7', '#79c69e', '#e4bd61', '#e98c58', '#ef6378'];
  const max = Math.max(1, ...(rows || []).map((row) => row.value));
  return `<div class="risk-dist">${(rows || []).map((row, index) => `<div class="risk-bin"><span>${escapeHTML(row.name)}</span><div class="risk-bin-track"><i style="height:${Math.max(4, row.value / max * 92)}%;background:${colors[index]}"></i></div><b>${fmtNumber(row.value)}</b></div>`).join('')}</div>`;
}

function alertTable(alerts, limit = 8) {
  if (!alerts?.length) return `<div class="empty-row">${svgEmpty('No alerts match these filters')}</div>`;
  return `<div class="table-scroll"><table class="data-table"><thead><tr><th>ALERT / OBSERVED</th><th>SOURCE → DESTINATION</th><th>TYPE</th><th>SEVERITY</th><th>RISK</th><th>STATUS</th></tr></thead><tbody>${alerts.slice(0, limit).map((alert) => `
    <tr class="clickable-row" data-alert-id="${escapeHTML(alert.alert_id)}">
      <td><div class="alert-id-cell"><b>${escapeHTML(alert.alert_id)}</b><small>${fmtDate(alert.last_seen || alert.created_at)}</small></div></td>
      <td><div class="ip-flow"><span>${escapeHTML(alert.source_ip)}</span><i>→</i><span>${escapeHTML(alert.destination_ip)}</span><small>${escapeHTML(alert.protocol)} · ${escapeHTML(String(alert.destination_port))}</small></div></td>
      <td><span class="alert-type-cell">${escapeHTML(alert.alert_type)}</span>${alert.occurrence_count > 1 ? `<small class="occurrence">${fmtNumber(alert.occurrence_count)} correlated</small>` : ''}</td>
      <td><span class="severity-pill sev-${escapeHTML(alert.severity.toLowerCase())}"><i></i>${escapeHTML(alert.severity)}</span></td>
      <td><div class="risk-cell"><b>${fmtNumber(alert.risk_score)}</b><span>/100</span><div class="risk-mini"><i style="width:${Math.min(100, Number(alert.risk_score || 0))}%"></i></div></div></td>
      <td><span class="status-pill status-${escapeHTML(alert.status.toLowerCase())}">${escapeHTML(alert.status.replace('_', ' '))}</span></td>
    </tr>`).join('')}</tbody></table></div>`;
}

function filterBar() {
  const alertTypes = [...new Set(state.alerts.map((alert) => alert.alert_type))].sort();
  const selected = (key, value) => state.filters[key] === value ? 'selected' : '';
  return `<div class="filter-bar">
    <label><span>Severity</span><select data-filter="severity"><option value="">All severities</option>${['INFO','LOW','MEDIUM','HIGH','CRITICAL'].map((value) => `<option ${selected('severity', value)}>${value}</option>`).join('')}</select></label>
    <label><span>Protocol</span><select data-filter="protocol"><option value="">All protocols</option>${['TCP','UDP','ICMP'].map((value) => `<option ${selected('protocol', value)}>${value}</option>`).join('')}</select></label>
    <label><span>Alert type</span><select data-filter="alert_type"><option value="">All alert types</option>${alertTypes.map((value) => `<option value="${escapeHTML(value)}" ${selected('alert_type', value)}>${escapeHTML(value)}</option>`).join('')}</select></label>
    <label><span>Status</span><select data-filter="status"><option value="">All statuses</option>${['NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE'].map((value) => `<option ${selected('status', value)}>${value}</option>`).join('')}</select></label>
    <label><span>Window</span><select data-filter="hours"><option value="1" ${selected('hours', 1)}>Last hour</option><option value="24" ${selected('hours', 24)}>24 hours</option><option value="168" ${selected('hours', 168)}>7 days</option></select></label>
    <button class="filter-reset" data-action="reset-filters">Reset</button>
  </div>`;
}

function overviewView() {
  const s = state.stats || {};
  const t = state.traffic || {};
  const cards = [
    metricCard('TOTAL FLOWS', fmtNumber(s.total_flows), `${fmtNumber(s.normal_flows)} classified normal`, 'pulse', 'cyan'),
    metricCard('SUSPICIOUS FLOWS', fmtNumber(s.suspicious_flows), `${s.total_flows ? Math.round(s.suspicious_flows / s.total_flows * 100) : 0}% of observed records`, 'arrow', 'amber'),
    metricCard('OPEN ALERTS', fmtNumber(s.open_alerts), `${fmtNumber(s.total_alerts)} total detections`, 'bell', 'violet'),
    metricCard('CRITICAL OPEN', fmtNumber(s.critical_alerts), 'Requires analyst review', 'shield', 'rose'),
    metricCard('AVG RISK SCORE', `${fmtNumber(s.average_risk_score, 1)}<small>/100</small>`, 'Flow-weighted composite', 'pulse', 'blue'),
  ].join('');
  return `<section class="metric-grid">${cards}</section>
    <section class="dashboard-grid first-row">
      ${panel('Traffic over time', 'Synthetic normal vs. suspicious records · 10-minute buckets', `<div class="chart-area">${lineChart(t.timeline, [{ key: 'normal', label: 'Normal flows', color: '#35d7c3' }, { key: 'suspicious', label: 'Suspicious flows', color: '#f18b64' }])}</div>`, 'panel-traffic')}
      ${panel('Alert severity', 'Open + closed detections in selected window', severityBars(t.severity_distribution), 'panel-severity')}
    </section>
    <section class="dashboard-grid second-row">
      ${panel('Protocol mix', 'Protocol distribution across stored flow records', donutChart(t.protocol_distribution), 'panel-protocol')}
      ${panel('Destination ports', 'Most represented service ports', barList(t.port_distribution, 'violet'), 'panel-ports')}
      ${panel('Risk distribution', 'Flow scores grouped by triage band', riskDistribution(t.risk_distribution), 'panel-risk')}
    </section>
    <section class="dashboard-grid telemetry-row">
      ${panel('Packet rate', 'Mean packets / second per interval', `<div class="mini-chart">${lineChart(t.timeline, [{ key: 'packets_per_second', label: 'Packets/s', color: '#70a6ff' }])}</div>`, 'panel-mini')}
      ${panel('Byte rate', 'Mean bytes / second per interval', `<div class="mini-chart">${lineChart(t.timeline, [{ key: 'bytes_per_second', label: 'Bytes/s', color: '#b291ff' }])}</div>`, 'panel-mini')}
      ${panel('Connections / minute', 'Connection volume represented by flow windows', `<div class="mini-chart">${lineChart(t.timeline, [{ key: 'connections_per_minute', label: 'Connections', color: '#f0b85d' }])}</div>`, 'panel-mini')}
      ${panel('Failed connections', 'Reported failed attempts per interval', `<div class="mini-chart">${lineChart(t.timeline, [{ key: 'failed_connections', label: 'Failures', color: '#ed7488' }])}</div>`, 'panel-mini')}
      ${panel('Alert timeline', 'Grouped alert creation by interval', `<div class="mini-chart">${lineChart(t.timeline, [{ key: 'alerts', label: 'Alerts', color: '#ef7487' }])}</div>`, 'panel-mini')}
      ${panel('Risk timeline', 'Mean final risk score by interval', `<div class="mini-chart">${lineChart(t.timeline, [{ key: 'average_risk_score', label: 'Average risk', color: '#35d7c3' }])}</div>`, 'panel-mini')}
    </section>
    <section class="dashboard-grid lower-row">
      ${panel('Top alert types', 'Recurring detection patterns', barList(t.top_alert_types, 'amber', 'No alerts in this time range'), 'panel-types')}
      ${panel('Top sources by alerts', 'Documentation-range source addresses', barList(t.top_source_ips, 'cyan', 'No alert sources in this window'), 'panel-sources')}
    </section>
    <section class="panel table-panel"><div class="panel-head"><div><h2>Recent detections</h2><p>Click a row to open evidence and investigation actions.</p></div><button class="text-button" data-view="alerts">View alert queue ${icon('arrow', 14)}</button></div>${alertTable(state.alerts, 7)}</section>
    <div class="disclaimer-strip">${icon('shield', 16)} <span>Signals are statistical indicators requiring validation. This simulation stores flow metadata only and never generates packets.</span></div>`;
}

function alertsView() {
  const filtered = state.alerts.filter((alert) => {
    return (!state.filters.severity || alert.severity === state.filters.severity)
      && (!state.filters.protocol || alert.protocol === state.filters.protocol)
      && (!state.filters.status || alert.status === state.filters.status)
      && (!state.filters.alert_type || alert.alert_type === state.filters.alert_type)
      && (state.filters.hours == null || (Date.now() - new Date(alert.created_at).getTime()) <= state.filters.hours * 3600000);
  });
  return `<section class="panel queue-panel"><div class="panel-head"><div><h2>Detection queue <span class="count-chip">${filtered.length}</span></h2><p>Evidence-rich alerts grouped by source, detection type, and 60-second window.</p></div><div class="queue-summary"><span class="severity-pill sev-critical"><i></i>${state.stats?.critical_alerts || 0} critical open</span></div></div>${filterBar()}${alertTable(filtered, 200)}</section>
    <div class="queue-footnote"><span class="small-pip"></span> Correlated occurrences are grouped into one analyst item; every contributing flow remains available in the incident detail.</div>`;
}

function flowsView() {
  return `<section class="panel queue-panel"><div class="panel-head"><div><h2>Flow records <span class="count-chip">${state.flows.length}</span></h2><p>Validated metadata and engineered features; payload data is never collected.</p></div></div>
    <div class="flow-search"><label>${icon('search', 16)}<input id="flow-search" type="search" value="${escapeHTML(state.flowSearch)}" placeholder="Search flow ID, source, destination, scenario…" /></label><button class="secondary-button" data-action="search-flows">Search</button></div>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>FLOW / TIME</th><th>SOURCE → DESTINATION</th><th>PROTOCOL / PORT</th><th>SCENARIO</th><th>CLASSIFICATION</th><th>RISK</th><th>ANOMALY</th></tr></thead><tbody>${state.flows.length ? state.flows.map((flow) => `<tr><td><div class="alert-id-cell"><b>${escapeHTML(flow.flow_id)}</b><small>${fmtDate(flow.timestamp)}</small></div></td><td><div class="ip-flow"><span>${escapeHTML(flow.source_ip)}</span><i>→</i><span>${escapeHTML(flow.destination_ip)}</span></div></td><td>${escapeHTML(flow.protocol)} <span class="muted">· ${fmtNumber(flow.destination_port)}</span></td><td><span class="scenario-tag">${escapeHTML(flow.scenario_type || '—')}</span></td><td><span class="class-pill class-${String(flow.classification).toLowerCase().replaceAll(' ', '-')}">${escapeHTML(flow.classification)}</span></td><td><span class="risk-number">${fmtNumber(flow.risk_score)}</span><span class="muted"> /100</span></td><td>${fmtNumber(flow.anomaly_score)}</td></tr>`).join('') : `<tr><td colspan="7" class="empty-cell">No flow records found. Use the Replay lab to add safe synthetic telemetry.</td></tr>`}</tbody></table></div></section>
    <div class="feature-note"><b>Feature snapshot</b><span>Packet rate, byte rate, failure ratio, SYN ratio, destination-port diversity, and connection rate are derived from record metadata.</span></div>`;
}

function rulesView() {
  const cards = state.rules.map((rule) => `<article class="rule-card ${rule.enabled ? '' : 'disabled'}"><div class="rule-card-top"><div class="rule-id">${escapeHTML(rule.rule_id)}</div><label class="toggle"><input type="checkbox" data-rule-toggle="${escapeHTML(rule.rule_id)}" ${rule.enabled ? 'checked' : ''}><span></span><em>${rule.enabled ? 'Enabled' : 'Paused'}</em></label></div><h3>${escapeHTML(rule.rule_name)}</h3><p>${escapeHTML(rule.description)}</p><div class="rule-config"><label>Threshold <input type="number" min="0" step="1" data-rule-threshold="${escapeHTML(rule.rule_id)}" value="${escapeHTML(rule.threshold)}"></label><span class="severity-pill sev-${escapeHTML(rule.severity.toLowerCase())}"><i></i>${escapeHTML(rule.severity)}</span></div><div class="rule-card-foot"><span>Rule matches are evidence, not attribution.</span><button class="text-button" data-action="save-rule" data-rule-id="${escapeHTML(rule.rule_id)}">Save ${icon('arrow', 13)}</button></div></article>`).join('');
  return `<section class="rules-intro"><div class="intro-icon">${icon('sliders', 22)}</div><div><b>Transparent, adjustable signatures</b><p>Thresholds live in SQLite and are applied to new records. Changes are local to this lab; tune with false-positive and false-negative trade-offs in mind.</p></div></section><section class="rules-grid">${cards || '<p>No rules found.</p>'}</section><div class="disclaimer-strip">${icon('shield', 16)} <span>Do not treat a rule match as proof of an intrusion. Production detections require asset context, authorized telemetry, and change control.</span></div>`;
}

const scenarios = [
  ['NORMAL_WEB', 'Normal HTTPS browsing', 'Expected web service traffic', 'NORMAL'],
  ['NORMAL_DNS', 'Normal DNS query', 'Low-volume UDP / 53 pattern', 'NORMAL'],
  ['REPEATED_FAILED_CONNECTIONS', 'Repeated failures', 'High failed-connection ratio', 'SUSPICIOUS'],
  ['HIGH_CONNECTION_RATE', 'High connection rate', 'Dense connection metadata', 'SUSPICIOUS'],
  ['MULTI_PORT_PROBING_PATTERN', 'Multi-port pattern', 'High destination-port diversity', 'SUSPICIOUS'],
  ['SYN_HEAVY_PATTERN', 'SYN-heavy pattern', 'Elevated SYN share in metadata', 'SUSPICIOUS'],
  ['HIGH_TRAFFIC_VOLUME', 'High volume record', 'Large bytes-per-flow record', 'SUSPICIOUS'],
  ['UNUSUAL_PORT_ACTIVITY', 'Unusual service port', 'Transport / service mismatch', 'SUSPICIOUS'],
];

function labView() {
  return `<section class="lab-banner"><div class="lab-sigil">${icon('flask', 25)}</div><div><div class="eyebrow">${IS_STATIC_DEMO ? 'BROWSER-LOCAL SIMULATION' : 'ISOLATED DATA SIMULATION'}</div><h2>Test detection without a network lab.</h2><p>${IS_STATIC_DEMO ? 'This GitHub Pages version evaluates synthetic flow records entirely in your browser. Changes stay in this browser profile; there is no backend connection.' : 'Each action inserts synthetic JSON flow records into the local IDS API. The simulator cannot emit packets and only POSTs to a loopback API.'}</p></div><div class="lab-badge"><span></span> SAFE MODE ACTIVE</div></section>
    <section class="lab-toolbar"><div><b>Scenario library</b><p>Pick a deterministic behavior class to exercise feature extraction and alert triage.</p></div><div class="lab-toolbar-actions"><button class="secondary-button" data-action="replay-normal">${icon('play', 14)} Normal sample</button><button class="primary-button" data-action="replay">${icon('play', 14)} Mixed replay</button></div></section>
    <section class="scenario-grid">${scenarios.map(([key, title, desc, label]) => `<article class="scenario-card"><div class="scenario-card-top"><span class="scenario-label ${label.toLowerCase()}">${label}</span><span class="mono tiny">FLOW PATTERN</span></div><h3>${title}</h3><p>${desc}</p><button data-action="scenario" data-scenario="${key}">Generate record ${icon('arrow', 13)}</button></article>`).join('')}</section>
    ${IS_STATIC_DEMO ? `<section class="panel replay-commands"><div class="panel-head"><div><h2>Browser-only storage</h2><p>Flows, alerts, analyst notes, rule tuning, and incident status are saved in this browser using localStorage. They are not shared with other visitors or devices.</p></div><button class="secondary-button" data-action="reset-static-demo">Reset demo data</button></div><div class="command-foot"><span>Fixed educational baseline · optional ML is off on GitHub Pages</span><span>No API calls · no packets</span></div></section>` : `<section class="panel replay-commands"><div class="panel-head"><div><h2>Run the continuous simulator</h2><p>Starts a local client that posts flow JSON to the app API. Use Ctrl+C to stop.</p></div></div><div class="command-block"><code>python -m simulator.traffic_simulator --mode mixed --speed fast --count 60</code><button class="icon-button" data-action="copy-command" aria-label="Copy command">${icon('note', 15)}</button></div><div class="command-foot"><span>Loopback destination by default</span><span>Slow: 1.5s · Fast: 0.2s</span></div></section>`}
    <div class="disclaimer-strip">${icon('shield', 16)} <span>Patterns are synthetic data records and statistics only. No scanning, probing, flooding, login attempts, or real network attacks occur.</span></div>`;
}

function render() {
  let content = '';
  if (state.view === 'overview') content = overviewView();
  else if (state.view === 'alerts') content = alertsView();
  else if (state.view === 'flows') content = flowsView();
  else if (state.view === 'rules') content = rulesView();
  else content = labView();
  const oldModal = $('#modal-root')?.innerHTML || '';
  document.querySelector('#app').innerHTML = shell(content);
  if (state.selectedAlert) $('#modal-root').innerHTML = oldModal;
}

async function openAlert(alertId) {
  try {
    const alert = await api(`/api/alerts/${encodeURIComponent(alertId)}`);
    state.selectedAlert = alert;
    renderModal(alert);
  } catch (error) { toast(error.message, 'error'); }
}

function renderModal(alert) {
  const flow = alert.flow || {};
  const features = flow.features || {};
  const matches = alert.matched_rules || [];
  const modal = `<div class="modal-backdrop" data-action="backdrop-close"><section class="investigation-modal" role="dialog" aria-modal="true" aria-labelledby="incident-title" data-modal-content>
    <header class="modal-header"><div><div class="eyebrow">ANALYST INVESTIGATION <span>·</span> ${escapeHTML(alert.alert_id)}</div><h2 id="incident-title">${escapeHTML(alert.alert_type)}</h2><p>${escapeHTML(alert.description)}</p></div><button class="icon-button" data-action="close-modal" aria-label="Close">${icon('close')}</button></header>
    <div class="modal-summary"><div class="summary-risk"><span>FINAL RISK</span><b>${fmtNumber(alert.risk_score)}<small>/100</small></b><div class="risk-track"><i style="width:${Math.min(100, Number(alert.risk_score))}%"></i></div></div><div><span>SEVERITY</span><b><span class="severity-pill sev-${escapeHTML(alert.severity.toLowerCase())}"><i></i>${escapeHTML(alert.severity)}</span></b></div><div><span>STATUS</span><b><span class="status-pill status-${escapeHTML(alert.status.toLowerCase())}">${escapeHTML(alert.status.replace('_', ' '))}</span></b></div><div><span>FIRST SEEN</span><b>${fmtDate(alert.created_at)}</b></div><div><span>LAST SEEN</span><b>${fmtDate(alert.last_seen)}</b></div><div><span>OCCURRENCES</span><b>${fmtNumber(alert.occurrence_count)}</b></div></div>
    <div class="modal-body-grid"><div class="modal-main-col">
      <section class="detail-card"><div class="detail-heading">${icon('pulse', 15)} FLOW EVIDENCE</div><div class="endpoint-row"><div><small>SOURCE</small><b>${escapeHTML(alert.source_ip)}<span>:${fmtNumber(alert.source_port)}</span></b></div><i>→</i><div><small>DESTINATION</small><b>${escapeHTML(alert.destination_ip)}<span>:${fmtNumber(alert.destination_port)}</span></b></div><span class="protocol-chip">${escapeHTML(alert.protocol)}</span></div><div class="feature-grid"><div><small>Packets</small><b>${fmtNumber(flow.packet_count)}</b></div><div><small>Bytes</small><b>${fmtNumber(flow.byte_count)}</b></div><div><small>Duration</small><b>${fmtNumber(flow.duration_seconds, 2)}s</b></div><div><small>Connections/s</small><b>${fmtNumber(features.connection_rate, 2)}</b></div><div><small>Failed ratio</small><b>${fmtNumber(features.failure_ratio, 2)}</b></div><div><small>Unique ports</small><b>${fmtNumber(features.unique_destination_ports)}</b></div><div><small>SYN ratio</small><b>${fmtNumber(features.syn_ratio, 2)}</b></div><div><small>Avg packet</small><b>${fmtNumber(features.average_packet_size, 1)} B</b></div></div><div class="feature-scores"><span>ANOMALY <b>${fmtNumber(alert.anomaly_score)}/100</b></span><span>ML <b>${alert.ml_probability == null ? 'Disabled' : `${fmtNumber(alert.ml_probability * 100, 1)}%`}</b></span><span>CLASS <b>${escapeHTML(flow.classification || '—')}</b></span></div></section>
      <section class="detail-card"><div class="detail-heading">${icon('shield', 15)} DETECTION EVIDENCE</div><div class="rule-evidence-list">${matches.length ? matches.map((rule) => `<div class="evidence-row"><span class="evidence-check">${icon('check', 13)}</span><div><b>${escapeHTML(rule.name)}</b><p>${escapeHTML(rule.evidence || rule.description)}</p><small>${escapeHTML(rule.rule_id)} · ${escapeHTML(rule.severity)}</small></div></div>`).join('') : `<div class="evidence-row"><span class="evidence-check">${icon('pulse', 13)}</span><div><b>Statistical anomaly</b><p>Score ${fmtNumber(alert.anomaly_score)} / 100 against the normal-traffic baseline.</p><small>ANOMALY-001 · Review baseline context</small></div></div>`}</div></section>
      <section class="detail-card"><div class="detail-heading">${icon('pulse', 15)} BASELINE DEVIATION CONTEXT</div><div class="anomaly-evidence-list">${(features.anomaly_evidence || []).slice(0, 3).map((item) => `<div class="anomaly-evidence-row"><div><b>${escapeHTML(item.feature.replaceAll('_', ' '))}</b><small>Observed ${fmtNumber(item.value, 2)} · baseline mean ${fmtNumber(item.baseline_mean, 2)} · +${fmtNumber(item.positive_z_score, 2)}σ</small></div><span>${fmtNumber(item.component_score)}/100</span></div>`).join('') || '<div class="muted-note">No baseline feature detail stored for this alert.</div>'}</div><div class="muted-note anomaly-footnote">Statistical deviation supports triage; it is not an attack attribution.</div></section>\n      <section class="detail-card"><div class="detail-heading">${icon('note', 15)} INVESTIGATION NOTES</div><div class="notes-list">${(alert.notes || []).length ? alert.notes.map((note) => `<div class="note-item"><div><b>${escapeHTML(note.author)}</b><small>${fmtDate(note.created_at)}</small></div><p>${escapeHTML(note.note)}</p></div>`).join('') : '<div class="muted-note">No analyst notes yet. Record the evidence reviewed and your reasoning.</div>'}</div><form id="note-form" class="note-form"><textarea name="note" rows="3" maxlength="2000" placeholder="Add an evidence-based analyst note…" required></textarea><div><span>${IS_STATIC_DEMO ? 'Notes stay in this browser only.' : 'Notes are stored in the local incident database.'}</span><button class="secondary-button" type="submit">Save note ${icon('arrow', 13)}</button></div></form></section>
    </div><aside class="modal-side-col"><section class="detail-card action-card"><div class="detail-heading">${icon('sliders', 15)} TRIAGE ACTION</div><label class="field-label">Incident status<select id="incident-status">${['NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE'].map((value) => `<option value="${value}" ${alert.status === value ? 'selected' : ''}>${value.replace('_', ' ')}</option>`).join('')}</select></label><label class="field-label">Resolution summary <textarea id="resolution-notes" rows="3" maxlength="4000" placeholder="Required context for a resolved / false-positive disposition">${escapeHTML(alert.resolution_notes || '')}</textarea></label><button class="primary-button full-width" data-action="update-status" data-alert-id="${escapeHTML(alert.alert_id)}">Update incident status ${icon('arrow', 14)}</button><div class="workflow-hint">NEW → INVESTIGATING → RESOLVED<br/>False-positive is a documented disposition.</div></section>
      <section class="detail-card"><div class="detail-heading">${icon('search', 15)} RECOMMENDED REVIEW</div><ol class="recommendations">${(alert.recommended_steps || []).map((step) => `<li>${escapeHTML(step)}</li>`).join('')}</ol></section>
      <section class="detail-card"><div class="detail-heading">${icon('clock', 15)} INCIDENT TIMELINE</div><div class="timeline-list">${(alert.timeline || []).length ? alert.timeline.map((event) => `<div class="timeline-item"><i></i><div><b>${escapeHTML(event.to_status.replace('_', ' '))}</b><small>${fmtDate(event.created_at)} · ${escapeHTML(event.actor)}</small>${event.note ? `<p>${escapeHTML(event.note)}</p>` : ''}</div></div>`).join('') : '<div class="muted-note">No status changes recorded yet.</div>'}</div></section>
    </aside></div>
  </section></div>`;
  $('#modal-root').innerHTML = modal;
}

async function runReplay(mode = 'mixed', count = 12) {
  if (state.busy) return;
  state.busy = true;
  render();
  try {
    const result = await api('/api/simulation/replay', { method: 'POST', body: JSON.stringify({ mode, count }) });
    state.busy = false;
    await loadData();
    toast(`${result.records_processed} synthetic flow records analyzed · ${result.alerts_created_or_correlated} alert(s) created or correlated.`);
  } catch (error) {
    state.busy = false;
    render();
    toast(error.message, 'error');
  }
}

async function generateScenario(scenario) {
  try {
    const result = await api(`/api/simulation/scenario/${encodeURIComponent(scenario)}?count=1`, { method: 'POST', body: '{}' });
    const item = result.items?.[0];
    await loadData();
    toast(`${scenario.replaceAll('_', ' ')} analyzed · risk ${item?.evaluation?.risk_score ?? '—'}/100.`);
  } catch (error) { toast(error.message, 'error'); }
}

function setApiKey() {
  const current = localStorage.getItem('sentinelflowApiKey') || '';
  const next = window.prompt('Optional IDS_API_KEY for protected write endpoints. Leave blank to clear.', current);
  if (next === null) return;
  if (next.trim()) localStorage.setItem('sentinelflowApiKey', next.trim());
  else localStorage.removeItem('sentinelflowApiKey');
  toast(next.trim() ? 'Local API key saved in this browser.' : 'Local API key cleared.');
}

async function updateRule(ruleId) {
  const toggle = $(`[data-rule-toggle="${CSS.escape(ruleId)}"]`);
  const input = $(`[data-rule-threshold="${CSS.escape(ruleId)}"]`);
  try {
    await api(`/api/rules/${encodeURIComponent(ruleId)}`, {
      method: 'PUT', body: JSON.stringify({ enabled: toggle?.checked, threshold: Number(input?.value) }),
    });
    await loadData();
    toast(`${ruleId} updated.`);
  } catch (error) { toast(error.message, 'error'); }
}

async function saveAlertStatus(alertId) {
  const status = $('#incident-status')?.value;
  const resolutionNotes = $('#resolution-notes')?.value.trim();
  try {
    const updated = await api(`/api/alerts/${encodeURIComponent(alertId)}/status`, {
      method: 'PUT', body: JSON.stringify({ status, resolution_notes: resolutionNotes || null, actor: 'analyst' }),
    });
    state.selectedAlert = updated;
    await loadData();
    renderModal(updated);
    toast(`Incident status updated to ${status.replace('_', ' ')}.`);
  } catch (error) { toast(error.message, 'error'); }
}

async function submitNote(event) {
  event.preventDefault();
  if (!state.selectedAlert) return;
  const form = event.target;
  const note = new FormData(form).get('note')?.toString().trim();
  if (!note) return;
  try {
    const updated = await api(`/api/alerts/${encodeURIComponent(state.selectedAlert.alert_id)}/notes`, {
      method: 'POST', body: JSON.stringify({ note, author: 'analyst' }),
    });
    state.selectedAlert = updated;
    renderModal(updated);
    toast('Investigation note saved.');
  } catch (error) { toast(error.message, 'error'); }
}

async function searchFlows() {
  state.flowSearch = $('#flow-search')?.value.trim() || '';
  try {
    const result = await api(`/api/flows?limit=200&search=${encodeURIComponent(state.flowSearch)}`);
    state.flows = result.items || [];
    render();
  } catch (error) { toast(error.message, 'error'); }
}

async function copyCommand() {
  const command = 'python -m simulator.traffic_simulator --mode mixed --speed fast --count 60';
  try { await navigator.clipboard.writeText(command); toast('Simulator command copied.'); }
  catch { toast(command, 'info'); }
}

$('#app').addEventListener('click', async (event) => {
  const nav = event.target.closest('[data-view]');
  if (nav) {
    state.view = nav.dataset.view;
    if (state.view === 'flows') {
      const result = await api(`/api/flows?limit=200&search=${encodeURIComponent(state.flowSearch)}`).catch(() => ({ items: [] }));
      state.flows = result.items || [];
    }
    if (state.view === 'rules') {
      const result = await api('/api/rules').catch(() => ({ items: [] }));
      state.rules = result.items || [];
    }
    render();
    return;
  }
  const alertRow = event.target.closest('[data-alert-id]');
  if (alertRow && !event.target.closest('[data-action="update-status"]')) {
    openAlert(alertRow.dataset.alertId);
    return;
  }
  const actionEl = event.target.closest('[data-action]');
  if (!actionEl) return;
  const action = actionEl.dataset.action;
  if (action === 'replay') runReplay('mixed', 12);
  if (action === 'replay-normal') runReplay('normal', 12);
  if (action === 'refresh') loadData();
  if (action === 'set-key') setApiKey();
  if (action === 'scenario') generateScenario(actionEl.dataset.scenario);
  if (action === 'save-rule') updateRule(actionEl.dataset.ruleId);
  if (action === 'reset-filters') {
    state.filters = { severity: '', protocol: '', status: '', hours: 24, alert_type: '' };
    render();
  }
  if (action === 'search-flows') searchFlows();
  if (action === 'update-status') saveAlertStatus(actionEl.dataset.alertId);
  if (action === 'close-modal') { state.selectedAlert = null; $('#modal-root').innerHTML = ''; }
  if (action === 'backdrop-close' && event.target === actionEl) { state.selectedAlert = null; $('#modal-root').innerHTML = ''; }
  if (action === 'copy-command') copyCommand();
  if (action === 'reset-static-demo' && IS_STATIC_DEMO) {
    if (window.confirm('Reset this browser-local demo? Notes, rule changes, and replayed records will be cleared.')) {
      resetStaticDemo();
      window.location.reload();
    }
    return;
  }
  if (action === 'open-menu') $('.sidebar')?.classList.add('sidebar-open');
  if (action === 'close-menu') $('.sidebar')?.classList.remove('sidebar-open');
});

$('#app').addEventListener('change', (event) => {
  const filter = event.target.closest('[data-filter]');
  if (filter) {
    const key = filter.dataset.filter;
    state.filters[key] = key === 'hours' ? Number(filter.value) : filter.value;
    loadData();
  }
  const toggle = event.target.closest('[data-rule-toggle]');
  if (toggle) updateRule(toggle.dataset.ruleToggle);
});

$('#app').addEventListener('submit', (event) => {
  if (event.target.id === 'note-form') submitNote(event);
});

$('#app').addEventListener('keydown', (event) => {
  if (event.target.id === 'flow-search' && event.key === 'Enter') searchFlows();
  if (event.key === 'Escape' && state.selectedAlert) { state.selectedAlert = null; $('#modal-root').innerHTML = ''; }
});

render();
loadData();
setInterval(loadData, 5000);
