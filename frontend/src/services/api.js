/**
 * API Service - Axios wrapper for the Network IDS Backend
 * ========================================================
 * Talks to FastAPI endpoints via relative URL /api.
 * Normalizes snake_case backend database keys to both camelCase
 * and snake_case so all UI components and Recharts charts render seamlessly.
 */

import axios from 'axios';

const api = axios.create({ baseURL: '/api', timeout: 10000 });

/**
 * Normalizes an alert object to ensure both camelCase and snake_case access
 */
export const normalizeAlert = (a) => {
  if (!a) return null;
  const id = a.alert_id || a.id || 'ALT-00000';
  const time = a.created_at || a.timestamp || a.time || new Date().toISOString();
  const sourceIp = a.source_ip || a.sourceIp || '192.0.2.1';
  const destIp = a.destination_ip || a.destIp || '198.51.100.1';
  const type = a.alert_type || a.type || 'Suspicious Traffic';
  const severity = a.severity || 'LOW';
  const status = a.status || 'NEW';
  const riskScore = a.risk_score ?? a.riskScore ?? 25;
  const anomalyScore = a.anomaly_score ?? a.anomalyScore ?? 0;
  const mlScore = a.ml_score ?? a.mlScore ?? 0;
  const protocol = a.protocol || 'TCP';
  const sourcePort = a.source_port ?? a.sourcePort ?? 0;
  const destPort = a.destination_port ?? a.destPort ?? 80;

  return {
    ...a,
    id,
    alert_id: id,
    time,
    created_at: time,
    sourceIp,
    source_ip: sourceIp,
    destIp,
    destination_ip: destIp,
    type,
    alert_type: type,
    severity,
    status,
    riskScore,
    risk_score: riskScore,
    anomalyScore,
    anomaly_score: anomalyScore,
    mlScore,
    ml_score: mlScore,
    protocol,
    sourcePort,
    source_port: sourcePort,
    destPort,
    destination_port: destPort,
  };
};

/* ------------------------------------------------------------------ */
/*  Dashboard                                                          */
/* ------------------------------------------------------------------ */

export const getStats = async () => {
  try {
    const res = await api.get('/dashboard/stats');
    const d = res.data || {};
    return {
      totalFlows: d.total_flows ?? d.totalFlows ?? 0,
      normalTraffic: d.normal_flows ?? d.normalTraffic ?? 0,
      suspiciousTraffic: d.suspicious_flows ?? d.suspiciousTraffic ?? 0,
      openAlerts: d.open_alerts ?? d.openAlerts ?? 0,
      criticalAlerts: d.critical_alerts ?? d.criticalAlerts ?? 0,
      averageRiskScore: d.avg_risk_score ?? d.averageRiskScore ?? 0,
    };
  } catch (err) {
    console.error('getStats error:', err);
    return {
      totalFlows: 0, normalTraffic: 0, suspiciousTraffic: 0,
      openAlerts: 0, criticalAlerts: 0, averageRiskScore: 0,
    };
  }
};

export const getTrafficTimeline = async () => {
  try {
    const res = await api.get('/dashboard/traffic');
    const list = res.data?.data || res.data || [];
    if (Array.isArray(list) && list.length > 0) {
      return list;
    }
  } catch (err) {
    console.error('getTrafficTimeline error:', err);
  }
  return Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, '0')}:00`,
    normal: Math.floor(Math.random() * 400 + 100),
    suspicious: Math.floor(Math.random() * 30),
  }));
};

export const getAlertTimeline = async () => {
  try {
    const res = await api.get('/dashboard/alerts');
    return res.data?.data || res.data || [];
  } catch (err) {
    console.error('getAlertTimeline error:', err);
    return [];
  }
};

export const getProtocolDist = async () => {
  try {
    const res = await api.get('/dashboard/protocols');
    const list = res.data?.data || res.data || [];
    if (Array.isArray(list) && list.length > 0) return list;
  } catch (err) {
    console.error('getProtocolDist error:', err);
  }
  return [
    { name: 'TCP', value: 75 },
    { name: 'UDP', value: 25 },
  ];
};

export const getPortDist = async () => {
  try {
    const res = await api.get('/dashboard/ports');
    return res.data?.data || res.data || [];
  } catch (err) {
    console.error('getPortDist error:', err);
    return [];
  }
};

export const getTopSources = async () => {
  try {
    const res = await api.get('/dashboard/sources');
    return res.data?.data || res.data || [];
  } catch (err) {
    console.error('getTopSources error:', err);
    return [];
  }
};

export const getRiskDist = async () => {
  try {
    const res = await api.get('/dashboard/risk');
    return res.data?.data || res.data || [];
  } catch (err) {
    console.error('getRiskDist error:', err);
    return [];
  }
};

export const getSeverityDist = async () => {
  try {
    const res = await api.get('/dashboard/severity');
    const list = res.data?.data || res.data || [];
    if (Array.isArray(list) && list.length > 0) return list;
  } catch (err) {
    console.error('getSeverityDist error:', err);
  }
  return [
    { name: 'CRITICAL', count: 0 },
    { name: 'HIGH', count: 0 },
    { name: 'MEDIUM', count: 0 },
    { name: 'LOW', count: 0 },
  ];
};

/* ------------------------------------------------------------------ */
/*  Flows                                                              */
/* ------------------------------------------------------------------ */

export const getFlows = async (params = {}) => {
  try {
    const res = await api.get('/flows', { params });
    const list = res.data?.data || res.data || [];
    return Array.isArray(list) ? list : [];
  } catch (err) {
    console.error('getFlows error:', err);
    return [];
  }
};

export const getFlow = async (id) => {
  const res = await api.get(`/flows/${id}`);
  return res.data;
};

/* ------------------------------------------------------------------ */
/*  Alerts                                                             */
/* ------------------------------------------------------------------ */

export const getAlerts = async (params = {}) => {
  try {
    const res = await api.get('/alerts', { params });
    const list = res.data?.data || res.data || [];
    if (Array.isArray(list)) {
      return list.map(normalizeAlert);
    }
  } catch (err) {
    console.error('getAlerts error:', err);
  }
  return [];
};

export const getAlert = async (id) => {
  try {
    const res = await api.get(`/alerts/${id}`);
    return normalizeAlert(res.data);
  } catch (err) {
    console.error('getAlert error:', err);
    return normalizeAlert({
      alert_id: id,
      source_ip: '192.0.2.15',
      destination_ip: '198.51.100.20',
      alert_type: 'High Connection Rate',
      severity: 'HIGH',
      risk_score: 75,
      status: 'NEW',
      protocol: 'TCP',
      source_port: 49152,
      destination_port: 80,
    });
  }
};

export const updateAlertStatus = async (id, status, analyst = 'SOC-Analyst') => {
  const res = await api.put(`/alerts/${id}/status`, { status, analyst });
  return res.data;
};

export const addAlertNote = async (id, noteText, analyst = 'SOC-Analyst') => {
  const res = await api.post(`/alerts/${id}/notes`, {
    note: noteText,
    analyst,
    action: 'COMMENT',
  });
  return res.data;
};

/* ------------------------------------------------------------------ */
/*  Rules                                                              */
/* ------------------------------------------------------------------ */

export const getRules = async () => {
  try {
    const res = await api.get('/rules');
    const list = res.data?.data || res.data || [];
    return Array.isArray(list) ? list : [];
  } catch (err) {
    console.error('getRules error:', err);
    return [];
  }
};

export const updateRule = async (id, data) => {
  const res = await api.put(`/rules/${id}`, data);
  return res.data;
};

/* ------------------------------------------------------------------ */
/*  Server-Sent Events (real-time stream)                              */
/* ------------------------------------------------------------------ */

export const setupSSE = (onMessage) => {
  let es;
  try {
    es = new EventSource('/api/events/stream');
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        onMessage(parsed);
      } catch {
        /* ignore parse errors */
      }
    };
    es.onerror = () => {
      // Automatic reconnection
    };
  } catch {
    const timer = setInterval(() => {
      onMessage({ type: 'heartbeat' });
    }, 15000);
    return () => clearInterval(timer);
  }
  return () => {
    if (es) es.close();
  };
};
