/**
 * Dual-Mode API Service - Hybrid Backend & Standalone IDS
 * ========================================================
 * Intelligently switches between:
 * 1. Live Python FastAPI backend (when running locally or connected to server)
 * 2. Standalone Client-Side IDS Simulation Engine (when hosted independently on GitHub Pages/Vercel)
 *
 * Guarantees zero downtime, zero 404s, and full interactive fidelity in all environments.
 */

import axios from 'axios';
import { standaloneEngine } from './standaloneIDS';

const api = axios.create({ baseURL: '/api', timeout: 3000 });

let backendAvailable = null;

// Probes backend availability once on startup
export const checkBackend = async () => {
  if (backendAvailable !== null) return backendAvailable;
  try {
    const res = await api.get('/health');
    backendAvailable = res.status === 200;
  } catch {
    backendAvailable = false;
  }
  return backendAvailable;
};

// Expose direct access to standalone engine for interactive controls
export { standaloneEngine };

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
/*  Dashboard Analytics                                                */
/* ------------------------------------------------------------------ */

export const getStats = async () => {
  try {
    const live = await checkBackend();
    if (live) {
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
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getStats();
};

export const getTrafficTimeline = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/dashboard/traffic');
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getTrafficTimeline();
};

export const getAlertTimeline = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/dashboard/alerts');
      return res.data?.data || res.data || [];
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getSeverityDistribution();
};

export const getProtocolDist = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/dashboard/protocols');
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getProtocolDistribution();
};

export const getPortDist = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/dashboard/ports');
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getPortDistribution();
};

export const getTopSources = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/dashboard/sources');
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getTopSources();
};

export const getSeverityDist = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/dashboard/severity');
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getSeverityDistribution();
};

export const getFlows = async (limit = 100) => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/flows', { params: { limit } });
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getFlows(limit);
};

/* ------------------------------------------------------------------ */
/*  Alerts Management & Forensic Triage                                */
/* ------------------------------------------------------------------ */

export const getAlerts = async (params = {}) => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/alerts', { params });
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) {
        return list.map(normalizeAlert);
      }
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.alerts.map(normalizeAlert);
};

export const getAlert = async (id) => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get(`/alerts/${id}`);
      return normalizeAlert(res.data);
    }
  } catch {
    backendAvailable = false;
  }
  const found = standaloneEngine.alerts.find(a => a.id === id || a.alert_id === id);
  if (found) return normalizeAlert(found);
  return normalizeAlert({
    alert_id: id,
    source_ip: '198.51.100.88',
    destination_ip: '192.0.2.10',
    alert_type: 'SYN-Heavy Flood Pattern',
    severity: 'CRITICAL',
    risk_score: 92,
    anomaly_score: 88,
    status: 'NEW',
    protocol: 'TCP',
    source_port: 48921,
    destination_port: 80,
  });
};

export const updateAlertStatus = async (id, status, analyst = 'SOC-Analyst-Tier1') => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.put(`/alerts/${id}/status`, { status, analyst });
      return res.data;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.updateAlertStatus(id, status, analyst);
};

export const addAlertNote = async (id, noteText, analyst = 'SOC-Analyst-Tier1') => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.post(`/alerts/${id}/notes`, { note: noteText, analyst, action: 'COMMENT' });
      return res.data;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.addAlertNote(id, noteText, analyst);
};

export const getAlertNotes = async (id) => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get(`/alerts/${id}/notes`);
      return res.data?.data || res.data || [];
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.getAlertNotes(id);
};

/* ------------------------------------------------------------------ */
/*  Rules Engine                                                       */
/* ------------------------------------------------------------------ */

export const getRules = async () => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.get('/rules');
      const list = res.data?.data || res.data || [];
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.rules;
};

export const updateRule = async (id, data) => {
  try {
    const live = await checkBackend();
    if (live) {
      const res = await api.put(`/rules/${id}`, data);
      return res.data;
    }
  } catch {
    backendAvailable = false;
  }
  return standaloneEngine.updateRule(id, data);
};

/* ------------------------------------------------------------------ */
/*  Real-Time Event Stream (SSE or In-Browser Engine)                  */
/* ------------------------------------------------------------------ */

export const setupSSE = (onMessage) => {
  // If backend is unreachable or on static page, subscribe to in-browser engine directly
  const unsubscribe = standaloneEngine.subscribe(onMessage);

  let es = null;
  checkBackend().then(live => {
    if (live) {
      try {
        es = new EventSource('/api/events/stream');
        es.onmessage = (e) => {
          try {
            const parsed = JSON.parse(e.data);
            onMessage(parsed);
          } catch { /* noop */ }
        };
      } catch { /* noop */ }
    }
  });

  return () => {
    unsubscribe();
    if (es) es.close();
  };
};

/* ------------------------------------------------------------------ */
/*  Interactive Demo Helpers                                           */
/* ------------------------------------------------------------------ */

export const injectAttackWave = (type) => {
  return standaloneEngine.injectAttack(type);
};

export const toggleLiveStream = (active) => {
  return standaloneEngine.toggleStreaming(active);
};
