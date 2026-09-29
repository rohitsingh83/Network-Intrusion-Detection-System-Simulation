/**
 * API Service – Axios wrapper for the Network IDS Backend
 * ========================================================
 * Talks to FastAPI endpoints via the CRA proxy (http://localhost:8000).
 * Every function first tries the real API; on failure it falls back to
 * realistic mock data so the frontend remains demo-able standalone.
 */

import axios from 'axios';

const api = axios.create({ baseURL: '/api', timeout: 8000 });

/* ------------------------------------------------------------------ */
/*  Dashboard                                                          */
/* ------------------------------------------------------------------ */

export const getStats = async () => {
  try {
    const res = await api.get('/dashboard/stats');
    return res.data;
  } catch {
    return {
      totalFlows: 0, normalTraffic: 0, suspiciousTraffic: 0,
      openAlerts: 0, criticalAlerts: 0, averageRiskScore: 0,
    };
  }
};

export const getTrafficTimeline = async () => {
  try {
    const res = await api.get('/dashboard/traffic');
    return res.data;
  } catch {
    return Array.from({ length: 24 }, (_, i) => ({
      time: `${String(i).padStart(2, '0')}:00`,
      normal: Math.floor(Math.random() * 800 + 200),
      suspicious: Math.floor(Math.random() * 40),
    }));
  }
};

export const getAlertTimeline = async () => {
  try {
    const res = await api.get('/dashboard/alerts');
    return res.data;
  } catch {
    return [
      { name: 'CRITICAL', count: 0 },
      { name: 'HIGH', count: 0 },
      { name: 'MEDIUM', count: 0 },
      { name: 'LOW', count: 0 },
    ];
  }
};

export const getProtocolDist = async () => {
  try {
    const res = await api.get('/dashboard/protocols');
    return res.data;
  } catch {
    return [
      { name: 'TCP', value: 0 },
      { name: 'UDP', value: 0 },
    ];
  }
};

export const getPortDist = async () => {
  try {
    const res = await api.get('/dashboard/ports');
    return res.data;
  } catch {
    return [];
  }
};

export const getTopSources = async () => {
  try {
    const res = await api.get('/dashboard/sources');
    return res.data;
  } catch {
    return [];
  }
};

export const getRiskDist = async () => {
  try {
    const res = await api.get('/dashboard/risk');
    return res.data;
  } catch {
    return [
      { range: '0-20', count: 0 },
      { range: '21-40', count: 0 },
      { range: '41-60', count: 0 },
      { range: '61-80', count: 0 },
      { range: '81-100', count: 0 },
    ];
  }
};

export const getSeverityDist = async () => {
  try {
    const res = await api.get('/dashboard/severity');
    return res.data;
  } catch {
    return [];
  }
};

/* ------------------------------------------------------------------ */
/*  Flows                                                              */
/* ------------------------------------------------------------------ */

export const getFlows = async (params = {}) => {
  try {
    const res = await api.get('/flows', { params });
    return res.data;
  } catch {
    return { data: [], count: 0 };
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
    return res.data;
  } catch {
    return { data: [], count: 0 };
  }
};

export const getAlert = async (id) => {
  const res = await api.get(`/alerts/${id}`);
  return res.data;
};

export const updateAlertStatus = async (id, status, analyst = 'Analyst') => {
  const res = await api.put(`/alerts/${id}/status`, { status, analyst });
  return res.data;
};

export const addAlertNote = async (id, noteObj) => {
  const res = await api.post(`/alerts/${id}/notes`, noteObj);
  return res.data;
};

/* ------------------------------------------------------------------ */
/*  Rules                                                              */
/* ------------------------------------------------------------------ */

export const getRules = async () => {
  try {
    const res = await api.get('/rules');
    return res.data;
  } catch {
    return [];
  }
};

export const updateRule = async (id, data) => {
  const res = await api.put(`/rules/${id}`, data);
  return res.data;
};

/* ------------------------------------------------------------------ */
/*  Server-Sent Events (real-time)                                     */
/* ------------------------------------------------------------------ */

export const setupSSE = (onMessage) => {
  let es;
  try {
    es = new EventSource('/api/events/stream');
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        onMessage(parsed);
      } catch { /* ignore parse errors */ }
    };
    es.onerror = () => {
      // Silently reconnect – EventSource handles this automatically
    };
  } catch {
    // SSE not supported or blocked – fall back to polling
    const timer = setInterval(() => {
      onMessage({ type: 'heartbeat' });
    }, 15000);
    return () => clearInterval(timer);
  }
  return () => { if (es) es.close(); };
};
