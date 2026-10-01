/**
 * api-client.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unified API layer.
 *
 * Mode selection (automatic):
 *   - STANDALONE / GitHub Pages → uses mockApi (in-browser IDS simulation)
 *   - Local dev / production    → fetches from FastAPI backend at API_BASE
 *
 * Set NEXT_PUBLIC_STANDALONE=true to force standalone mode.
 * Set NEXT_PUBLIC_API_URL to override the backend URL.
 */

import type {
  HealthStatus, Flow, Alert, DashboardStats,
  TrafficPoint, ProtocolDist, SeverityDist, PortDist, SourceDist,
} from '@/types';

// ─── Detect execution context ─────────────────────────────────────────────────
// GitHub Pages has no backend → use mock engine.
// We check:
//   1. Explicit env var NEXT_PUBLIC_STANDALONE=true
//   2. Running in browser AND hostname ends with github.io
const isStandalone = (): boolean => {
  if (process.env.NEXT_PUBLIC_STANDALONE === 'true') return true;
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    if (host.endsWith('github.io') || host === 'localhost.local') return true;
  }
  return false;
};

// ─── Real API (FastAPI backend) ───────────────────────────────────────────────
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

const realApi = {
  health: () => fetchAPI<HealthStatus>('/api/health'),

  getFlows: (params?: { limit?: number; offset?: number; protocol?: string; classification?: string }) => {
    const q = new URLSearchParams();
    if (params?.limit)          q.set('limit',          String(params.limit));
    if (params?.offset)         q.set('offset',         String(params.offset));
    if (params?.protocol)       q.set('protocol',       params.protocol);
    if (params?.classification) q.set('classification', params.classification);
    return fetchAPI<Flow[]>(`/api/flows?${q.toString()}`);
  },

  getAlerts: (params?: { limit?: number; severity?: string; status?: string }) => {
    const q = new URLSearchParams();
    if (params?.limit)    q.set('limit',    String(params.limit));
    if (params?.severity) q.set('severity', params.severity);
    if (params?.status)   q.set('status',   params.status);
    return fetchAPI<Alert[]>(`/api/alerts?${q.toString()}`);
  },

  getAlert: (id: string) => fetchAPI<Alert>(`/api/alerts/${id}`),

  updateAlertStatus: (id: string, status: string, analyst: string) =>
    fetchAPI<Alert>(`/api/alerts/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status, analyst }),
    }),

  addNote: (id: string, note: string, analyst: string, action?: string) =>
    fetchAPI<Alert>(`/api/alerts/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify({ note, analyst, action }),
    }),

  getStats:     () => fetchAPI<DashboardStats>('/api/dashboard/stats'),
  getTraffic:   () => fetchAPI<TrafficPoint[]>('/api/dashboard/traffic'),
  getProtocols: () => fetchAPI<ProtocolDist[]>('/api/dashboard/protocols'),
  getSeverity:  () => fetchAPI<SeverityDist[]>('/api/dashboard/severity'),
  getPorts:     () => fetchAPI<PortDist[]>('/api/dashboard/ports'),
  getSources:   () => fetchAPI<SourceDist[]>('/api/dashboard/sources'),
  getRules:     () => fetchAPI<Record<string, unknown>[]>('/api/rules'),
};

// ─── Dynamic import of mock engine (tree-shaken in production w/ real backend) ─
let _mockApi: typeof import('@/lib/mock-engine').mockApi | null = null;

async function getMockApi() {
  if (!_mockApi) {
    const mod = await import('@/lib/mock-engine');
    mod.startSimulation();
    _mockApi = mod.mockApi;
  }
  return _mockApi;
}

// ─── Unified API object ───────────────────────────────────────────────────────
type ApiMethod<T> = () => Promise<T>;
type ApiMethodP<P, T> = (params?: P) => Promise<T>;

function adapt<T>(real: ApiMethod<T>, mockFn: () => Promise<T>): ApiMethod<T> {
  return async () => {
    if (isStandalone()) return (await getMockApi()).health() as unknown as T;
    return real();
  };
}

// Build the unified api object
export const api = {
  health: async (): Promise<HealthStatus> => {
    if (isStandalone()) return (await getMockApi()).health();
    return realApi.health();
  },

  getFlows: async (params?: Parameters<typeof realApi.getFlows>[0]): Promise<Flow[]> => {
    if (isStandalone()) return (await getMockApi()).getFlows(params);
    return realApi.getFlows(params);
  },

  getAlerts: async (params?: Parameters<typeof realApi.getAlerts>[0]): Promise<Alert[]> => {
    if (isStandalone()) return (await getMockApi()).getAlerts(params);
    return realApi.getAlerts(params);
  },

  getAlert: async (id: string): Promise<Alert> => {
    if (isStandalone()) return (await getMockApi()).getAlert(id);
    return realApi.getAlert(id);
  },

  updateAlertStatus: async (id: string, status: string, analyst: string): Promise<Alert> => {
    if (isStandalone()) return (await getMockApi()).updateAlertStatus(id, status, analyst);
    return realApi.updateAlertStatus(id, status, analyst);
  },

  addNote: async (id: string, note: string, analyst: string, action?: string): Promise<Alert> => {
    if (isStandalone()) return (await getMockApi()).addNote(id, note, analyst, action);
    return realApi.addNote(id, note, analyst, action);
  },

  getStats: async (): Promise<DashboardStats> => {
    if (isStandalone()) return (await getMockApi()).getStats();
    return realApi.getStats();
  },

  getTraffic: async (): Promise<TrafficPoint[]> => {
    if (isStandalone()) return (await getMockApi()).getTraffic();
    return realApi.getTraffic();
  },

  getProtocols: async (): Promise<ProtocolDist[]> => {
    if (isStandalone()) return (await getMockApi()).getProtocols();
    return realApi.getProtocols();
  },

  getSeverity: async (): Promise<SeverityDist[]> => {
    if (isStandalone()) return (await getMockApi()).getSeverity();
    return realApi.getSeverity();
  },

  getPorts: async (): Promise<PortDist[]> => {
    if (isStandalone()) return (await getMockApi()).getPorts();
    return realApi.getPorts();
  },

  getSources: async (): Promise<SourceDist[]> => {
    if (isStandalone()) return (await getMockApi()).getSources();
    return realApi.getSources();
  },

  getRules: async (): Promise<Record<string, unknown>[]> => {
    if (isStandalone()) return (await getMockApi()).getRules();
    return realApi.getRules();
  },
};
