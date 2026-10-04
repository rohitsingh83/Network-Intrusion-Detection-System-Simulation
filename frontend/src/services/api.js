// Browser API helpers shared by the dashboard pages.
import { resetStaticDemo, staticApi } from './static-api.js';

export const IS_STATIC_DEMO = window.location.hostname.endsWith('.github.io')
  || window.location.search.includes('static-demo=1')
  || document.documentElement.dataset.staticDemo === 'true';
export { resetStaticDemo };

export const escapeHTML = (value = '') => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]));

export const fmtNumber = (value, digits = 0) => Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: digits });

export const fmtDate = (value) => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? escapeHTML(value) : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
};

export const shortTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

export async function api(path, options = {}) {
  if (IS_STATIC_DEMO) return staticApi(path, options);
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const key = localStorage.getItem('sentinelflowApiKey');
  if (key) headers['X-API-Key'] = key;
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  let result = {};
  try { result = text ? JSON.parse(text) : {}; } catch { result = { detail: text }; }
  if (!response.ok) throw new Error(result.detail || `Request failed (${response.status})`);
  return result;
}
