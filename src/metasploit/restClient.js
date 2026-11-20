import { config } from '../config.js';
import { rawRequest } from './http.js';

function normalizePath(endpoint) {
  const base = config.msf.restBase.replace(/\/+$/, '');
  return `${base}/${String(endpoint).replace(/^\/+/, '')}`;
}

/**
 * Gọi REST API v2 của Metasploit Pro. API key được gửi qua header `token`.
 */
export async function restRequest(method, endpoint, { query = {}, body } = {}) {
  const url = new URL(normalizePath(endpoint), 'http://internal');
  for (const [key, value] of Object.entries(query || {})) {
    if (value === undefined || value === null || value === '') continue;
    url.searchParams.set(key, String(value));
  }

  const headers = {
    token: config.msf.apiKey,
    // Metasploit trả 406 nếu Accept có nhiều giá trị (vd "application/json, */*").
    Accept: 'application/json',
  };
  let payload;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  const res = await rawRequest({
    scheme: config.msf.scheme,
    host: config.msf.host,
    port: config.msf.port,
    path: `${url.pathname}${url.search}`,
    method,
    headers,
    body: payload,
    timeoutMs: config.msf.timeoutMs,
    rejectUnauthorized: config.msf.rejectUnauthorized,
  });

  const raw = res.body.toString('utf8');
  let data;
  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = raw;
  }

  if (res.status < 200 || res.status >= 300) {
    const detail = typeof data === 'object' && data !== null ? JSON.stringify(data) : raw;
    throw new Error(`Metasploit REST ${method} ${url.pathname} -> HTTP ${res.status} ${res.statusMessage}: ${detail}`);
  }

  return data;
}

export const restGet = (endpoint, query) => restRequest('GET', endpoint, { query });
