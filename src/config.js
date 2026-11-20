import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const here = path.dirname(fileURLToPath(import.meta.url));
// .env luôn nằm ở thư mục gốc của dự án (được docker compose mount / copy vào).
dotenv.config({ path: path.resolve(here, '..', '.env') });

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on', 'enable', 'enabled'].includes(String(value).trim().toLowerCase());
}

function int(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const config = Object.freeze({
  // Máy chủ MCP (HTTP)
  host: process.env.MCP_HOST || '0.0.0.0',
  port: int(process.env.MCP_PORT, 8080),
  mcpPath: process.env.MCP_PATH || '/mcp',
  authToken: process.env.MCP_AUTH_TOKEN || '',

  // Công tắc an toàn: chỉ cho phép exploit khi = true
  exploitEnabled: bool(process.env.EXPLOIT_ENABLED, false),

  // Metasploit Pro
  msf: Object.freeze({
    scheme: String(process.env.MSF_SCHEME || 'https').replace(/:\/\/$/, '').toLowerCase(),
    host: process.env.MSF_HOST || 'host.docker.internal',
    port: int(process.env.MSF_PORT, 3790),
    apiKey: process.env.MSF_API_KEY || '',
    restBase: process.env.MSF_REST_BASE || '/rest_api/v2',
    rpcPath: process.env.MSF_RPC_URI || '/api/1.0',
    rejectUnauthorized: bool(process.env.MSF_TLS_REJECT_UNAUTHORIZED, false),
    timeoutMs: int(process.env.MSF_REQUEST_TIMEOUT_MS, 30000),
  }),
});

export function assertConfigured() {
  if (!config.authToken) {
    throw new Error('Thiếu MCP_AUTH_TOKEN trong file .env (bắt buộc để xác thực Bearer).');
  }
  if (!config.msf.apiKey) {
    throw new Error('Thiếu MSF_API_KEY trong file .env.');
  }
  if (!['http', 'https'].includes(config.msf.scheme)) {
    throw new Error('MSF_SCHEME chỉ được là http hoặc https.');
  }
}
