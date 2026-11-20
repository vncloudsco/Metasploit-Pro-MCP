import { encode, decode, ExtensionCodec } from '@msgpack/msgpack';
import { config } from '../config.js';
import { rawRequest } from './http.js';

// msgpack-ruby có thể trả về giá trị dùng extension type (Symbol, Time, ...).
// Đăng ký bộ giải mã tổng quát để response không bị lỗi "unregistered extension type".
const extensionCodec = new ExtensionCodec();
for (let type = -128; type <= 127; type += 1) {
  extensionCodec.register({
    type,
    decode: (data) => {
      const bytes = Buffer.from(data);
      const asText = bytes.toString('utf8');
      // Ưu tiên chuỗi nếu dữ liệu là text, ngược lại giữ base64 để không mất bytes.
      return /^[\x09\x0A\x0D\x20-\x7E]*$/.test(asText) && asText.length > 0
        ? asText
        : { __ext: type, __base64: bytes.toString('base64') };
    },
  });
}

/**
 * Gọi RPC API (MessagePack) của Metasploit Pro.
 * Định dạng: ["MethodName", "<api token>", ...params]
 * Response: hash kết quả, hoặc hash có `error: true` khi lỗi.
 */
export async function rpcCall(method, params = []) {
  if (!method || typeof method !== 'string') {
    throw new Error('Tên method RPC không hợp lệ.');
  }

  const payload = [method, config.msf.apiKey, ...(Array.isArray(params) ? params : [params])];
  const body = encode(payload, { extensionCodec, ignoreUndefined: true });

  const res = await rawRequest({
    scheme: config.msf.scheme,
    host: config.msf.host,
    port: config.msf.port,
    path: config.msf.rpcPath,
    method: 'POST',
    headers: {
      'Content-Type': 'binary/message-pack',
      Accept: 'application/msgpack, application/json, */*',
    },
    body,
    timeoutMs: config.msf.timeoutMs,
    rejectUnauthorized: config.msf.rejectUnauthorized,
  });

  const contentType = String(res.headers['content-type'] || '').toLowerCase();
  let data;
  try {
    data = contentType.includes('json')
      ? JSON.parse(res.body.toString('utf8'))
      : decode(res.body, {
          extensionCodec,
          // msgpack-ruby encode các key dạng bin type -> Uint8Array; convert về string.
          mapKeyConverter: (key) => {
            if (typeof key === 'string' || typeof key === 'number') return key;
            if (key instanceof Uint8Array || Buffer.isBuffer(key)) return Buffer.from(key).toString('utf8');
            return String(key);
          },
        });
  } catch (err) {
    throw new Error(`Không giải mã được response RPC (${contentType || 'unknown'}): ${err.message}`);
  }

  if (res.status === 401 || res.status === 403) {
    throw new Error(`RPC từ chối xác thực (HTTP ${res.status}). Kiểm tra MSF_API_KEY / quyền của API key.`);
  }
  if (res.status === 404) {
    throw new Error(`RPC endpoint ${config.msf.rpcPath} không tồn tại (HTTP 404).`);
  }
  if (res.status >= 400) {
    throw new Error(`RPC ${method} -> HTTP ${res.status} ${res.statusMessage}: ${JSON.stringify(data)}`);
  }

  if (data && typeof data === 'object' && !Array.isArray(data) && data.error === true) {
    throw new Error(`RPC ${method} lỗi: ${data.error_class || ''} ${data.error_message || JSON.stringify(data)}`.trim());
  }

  return data;
}
