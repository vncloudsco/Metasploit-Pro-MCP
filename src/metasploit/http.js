import http from 'node:http';
import https from 'node:https';

/**
 * Gửi một request thô tới Metasploit Pro. Dùng http/https native để kiểm soát
 * rejectUnauthorized (chứng chỉ self-signed mặc định của Metasploit Pro).
 */
function toBuffer(body) {
  if (Buffer.isBuffer(body)) return body;
  // @msgpack/msgpack trả về Uint8Array (có thể là view của buffer lớn hơn).
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  return Buffer.from(String(body));
}

export function rawRequest({
  scheme = 'https',
  host,
  port,
  path = '/',
  method = 'GET',
  headers = {},
  body,
  timeoutMs = 30000,
  rejectUnauthorized = false,
}) {
  return new Promise((resolve, reject) => {
    const transport = scheme === 'https' ? https : http;
    const payload = body === undefined || body === null ? null : toBuffer(body);
    const options = {
      hostname: host,
      port,
      path,
      method,
      headers: {
        Host: `${host}:${port}`,
        'User-Agent': 'metasploit-pro-mcp/1.0',
        Connection: 'close',
        ...(payload ? { 'Content-Length': payload.length } : {}),
        ...headers,
      },
      timeout: timeoutMs,
    };
    if (scheme === 'https') options.rejectUnauthorized = rejectUnauthorized;

    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        resolve({
          status: res.statusCode || 0,
          statusMessage: res.statusMessage || '',
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
    });

    req.on('timeout', () => req.destroy(new Error(`Metasploit timeout sau ${timeoutMs}ms`)));
    req.on('error', reject);

    if (payload) req.write(payload);
    req.end();
  });
}
