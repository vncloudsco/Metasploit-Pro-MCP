import crypto from 'node:crypto';

/**
 * Middleware xác thực Bearer token cho endpoint MCP.
 * So sánh theo thời gian không đổi (timing-safe) để tránh timing attack.
 */
export function bearerAuth(requiredToken) {
  const expected = Buffer.from(requiredToken, 'utf8');

  return function authenticate(req, res, next) {
    const header = req.get('authorization') || '';
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());

    if (!match) {
      res.set('WWW-Authenticate', 'Bearer realm="metasploit-pro-mcp", error="invalid_token"');
      return res.status(401).json({
        error: 'unauthorized',
        message: 'Thiếu header Authorization: Bearer <MCP_AUTH_TOKEN>.',
      });
    }

    const provided = Buffer.from(match[1].trim(), 'utf8');
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
      res.set('WWW-Authenticate', 'Bearer realm="metasploit-pro-mcp", error="invalid_token"');
      return res.status(401).json({
        error: 'unauthorized',
        message: 'Bearer token không hợp lệ.',
      });
    }

    req.auth = { authenticated: true, method: 'bearer' };
    return next();
  };
}
