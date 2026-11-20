import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { assertConfigured, config } from './config.js';
import { bearerAuth } from './auth.js';
import { registerTools } from './tools/index.js';

assertConfigured();

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10mb' }));

// Health check công khai (không chứa thông tin nhạy cảm) để docker healthcheck.
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'metasploit-pro-mcp',
    transport: 'streamable-http',
    exploitEnabled: config.exploitEnabled,
  });
});

const authenticate = bearerAuth(config.authToken);

app.all(config.mcpPath, authenticate, async (req, res) => {
  if (req.method !== 'POST') {
    res.set('Allow', 'POST');
    return res.status(405).json({
      jsonrpc: '2.0',
      error: { code: -32600, message: 'Chỉ chấp nhận POST cho MCP messages.' },
      id: null,
    });
  }

  let server;
  let transport;
  try {
    server = new McpServer(
      { name: 'metasploit-pro-mcp', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );
    registerTools(server);

    // Stateless: mỗi request là một phiên độc lập, dễ scale và không cần session affinity.
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      try {
        transport?.close();
      } catch {
        /* already closed */
      }
      try {
        server?.close();
      } catch {
        /* already closed */
      }
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('[mcp] request failed:', err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: err?.message || 'Internal error' },
        id: null,
      });
    }
  }
});

app.use((err, _req, res, _next) => {
  console.error('[http]', err);
  if (!res.headersSent) res.status(400).json({ error: 'bad_request', message: err?.message || 'Invalid request' });
});

const server = app.listen(config.port, config.host, () => {
  console.log(`[metasploit-pro-mcp] listening on http://${config.host}:${config.port}${config.mcpPath}`);
  console.log(`[metasploit-pro-mcp] Metasploit: ${config.msf.scheme}://${config.msf.host}:${config.msf.port}`);
  console.log(`[metasploit-pro-mcp] exploitEnabled=${config.exploitEnabled}`);
});

function shutdown() {
  console.log('[metasploit-pro-mcp] shutting down...');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
