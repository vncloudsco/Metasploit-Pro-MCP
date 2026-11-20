import { z } from 'zod';
import { config } from '../config.js';
import { restGet } from '../metasploit/restClient.js';
import { rpcCall } from '../metasploit/rpcClient.js';

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function bytesToDisplay(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const text = buffer.toString('utf8');
  // msgpack-ruby dùng kiểu bin cho cả chuỗi thường -> ưu tiên hiển thị text khi có thể.
  return text.length > 0 && /^[\x09\x0A\x0D\x20-\x7E]*$/.test(text)
    ? text
    : { __base64: buffer.toString('base64') };
}

function normalize(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value ?? null;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return bytesToDisplay(value);
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map((item) => normalize(item, seen));
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = normalize(item, seen);
    return out;
  }
  return value;
}

const ok = (value) => ({
  content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(normalize(value), null, 2) }],
});

const fail = (err) => ({
  content: [{ type: 'text', text: `ERROR: ${err?.message || String(err)}` }],
  isError: true,
});

const safe = (fn) => async (args) => {
  try {
    return ok(await fn(args || {}));
  } catch (err) {
    return fail(err);
  }
};

const EXPLOIT_DISABLED_MESSAGE =
  'EXPLOIT_DISABLED: tính năng exploit đã bị tắt. Đặt EXPLOIT_ENABLED=true trong file .env và khởi động lại container để kích hoạt.';

const gated = (fn) => async (args) => {
  if (!config.exploitEnabled) return fail(new Error(EXPLOIT_DISABLED_MESSAGE));
  return safe(fn)(args);
};

const ws = (id) => `workspaces/${encodeURIComponent(id)}`;
const hp = (w, h) => `${ws(w)}/hosts/${encodeURIComponent(h)}`;
const sp = (w, h, s) => `${hp(w, h)}/services/${encodeURIComponent(s)}`;
const wp = (w, h, s, site) => `${sp(w, h, s)}/web_sites/${encodeURIComponent(site)}`;

const pick = (obj, keys) => {
  const out = {};
  for (const key of keys) if (obj[key] !== undefined && obj[key] !== null) out[key] = obj[key];
  return out;
};

// Chặn exploit cả khi dùng tool RPC tổng quát.
const EXPLOIT_METHOD_PATTERNS = [
  /^pro\.start_exploit$/i,
  /^pro\.run_module$/i,
  /^module\.run$/i,
  /^console\.write$/i,
  /^session\.(shell|write|meterpreter|upload|download)/i,
  /exploit/i,
];

/* ------------------------------------------------------------------ */
/* Schemas dùng lại                                                    */
/* ------------------------------------------------------------------ */

const workspace_id = z.number().int().positive();
const host_id = z.number().int().positive();
const service_id = z.number().int().positive();
const siteId = z.number().int().positive();
const options = z.record(z.any());

/* ------------------------------------------------------------------ */
/* Danh mục tool                                                       */
/* ------------------------------------------------------------------ */

const tools = [
  /* ---------- Hệ thống / kết nối ---------- */
  {
    name: 'msf_health',
    description: 'Kiểm tra kết nối tới Metasploit Pro (REST base + RPC core.version) và trạng thái công tắc exploit.',
    schema: {},
    run: async () => {
      const base = await restGet('base');
      let version = null;
      try {
        version = await rpcCall('core.version');
      } catch (err) {
        version = { error: err.message };
      }
      return { connected: true, rest: base, rpc: version, exploitEnabled: config.exploitEnabled };
    },
  },
  {
    name: 'msf_core_version',
    description: 'Lấy phiên bản Metasploit qua RPC core.version.',
    schema: {},
    run: () => rpcCall('core.version'),
  },
  {
    name: 'msf_core_about',
    description: 'Lấy thông tin tổng quan về instance Metasploit Pro qua RPC pro.about.',
    schema: {},
    run: () => rpcCall('pro.about'),
  },

  /* ---------- Project / Workspace ---------- */
  {
    name: 'msf_workspaces_list',
    description: 'Liệt kê tất cả project (workspace) trong Metasploit Pro (REST API).',
    schema: {},
    run: () => restGet('workspaces'),
  },
  {
    name: 'msf_workspace_get',
    description: 'Xem chi tiết một project (workspace) theo ID.',
    schema: { id: workspace_id.describe('Workspace ID') },
    run: ({ id }) => restGet(`${ws(id)}`),
  },
  {
    name: 'msf_workspace_add',
    description: 'Tạo project (workspace) mới qua RPC pro.workspace_add.',
    schema: {
      name: z.string().min(1).describe('Tên project mới'),
      boundary: z.string().optional().describe('Phạm vi mạng, ví dụ 192.168.0.0/24'),
      description: z.string().optional(),
      owner: z.string().optional(),
      limit_to_network: z.boolean().optional(),
    },
    run: (args) => rpcCall('pro.workspace_add', [pick(args, ['name', 'boundary', 'description', 'owner', 'limit_to_network'])]),
  },
  {
    name: 'msf_workspace_update',
    description: 'Cập nhật project (workspace) qua RPC pro.workspace_update.',
    schema: {
      id: z.union([z.number().int(), z.string()]).optional().describe('ID hoặc tên workspace cần update'),
      name: z.string().optional().describe('Tên workspace (dùng khi không truyền id)'),
      boundary: z.string().optional(),
      description: z.string().optional(),
      limit_to_network: z.boolean().optional(),
      options: options.optional().describe('Các trường bổ sung truyền thẳng vào RPC'),
    },
    run: ({ id, options: extra, ...rest }) => {
      const payload = { ...(extra || {}), ...pick(rest, ['name', 'boundary', 'description', 'limit_to_network']) };
      if (id !== undefined) payload.id = id;
      return rpcCall('pro.workspace_update', [payload]);
    },
  },
  {
    name: 'msf_workspace_delete',
    description: 'Xóa project (workspace) qua RPC pro.workspace_delete.',
    schema: {
      workspace: z.union([z.string(), z.number().int()]).describe('Tên hoặc ID workspace cần xóa'),
    },
    run: ({ workspace }) => rpcCall('pro.workspace_delete', [workspace]),
  },

  /* ---------- Dữ liệu: Hosts / Services / Vulns / Sessions / Notes ---------- */
  {
    name: 'msf_hosts_list',
    description: 'Liệt kê host trong một project (workspace).',
    schema: { workspace_id, query: z.record(z.union([z.string(), z.number(), z.boolean()])).optional() },
    run: ({ workspace_id, query }) => restGet(`${ws(workspace_id)}/hosts`, query),
  },
  {
    name: 'msf_host_get',
    description: 'Xem chi tiết một host.',
    schema: { workspace_id, host_id },
    run: ({ workspace_id, host_id }) => restGet(hp(workspace_id, host_id)),
  },
  {
    name: 'msf_services_list',
    description: 'Liệt kê service của một host.',
    schema: { workspace_id, host_id },
    run: ({ workspace_id, host_id }) => restGet(`${hp(workspace_id, host_id)}/services`),
  },
  {
    name: 'msf_service_get',
    description: 'Xem chi tiết một service.',
    schema: { workspace_id, host_id, service_id },
    run: ({ workspace_id, host_id, service_id }) => restGet(sp(workspace_id, host_id, service_id)),
  },
  {
    name: 'msf_vulns_list',
    description: 'Liệt kê lỗ hổng (vulns) của một service.',
    schema: { workspace_id, host_id, service_id },
    run: ({ workspace_id, host_id, service_id }) => restGet(`${sp(workspace_id, host_id, service_id)}/vulns`),
  },
  {
    name: 'msf_vuln_get',
    description: 'Xem chi tiết một lỗ hổng.',
    schema: { workspace_id, host_id, service_id, vuln_id: z.number().int().positive() },
    run: ({ workspace_id, host_id, service_id, vuln_id }) => restGet(`${sp(workspace_id, host_id, service_id)}/vulns/${vuln_id}`),
  },
  {
    name: 'msf_sessions_list',
    description: 'Liệt kê session của một host.',
    schema: { workspace_id, host_id },
    run: ({ workspace_id, host_id }) => restGet(`${hp(workspace_id, host_id)}/sessions`),
  },
  {
    name: 'msf_session_get',
    description: 'Xem chi tiết một session.',
    schema: { workspace_id, host_id, session_id: z.number().int().positive() },
    run: ({ workspace_id, host_id, session_id }) => restGet(`${hp(workspace_id, host_id)}/sessions/${session_id}`),
  },
  {
    name: 'msf_notes_list',
    description: 'Liệt kê note của một host.',
    schema: { workspace_id, host_id },
    run: ({ workspace_id, host_id }) => restGet(`${hp(workspace_id, host_id)}/notes`),
  },
  {
    name: 'msf_note_get',
    description: 'Xem chi tiết một note.',
    schema: { workspace_id, host_id, note_id: z.number().int().positive() },
    run: ({ workspace_id, host_id, note_id }) => restGet(`${hp(workspace_id, host_id)}/notes/${note_id}`),
  },
  {
    name: 'msf_web_sites_list',
    description: 'Liệt kê website phát hiện được trên một service.',
    schema: { workspace_id, host_id, service_id },
    run: ({ workspace_id, host_id, service_id }) => restGet(`${sp(workspace_id, host_id, service_id)}/web_sites`),
  },
  {
    name: 'msf_web_forms_list',
    description: 'Liệt kê web form của một website.',
    schema: { workspace_id, host_id, service_id, web_site_id: siteId },
    run: ({ workspace_id, host_id, service_id, web_site_id }) =>
      restGet(`${wp(workspace_id, host_id, service_id, web_site_id)}/web_forms`),
  },
  {
    name: 'msf_web_pages_list',
    description: 'Liệt kê web page của một website.',
    schema: { workspace_id, host_id, service_id, web_site_id: siteId },
    run: ({ workspace_id, host_id, service_id, web_site_id }) =>
      restGet(`${wp(workspace_id, host_id, service_id, web_site_id)}/web_pages`),
  },
  {
    name: 'msf_web_vulns_list',
    description: 'Liệt kê lỗ hổng web của một website.',
    schema: { workspace_id, host_id, service_id, web_site_id: siteId },
    run: ({ workspace_id, host_id, service_id, web_site_id }) =>
      restGet(`${wp(workspace_id, host_id, service_id, web_site_id)}/web_vulns`),
  },
  {
    name: 'msf_rest_get',
    description: 'Gọi tùy ý GET /rest_api/v2/<path> (full REST API) với query params.',
    schema: {
      path: z.string().min(1).describe('Đường dẫn sau /rest_api/v2, ví dụ workspaces/1/hosts'),
      query: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
    },
    run: ({ path, query }) => restGet(path, query),
  },

  /* ---------- Scan / Discovery / Import ---------- */
  {
    name: 'msf_scan_start',
    description: 'Bắt đầu discovery scan qua RPC pro.start_discover. Trả về task_id.',
    schema: {
      workspace: z.string().min(1).describe('Tên project chạy scan'),
      ips: z.array(z.string()).min(1).describe('Danh sách IP/CIDR, ví dụ ["192.168.1.0/24"]'),
      ports: z.string().optional().describe('DS_PORTS_CUSTOM, ví dụ "1-65535"'),
      fast_detect: z.boolean().optional(),
      dry_run: z.boolean().optional(),
      options: options.optional().describe('Các DS_* option bổ sung'),
    },
    run: ({ workspace, ips, ports, fast_detect, dry_run, options: extra }) =>
      rpcCall('pro.start_discover', [
        {
          ips,
          workspace,
          ...(ports ? { DS_PORTS_CUSTOM: ports } : {}),
          ...(fast_detect !== undefined ? { DS_FAST_DETECT: fast_detect } : {}),
          ...(dry_run !== undefined ? { DS_DRY_RUN: dry_run } : {}),
          ...(extra || {}),
        },
      ]),
  },
  {
    name: 'msf_scan_bruteforce_start',
    description: 'Bắt đầu bruteforce qua RPC pro.start_bruteforce.',
    schema: {
      workspace: z.string().min(1),
      options: options.optional().describe('Các tham số/DS_* option, ví dụ DS_PATH, DS_USERNAMES, DS_PASSWORDS'),
    },
    run: ({ workspace, options: extra }) => rpcCall('pro.start_bruteforce', [{ workspace, ...(extra || {}) }]),
  },
  {
    name: 'msf_scan_import_start',
    description: 'Import dữ liệu (Nessus, Nmap, ...) vào project qua RPC pro.start_import.',
    schema: {
      workspace: z.string().min(1),
      path: z.string().min(1).describe('Đường dẫn file import trên máy Metasploit (DS_PATH)'),
      options: options.optional(),
    },
    run: ({ workspace, path, options: extra }) =>
      rpcCall('pro.start_import', [{ workspace, DS_PATH: path, ...(extra || {}) }]),
  },

  /* ---------- Exploit (BỊ KHÓA nếu EXPLOIT_ENABLED != true) ---------- */
  {
    name: 'msf_exploit_start',
    description:
      'Chạy automated exploitation qua RPC pro.start_exploit. CHỈ hoạt động khi EXPLOIT_ENABLED=true trong .env.',
    guard: 'exploit',
    schema: {
      workspace: z.string().min(1),
      whitelist_hosts: z.string().optional().describe('DS_WHITELIST_HOSTS, ví dụ "192.168.0.0/24"'),
      minimum_rank: z.string().optional().describe('DS_MinimumRank, ví dụ "great"'),
      exploit_speed: z.number().optional().describe('DS_EXPLOIT_SPEED'),
      exploit_timeout: z.number().optional().describe('DS_EXPLOIT_TIMEOUT'),
      limit_sessions: z.boolean().optional().describe('DS_LimitSessions'),
      match_vulns: z.boolean().optional().describe('DS_MATCH_VULNS'),
      match_ports: z.boolean().optional().describe('DS_MATCH_PORTS'),
      options: options.optional().describe('Các DS_* option bổ sung'),
    },
    run: ({ workspace, whitelist_hosts, minimum_rank, exploit_speed, exploit_timeout, limit_sessions, match_vulns, match_ports, options: extra }) =>
      rpcCall('pro.start_exploit', [
        {
          workspace,
          ...(whitelist_hosts ? { DS_WHITELIST_HOSTS: whitelist_hosts } : {}),
          ...(minimum_rank ? { DS_MinimumRank: minimum_rank } : {}),
          ...(exploit_speed !== undefined ? { DS_EXPLOIT_SPEED: exploit_speed } : {}),
          ...(exploit_timeout !== undefined ? { DS_EXPLOIT_TIMEOUT: exploit_timeout } : {}),
          ...(limit_sessions !== undefined ? { DS_LimitSessions: limit_sessions } : {}),
          ...(match_vulns !== undefined ? { DS_MATCH_VULNS: match_vulns } : {}),
          ...(match_ports !== undefined ? { DS_MATCH_PORTS: match_ports } : {}),
          ...(extra || {}),
        },
      ]),
  },
  {
    name: 'msf_module_search',
    description: 'Tìm module Metasploit (exploit/auxiliary/payload/...).',
    schema: { query: z.string().min(1).describe('Từ khóa, ví dụ "ms17_010"') },
    run: ({ query }) => rpcCall('module.search', [query]),
  },
  {
    name: 'msf_module_info',
    description: 'Xem thông tin chi tiết một module.',
    schema: {
      module_type: z.string().min(1).describe('exploit | auxiliary | payload | post | encoder | nop'),
      module_name: z.string().min(1).describe('Đường dẫn module, ví dụ exploit/windows/smb/ms17_010_eternalblue'),
    },
    run: ({ module_type, module_name }) => rpcCall('module.info', [module_type, module_name]),
  },
  {
    name: 'msf_module_check',
    description: 'Chạy phương thức check của module để kiểm tra mục tiêu (không khai thác).',
    schema: {
      module_type: z.string().min(1),
      module_name: z.string().min(1),
      options: options.optional().describe('Datastore options, ví dụ { RHOST: "10.0.0.5" }'),
    },
    run: ({ module_type, module_name, options: datastore }) =>
      rpcCall('module.check', [module_type, module_name, datastore || {}]),
  },
  {
    name: 'msf_module_run',
    description: 'Chạy một module tùy ý. CÓ THỂ khai thác — CHỈ hoạt động khi EXPLOIT_ENABLED=true.',
    guard: 'exploit',
    schema: {
      module_type: z.string().min(1),
      module_name: z.string().min(1),
      options: options.optional().describe('Datastore options'),
    },
    run: ({ module_type, module_name, options: datastore }) =>
      rpcCall('module.run', [module_type, module_name, datastore || {}]),
  },
  {
    name: 'msf_session_list_rpc',
    description: 'Liệt kê session đang hoạt động qua RPC session.list.',
    schema: {},
    run: () => rpcCall('session.list'),
  },
  {
    name: 'msf_console_create',
    description: 'Tạo msfconsole tương tác qua RPC console.create. Trả về console_id.',
    schema: {},
    run: () => rpcCall('console.create'),
  },
  {
    name: 'msf_console_read',
    description: 'Đọc output của msfconsole tương tác.',
    schema: { console_id: z.string().min(1) },
    run: ({ console_id }) => rpcCall('console.read', [console_id]),
  },
  {
    name: 'msf_console_write',
    description: 'Gửi lệnh vào msfconsole. CÓ THỂ khai thác — CHỈ hoạt động khi EXPLOIT_ENABLED=true.',
    guard: 'exploit',
    schema: { console_id: z.string().min(1), command: z.string().min(1) },
    run: ({ console_id, command }) => rpcCall('console.write', [console_id, `${command}\n`]),
  },
  {
    name: 'msf_console_destroy',
    description: 'Đóng msfconsole tương tác.',
    schema: { console_id: z.string().min(1) },
    run: ({ console_id }) => rpcCall('console.destroy', [console_id]),
  },

  /* ---------- Reporting ---------- */
  {
    name: 'msf_report_types',
    description: 'Liệt kê các loại báo cáo hợp lệ qua RPC pro.list_report_types.',
    schema: {},
    run: () => rpcCall('pro.list_report_types'),
  },
  {
    name: 'msf_report_list',
    description: 'Liệt kê báo cáo đã tạo trong một project.',
    schema: { workspace: z.string().min(1) },
    run: ({ workspace }) => rpcCall('pro.report_list', [workspace]),
  },
  {
    name: 'msf_report_start',
    description: 'Tạo báo cáo mới qua RPC pro.start_report. Trả về task_id.',
    schema: {
      workspace: z.string().min(1).describe('Tên workspace lấy dữ liệu'),
      name: z.string().min(1).describe('Tên báo cáo'),
      report_type: z.string().min(1).describe('audit | pentest | ... (xem msf_report_types)'),
      created_by: z.string().optional(),
      file_formats: z.array(z.string()).optional().describe('["pdf", "html", ...]'),
      options: options.optional(),
    },
    run: ({ workspace, name, report_type, created_by, file_formats, options: extra }) =>
      rpcCall('pro.start_report', [
        {
          workspace,
          name,
          report_type,
          created_by: created_by || 'mcp',
          file_formats: file_formats || ['pdf'],
          ...(extra || {}),
        },
      ]),
  },
  {
    name: 'msf_report_download',
    description: 'Tải báo cáo (dữ liệu trả về dạng base64).',
    schema: { report_id: z.union([z.string(), z.number().int()]) },
    run: ({ report_id }) => rpcCall('pro.report_download', [report_id]),
  },
  {
    name: 'msf_report_artifact_download',
    description: 'Tải một artifact của báo cáo (base64).',
    schema: { artifact_id: z.union([z.string(), z.number().int()]) },
    run: ({ artifact_id }) => rpcCall('pro.report_artifact_download', [artifact_id]),
  },
  {
    name: 'msf_report_delete',
    description: 'Xóa báo cáo qua RPC pro.report_delete.',
    schema: { report_id: z.union([z.string(), z.number().int()]) },
    run: ({ report_id }) => rpcCall('pro.report_delete', [report_id]),
  },

  /* ---------- Export ---------- */
  {
    name: 'msf_export_list',
    description: 'Liệt kê export của một project.',
    schema: { workspace: z.string().min(1) },
    run: ({ workspace }) => rpcCall('pro.export_list', [workspace]),
  },
  {
    name: 'msf_export_start',
    description: 'Tạo export (zip_workspace, xml, replay_scripts, pwdump, ...).',
    schema: {
      workspace: z.string().min(1),
      export_type: z.string().min(1),
      created_by: z.string().optional(),
      options: options.optional(),
    },
    run: ({ workspace, export_type, created_by, options: extra }) =>
      rpcCall('pro.start_export', [{ workspace, export_type, created_by: created_by || 'mcp', ...(extra || {}) }]),
  },
  {
    name: 'msf_export_download',
    description: 'Tải export (base64).',
    schema: { export_id: z.union([z.string(), z.number().int()]) },
    run: ({ export_id }) => rpcCall('pro.export_download', [export_id]),
  },

  /* ---------- Task ---------- */
  {
    name: 'msf_task_list',
    description: 'Liệt kê các task đang chạy (scan, exploit, report, ...).',
    schema: {},
    run: () => rpcCall('pro.task_list'),
  },
  {
    name: 'msf_task_status',
    description: 'Xem trạng thái một task.',
    schema: { task_id: z.union([z.string(), z.number().int()]) },
    run: ({ task_id }) => rpcCall('pro.task_status', [String(task_id)]),
  },
  {
    name: 'msf_task_log',
    description: 'Xem log của một task.',
    schema: { task_id: z.union([z.string(), z.number().int()]) },
    run: ({ task_id }) => rpcCall('pro.task_log', [String(task_id)]),
  },
  {
    name: 'msf_task_stop',
    description: 'Dừng một task.',
    schema: { task_id: z.union([z.string(), z.number().int()]) },
    run: ({ task_id }) => rpcCall('pro.task_stop', [String(task_id)]),
  },
  {
    name: 'msf_task_delete_log',
    description: 'Xóa log của một task.',
    schema: { task_id: z.union([z.string(), z.number().int()]) },
    run: ({ task_id }) => rpcCall('pro.task_delete_log', [String(task_id)]),
  },

  /* ---------- DB primitives ---------- */
  {
    name: 'msf_db_workspaces',
    description: 'Liệt kê workspace qua RPC db.workspaces.',
    schema: {},
    run: () => rpcCall('db.workspaces'),
  },
  {
    name: 'msf_db_report_host',
    description: 'Thêm/cập nhật host vào database qua RPC db.report_host.',
    schema: { data: options.describe('Hash chứa workspace, host, state, os_name, ...') },
    run: ({ data }) => rpcCall('db.report_host', [data]),
  },
  {
    name: 'msf_db_report_service',
    description: 'Thêm/cập nhật service qua RPC db.report_service.',
    schema: { data: options },
    run: ({ data }) => rpcCall('db.report_service', [data]),
  },
  {
    name: 'msf_db_report_vuln',
    description: 'Thêm/cập nhật vulnerability qua RPC db.report_vuln.',
    schema: { data: options },
    run: ({ data }) => rpcCall('db.report_vuln', [data]),
  },
  {
    name: 'msf_db_analyze_host',
    description: 'Gợi ý module phù hợp cho host qua RPC db.analyze_host.',
    schema: { data: options.describe('Hash chứa workspace, host, có thể có payload') },
    run: ({ data }) => rpcCall('db.analyze_host', [data]),
  },

  /* ---------- RPC tổng quát ---------- */
  {
    name: 'msf_rpc_call',
    description:
      'Gọi tùy ý một RPC method của Metasploit Pro với params dạng mảng. Các method liên quan exploit bị chặn khi EXPLOIT_ENABLED=false.',
    schema: {
      method: z.string().min(1).describe('Tên method, ví dụ pro.task_list hoặc pro.workspace_add'),
      params: z.array(z.any()).optional().describe('Tham số truyền sau API token'),
    },
    run: ({ method, params }) => {
      if (!config.exploitEnabled && EXPLOIT_METHOD_PATTERNS.some((pattern) => pattern.test(method))) {
        throw new Error(EXPLOIT_DISABLED_MESSAGE);
      }
      return rpcCall(method, params || []);
    },
  },
];

export function registerTools(server) {
  for (const tool of tools) {
    const handler = tool.guard === 'exploit' ? gated(tool.run) : safe(tool.run);
    server.tool(tool.name, tool.description, tool.schema, handler);
  }
  return tools.length;
}
