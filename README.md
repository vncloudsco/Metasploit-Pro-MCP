# Metasploit Pro MCP Server

MCP server dạng **HTTP (Streamable HTTP)** bao phủ toàn bộ tính năng của Metasploit Pro
thông qua **REST API v2** và **RPC API (MessagePack)**, chạy bằng **Node.js trong Docker Compose**,
xác thực bằng **Bearer token**, và có **công tắc bật/tắt exploit**.

> ⚠️ Chỉ sử dụng trên hệ thống bạn được phép kiểm thử. Công cụ này có khả năng chạy exploit thật.

---

## 1. Cấu trúc

```
.
├── .env                 # TOÀN BỘ cấu hình (API key, bearer token, cờ exploit, host...)
├── .env.example         # Template
├── docker-compose.yml   # Chạy service trên cổng 8080, mount host.docker.internal
├── Dockerfile
├── package.json
└── src/
    ├── index.js                 # Express + MCP Streamable HTTP + auth middleware
    ├── config.js                # Đọc .env
    ├── auth.js                  # Bearer token (timing-safe)
    ├── metasploit/
    │   ├── http.js              # HTTP/HTTPS thô, hỗ trợ self-signed TLS
    │   ├── restClient.js        # REST API v2 (header `token`)
    │   └── rpcClient.js         # RPC MessagePack `/api/1.0` (`[method, token, ...params]`)
    └── tools/index.js           # Toàn bộ tool MCP
```

## 2. Chạy

```bash
cp .env.example .env   # nếu chưa có
# chỉnh .env: MCP_AUTH_TOKEN, MSF_API_KEY, EXPLOIT_ENABLED, MSF_HOST...
docker compose up -d --build
docker compose logs -f
```

Kiểm tra nhanh:

```bash
curl http://localhost:8080/health
# {"status":"ok","service":"metasploit-pro-mcp",...,"exploitEnabled":false}

curl -i http://localhost:8080/mcp \
  -H "Authorization: Bearer <MCP_AUTH_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### Lưu ý về `MSF_HOST`

- Bạn cung cấp `https://localhost:3790`. Trong Docker, `localhost` là chính container,
  nên mặc định dùng `host.docker.internal` (đã khai báo `extra_hosts: host-gateway`).
- Nếu Metasploit Pro chạy **trong container/network khác**, đổi `MSF_HOST` thành IP/Host đó.
- Chứng chỉ mặc định của Metasploit Pro là self-signed → giữ `MSF_TLS_REJECT_UNAUTHORIZED=false`.

## 3. Xác thực Bearer

Mọi request tới `/mcp` phải có:

```
Authorization: Bearer <MCP_AUTH_TOKEN>
```

 Thiếu/sai token → `401` + header `WWW-Authenticate: Bearer ...`. So sánh bằng
 `crypto.timingSafeEqual`. Endpoint `/health` là công khai để docker healthcheck.

Cấu hình client (ví dụ Claude Desktop / VS Code / CLI):

```json
{
  "mcpServers": {
    "metasploit-pro": {
      "url": "http://<IP-CUA-SERVER>:8080/mcp",
      "headers": {
        "Authorization": "Bearer 62e7f92bcc5db790df3ba2fdd3296c1881e453c99ab2d5f0603c85c1cb1dbf48"
      }
    }
  }
}
```

## 4. Công tắc exploit (`EXPLOIT_ENABLED`)

| Giá trị | Hành vi |
|---|---|
| `false` (mặc định) | Mọi tool có khả năng khai thác trả về lỗi `EXPLOIT_DISABLED`; `msf_rpc_call` cũng chặn các method như `pro.start_exploit`, `module.run`, `console.write`, ... |
| `true` | Toàn bộ tính năng exploit được kích hoạt tự động (`auto`) |

Các tool bị khóa khi `false`: `msf_exploit_start`, `msf_module_run`, `msf_console_write`
(và mọi method exploit gọi qua `msf_rpc_call`). Các tool đọc dữ liệu, scan, report, task,
module search/check vẫn dùng bình thường.

Đổi giá trị trong `.env` rồi `docker compose up -d --force-recreate`.

## 5. Danh mục tool (56 tools)

| Nhóm | Tools |
|---|---|
| Hệ thống | `msf_health`, `msf_core_version`, `msf_core_about` |
| Project | `msf_workspaces_list`, `msf_workspace_get`, `msf_workspace_add`, `msf_workspace_update`, `msf_workspace_delete` |
| Dữ liệu (REST) | `msf_hosts_list`, `msf_host_get`, `msf_services_list`, `msf_service_get`, `msf_vulns_list`, `msf_vuln_get`, `msf_sessions_list`, `msf_session_get`, `msf_notes_list`, `msf_note_get`, `msf_web_sites_list`, `msf_web_forms_list`, `msf_web_pages_list`, `msf_web_vulns_list`, `msf_rest_get` |
| Scan / Import | `msf_scan_start` (`pro.start_discover`), `msf_scan_bruteforce_start`, `msf_scan_import_start` |
| Exploit 🔒 | `msf_exploit_start` (`pro.start_exploit`), `msf_module_run`, `msf_console_write` |
| Module | `msf_module_search`, `msf_module_info`, `msf_module_check`, `msf_session_list_rpc`, `msf_console_create`, `msf_console_read`, `msf_console_destroy` |
| Report | `msf_report_types`, `msf_report_list`, `msf_report_start`, `msf_report_download`, `msf_report_artifact_download`, `msf_report_delete` |
| Export | `msf_export_list`, `msf_export_start`, `msf_export_download` |
| Task | `msf_task_list`, `msf_task_status`, `msf_task_log`, `msf_task_stop`, `msf_task_delete_log` |
| DB primitives | `msf_db_workspaces`, `msf_db_report_host`, `msf_db_report_service`, `msf_db_report_vuln`, `msf_db_analyze_host` |
| Tổng quát | `msf_rpc_call` (gọi bất kỳ RPC method nào, có kiểm soát exploit) |

Dữ liệu nhị phân (file báo cáo/export) được trả về dưới dạng base64 (`__base64`).

## 6. Ví dụ dùng tools

```text
1) msf_workspace_add  { "name": "PentestDemo", "boundary": "192.168.1.0/24" }
2) msf_scan_start     { "workspace": "PentestDemo", "ips": ["192.168.1.0/24"],
                        "ports": "1-65535", "fast_detect": true }
3) msf_task_status    { "task_id": "<task_id từ bước 2>" }
4) msf_hosts_list     { "workspace_id": 2 }
5) msf_report_start   { "workspace": "PentestDemo", "name": "report_1",
                        "report_type": "audit", "file_formats": ["pdf"] }
6) msf_report_list    { "workspace": "PentestDemo" }
```

## 7. Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `MCP_HOST` | `0.0.0.0` | Interface lắng nghe |
| `MCP_PORT` | `8080` | Cổng HTTP MCP |
| `MCP_PATH` | `/mcp` | Đường dẫn endpoint MCP |
| `MCP_AUTH_TOKEN` | — | Bearer token client phải gửi (bắt buộc) |
| `EXPLOIT_ENABLED` | `false` | Công tắc exploit |
| `MSF_SCHEME` | `https` | Scheme tới Metasploit |
| `MSF_HOST` | `host.docker.internal` | Host Metasploit Pro |
| `MSF_PORT` | `3790` | Cổng Metasploit Pro |
| `MSF_API_KEY` | — | API key Metasploit Pro (bắt buộc) |
| `MSF_TLS_REJECT_UNAUTHORIZED` | `false` | Bỏ qua cert self-signed |
| `MSF_REST_BASE` | `/rest_api/v2` | Base path REST API |
| `MSF_RPC_URI` | `/api/1.0` | Đường dẫn RPC MessagePack |
| `MSF_REQUEST_TIMEOUT_MS` | `30000` | Timeout request |

## 8. Tài liệu tham khảo

- https://docs.rapid7.com/metasploit/rest-api/
- https://docs.rapid7.com/metasploit/rest-api-endpoints/
- https://docs.rapid7.com/metasploit/rpc-api/
- https://docs.rapid7.com/metasploit/pro-feature-api/
- https://docs.rapid7.com/metasploit/pro-task-api/
