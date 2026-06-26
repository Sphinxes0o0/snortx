# REST API

Server: `./snortx-api serve --addr :8080` (or `:8443` with TLS).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/rules/upload` | Upload rules file (multipart/form-data, field `rules`) |
| POST | `/api/v1/rules/parse` | Parse rules text |
| POST | `/api/v1/tests/run` | Run full test pipeline |
| GET | `/api/v1/tests/results?id=<id>` | Get test results (paginated) |
| DELETE | `/api/v1/tests/results?id=<id>` | Delete test results |
| GET | `/api/v1/health` | Health check (bypasses auth) |

## Middleware stack (applied in order)

1. **Logging** — request log
2. **Recovery** — catches panics, returns 500 (server does NOT crash)
3. **Auth** — Bearer token via `Authorization` header; `health` endpoint bypasses
4. **CORS** — `Access-Control-Allow-Origin` matches `cors_allowed_origins` config; supports `*` wildcard
5. **Rate limit** — per-IP, tracks via `X-Forwarded-For` if present, resets per second

## Request / response shapes

### POST `/api/v1/rules/parse`

```json
// Request
{ "rules": "alert tcp any any -> any any (content:\"test\"; sid:1;)" }

// Response
{
  "rules":  [ /* ParsedRule objects */ ],
  "count":  1,
  "errors": [ /* ParseError objects, may be empty */ ]
}
```

### POST `/api/v1/tests/run`

```json
// Request
{
  "rules":     "alert tcp any any -> any any (content:\"test\"; sid:1;)",
  "format":    "both",          // "json" | "html" | "both"
  "interface": "lo0"
}

// Response
{
  "test_run_id":  "run_1234567890",
  "status":       "completed",
  "total":        1,
  "success":      1,
  "failed":       0,
  "message":      "JSON: ./output/run_1234567890.json, HTML: ./output/run_1234567890.html",
  "json_path":    "./output/run_1234567890.json",
  "html_path":    "./output/run_1234567890.html",
  "report_errors": []
}
```

### GET `/api/v1/tests/results?id=<id>` (paginated)

```
GET /api/v1/tests/results?id=run_1234567890&page=1&page_size=50
```

| Param | Default | Max | Notes |
|-------|---------|-----|-------|
| `page` | 1 | — | Page number |
| `page_size` | 50 | 100 | Omit both → full result (backward compatible) |

```json
// Response
{
  "test_run_id":    "run_1234567890",
  "total_results":  100,
  "page":           1,
  "page_size":      50,
  "total_pages":    2,
  "results": [
    {
      "rule_sid":       1,
      "rule_msg":       "TEST",
      "protocol":       "tcp",
      "packets_gen":    1,
      "packets_sent":   1,
      "pcap_path":      "./output/rule_1.pcap",
      "status":         "success",
      "duration":       "1.234ms"
    }
  ]
}
```

### DELETE `/api/v1/tests/results?id=<id>`

```json
{ "status": "deleted", "test_run_id": "run_1234567890" }
```

## Persistence

- Result JSON written to `output/test_runs/<test_run_id>.json` on completion
- Loaded into memory on server startup
- In-memory store for fast access
- API also writes reports to `output/report_<test_run_id>.{json,html}`

## CLI vs API test flow

| Aspect | CLI `test` | API `POST /tests/run` |
|--------|------------|----------------------|
| Engine workers | `-w` flag | Always `NumCPU` |
| Output PCAPs | `output/rule_<sid>.pcap` | `output/<test_run_id>/rule_<sid>.pcap` |
| Test run ID | Not exposed | Returned as `test_run_id` |
| Reports | Per-run in output root | Per-run in output root |
| Persistence | Not persisted | Persisted to `test_runs/` |

## TLS

```yaml
api:
  tls_enabled: true
  tls_cert:    "/path/to/cert.pem"
  tls_key:     "/path/to/key.pem"
```

Server timeouts: 30s read, 30s write (both plaintext and TLS).

## Auth

Bearer token. Disabled by default; enable via `api.auth.enabled: true` + `api.auth.token: "..."`.

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/health
```

Health endpoint bypasses auth.

## Test result status values

| Status | Meaning |
|--------|---------|
| `success` | Packet generated AND PCAP written successfully |
| `failed` | Generation failed, PCRE mismatch, or send error |

## Rate limiting

Per-IP, per-second reset. Default 100 req/s (configurable via `api.rate_limit`). Uses `X-Forwarded-For` if present.

## Error responses

| Code | Cause |
|------|-------|
| 400 | Malformed JSON / missing fields |
| 401 | Missing or bad auth token (when enabled) |
| 404 | Unknown `id` on GET / DELETE |
| 429 | Rate limit exceeded |
| 500 | Server-side error (caught by recovery middleware) |