# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

snortx is a Go-based tool that parses Snort rules, generates matching network packets, records them to PCAP files, and generates HTML/JSON test reports.

## Build Commands

```bash
go build -o snortx ./cmd/cli
go build -o snortx-api ./cmd/api
go test ./...                      # Run all tests
go test ./internal/rules -v        # Run tests for a specific package
go test -run TestParser ./...      # Run tests matching a pattern
go mod tidy
```

## Parsing Methods

| Method | Input | Use Case |
|--------|-------|----------|
| `ParseFile(path)` | File path | CLI commands, API file upload |
| `ParseMulti(text)` | Raw text string | API `/parse` endpoint, multiline rules |

Both return `*ParseResult` with partial results on error—parse errors in one rule do not abort the entire batch.

## Config Flag

`--config` is a global flag on `snortx` root (not subcommand-specific). Place before or after the subcommand:

```bash
./snortx --config myconfig.yaml test rules.rules
./snortx test rules.rules --config myconfig.yaml   # also works
```

## Running

```bash
./snortx version
./snortx parse examples/sample.rules
./snortx generate examples/sample.rules
./snortx lint examples/sample.rules
./snortx test examples/sample.rules -o /tmp/output
./snortx batch rules1.rules rules2.rules
./snortx benchmark rules.rules --iterations 1000
./snortx diff rules1.rules rules2.rules
./snortx-api serve --addr :8080
```

## Quick Reference

| Task | Command |
|------|---------|
| Parse and validate rules | `./snortx lint rules.rules` |
| Generate test packets | `./snortx generate rules.rules` |
| Run full test + reports | `./snortx test rules.rules -o ./output` |
| Test with custom config | `./snortx --config snortx.yaml test rules.rules` |
| Run API server | `./snortx-api serve --addr :8080` |
| View parsed rules as JSON | `./snortx parse rules.rules --json` |
| Test on specific interface | `./snortx test rules.rules -i eth0 --mode inject` |
| Batch test multiple files | `./snortx batch rules1.rules rules2.rules -w 8` |

## CLI Commands

| Command | Description |
|---------|-------------|
| `parse <file>` | Parse Snort rules from file |
| `generate <file>` | Generate packets from rules (without sending) |
| `lint <file>` | Validate rules without generating packets |
| `test <file>` | Run full test pipeline (parse → generate → PCAP) |
| `batch <files...>` | Run tests on multiple rule files in parallel |
| `benchmark <file>` | Performance benchmark on rule file |
| `diff <file1> <file2>` | Compare two rule files (shows [+SID] added, [-SID] removed, [~SID] modified by content) |
| `repl` | Interactive REPL for rule testing (parse, generate, or enter rule directly) |
| `serve` | Start the REST API server (snortx-api only) |
| `version` | Show version information |

**Note**: `serve` is not a `snortx` CLI command—use `snortx-api serve` for the REST API server.

### REPL Commands

```
parse <rule>      # Parse a rule and show details
generate <rule>   # Generate packets for a rule
<rule text>       # Direct rule input (parsed then shown)
help             # Show help
exit, quit        # Exit REPL
```

## Key Flags

```bash
# Test command
./snortx test rules.rules -o ./output        # Output directory (default: ./output)
./snortx test rules.rules -w 4               # Worker count (default: auto/NumCPU)
./snortx test rules.rules -r json            # Report format: json, html, both (default: both)
./snortx test rules.rules -i eth0            # Network interface (default: lo0)
./snortx test rules.rules --mode pcap        # Send mode: pcap, inject, both
# Note: --config is a global flag, place before or after subcommand

# Parse command
./snortx parse rules.rules --json            # Output rules as JSON

# Lint command
./snortx lint rules.rules                   # Validate rules (no packet generation)

# Batch command
./snortx batch rules1.rules rules2.rules -w 4  # Parallel workers (default: 4)

# Benchmark command
./snortx benchmark rules.rules -n 1000       # Iterations (default: 1000)
./snortx benchmark rules.rules --warmup      # Run warmup before benchmark

# Diff command
./snortx diff rules1.rules rules2.rules     # Compare two rule files

# Serve command
./snortx-api serve --addr :8080             # Listen address
./snortx-api serve --auth-token TOKEN       # Bearer token authentication
./snortx-api serve --cors "*,example.com"    # CORS origins
./snortx-api serve --rate-limit 100         # Requests per second (default: 100)
```

## Architecture

```
cmd/cli, cmd/api     → Entry points (cobra CLI, gorilla/mux HTTP)
internal/rules       → Snort rule parsing (Parser), models (ParsedRule, ContentMatch, PCREMatch)
internal/packets     → Packet generation (Generator) and PCAP writing (Sender)
internal/engine      → Worker pool: buffered channels for rules/results, PCRE regex caching
internal/reports     → JSON and HTML report generation
internal/api         → HTTP server with auth, CORS, rate limiting
pkg/config           → Configuration structs and YAML loading
```

**Data flow**: Parser → Engine (worker pool with N goroutines) → Generator (creates packets) → Sender (writes PCAP). Note: `generate` command uses Generator directly without PCAP recording; `test` runs the full pipeline.

**Module**: `github.com/user/snortx`

**Engine design**: Uses sync.WaitGroup for worker coordination, sync.Mutex for thread-safe result aggregation, and buffered channels (`ruleChan`, `resultChan`) sized at `workerCount*2`. PCRE patterns are cached in a map keyed by pattern string.

**Protocol mapping**: Application-layer protocol specifiers (http, https, ftp, ssh, smtp, dns, etc.) are transparently mapped to TCP transport in `parseHeader()`.

## Key Interfaces

- `rules.Parser`: Parses Snort rules → `*ParsedRule`
- `packets.Generator`: Generates `gopacket.Packet` from `*ParsedRule`
- `packets.Sender`: Writes packets to PCAP files
- `engine.Engine`: Worker pool (NumCPU workers by default) with buffered channels

## Parse Error Phases

When rule parsing fails, the error phase indicates where the failure occurred:

| Phase | Description |
|-------|-------------|
| `format` | Malformed rule structure (missing parentheses, etc.) |
| `header` | Invalid action, protocol, or direction |
| `content` | Invalid content match specification |
| `pcre` | Malformed PCRE regex pattern |
| `flow` | Invalid flow option value |
| `rule_id` | Invalid gid/sid/rev values |
| `vlan` | Invalid VLAN ID |

**ParseResult**: `ParseFile` and `ParseMulti` return `*ParseResult` with `Rules` (successfully parsed) and `Errors` (per-rule parse failures with line number and phase).

Rules that fail parsing are skipped but do not cause the entire file to fail—`ParseFile` returns partial results with `Errors` slice populated.

### Parse Error Example

```
line 5, col 15 (header): invalid direction '->>>', expected '->' or '<>'
```

### ParseResult and SendResult Fields

**ParsedRule** key fields:
- `RawText` — Original rule text as provided
- `RuleID` — GID, SID, REV
- `Protocol` — After app protocol mapping (e.g., "http" → "tcp")
- `Contents`, `PCREMatches` — Match specifications

**ParseResult**:
- `Rules []*ParsedRule` — Successfully parsed rules
- `Errors []*ParseError` — Parse failures with Line, CharOffset, Phase, Message, RuleText

### Empty Rule Handling

Rules that parse successfully but have no `content:`, `pcre:`, or other payload-generating options will still produce packets with a default payload of `"test payload"`.

**SendResult** (from `Sender.SendAndRecord`):
- `RuleSID`, `RuleMsg`, `Protocol` — Rule identification
- `PacketsGen` — Packets generated by Engine
- `PacketsSent` — Packets injected to interface (if ModeInject/Both)
- `PacketsWritten` — Packets written to PCAP
- `PCAPPath` — Path to PCAP file
- `Status` — "success" or "failed"
- `Error` — Error message if failed
- `Duration` — Processing time

## Lint Validation

`lint` performs static analysis without packet generation:
- Generates packets to verify constructibility
- Validates PCRE patterns for syntax errors
- Warns about potentially problematic patterns (negated content, nocase with multiple contents)
- Reports unsupported PCRE modifiers (R, U)
- **PCRE static analysis** (`AnalyzePCRE`):
  - Detects nested quantifiers (ReDoS risk)
  - Detects overlapping alternation patterns
  - Detects unanchored patterns with trailing quantifiers
  - Detects large character classes
  - Validates Go regex compatibility (some PCRE features unsupported)

## Supported Protocols

TCP, UDP, ICMP, IP (IPv4/IPv6), SCTP, ARP, DNS
Application protocols mapped to TCP: HTTP, HTTPS, FTP, SSH, SMTP, DNS, SIP, SMB, etc.

### DNS Protocol

DNS rules use UDP transport. The generator builds a DNS query packet with:
- Transaction ID: `0x0001`
- Flags: Standard query (QR=0)
- Question: 1 query for the domain in content (or `example.com` default)
- Query type: A (1), Query class: IN (1)

### SCTP Protocol

SCTP packets are generated with:
- IPv4 or IPv6 based on address format
- SCTP chunk with source/destination ports
- Payload from content/PCRE

### ARP Protocol

ARP packets are generated as Ethernet + ARP layers:
- ARP Request: Broadcast (`ff:ff:ff:ff:ff:ff`) with sender IP/target IP
- Generator does not differentiate request vs reply—payload is built from rule content

## Content Match Format

Snort content matches support:
- **String content**: `content:"test"` or `content:!"test"` (negated)
- **Hex content**: `content:"|48 61 6c 6c 6f|"` (ASCII "Hello")
- **Modifiers**: `nocase`, `rawbytes`, `fast_pattern`, `offset:N`, `depth:N`, `distance:N`, `within:N`
- **Negation**: `content:!"pattern"` or `content:!pattern`

### fast_pattern

When a rule has multiple content matches, `fast_pattern` selects which one to use for fast matching:

```
alert tcp any any -> any any (
  content:"first";
  content:"second";
  fast_pattern;
  content:"third";
  sid:1;
)
```

Only one content can be marked `fast_pattern`. snortx stores this in `ParsedRule.Options["fast_pattern"]` but does not implement fast pattern optimization.

## PCRE Format

PCRE patterns follow Snort syntax: `/pattern/modifiers`

Supported modifiers: `i` (case-insensitive), `m` (multiline), `s` (dotall)
Unsupported but detected: `R` (PCRE_MATCH_END), `U` (PCRE_UNGREEDY)

The parser extracts literal strings from PCRE for packet payload generation when no explicit content match exists.

**nopcre**: Option `nopcre` or `no_pcre` disables PCRE matching for a rule (stored in Options).

## Flow Options

The `flow:` option controls TCP stream handling:

| Value | Description |
|-------|-------------|
| `established` | Match only established connections |
| `to_server` | Match client → server traffic |
| `to_client` | Match server → client traffic |
| `from_server` | Match server → client (alias for to_client) |
| `from_client` | Match client → server (alias for to_server) |

**Direction**: `->` (unidirectional), `<>` (bidirectional). The parser stores `Direction` and sets `IsBidirectional: true` when `<>`.
| `only_stream` | Match only reassembled stream |
| `no_stream` | Match only un reassembled packets |

Values can be combined: `established,to_server`

## Byte Test/Jump

Byte test and byte jump are content modifiers for binary protocol analysis:

**byte_test**: `<count>, <operator>, <value>, <offset>[, relative][, big][, little][, string][, negate]`
- `count`: number of bytes to extract
- `operator`: `<`, `>`, `=`, `!`, `<=`, `>=`
- `value`: value to compare against
- `offset`: bytes from reference point

**byte_jump**: `<count>, <offset>[, relative][, big][, little][, string][, align <n>][, post_offset <n>]`
- Extracts bytes and jumps (adds) offset for relative matching

## Rule ID Constraints

GID/SID/REV values have valid ranges:

| Field | Valid Range |
|-------|-------------|
| GID | 0 - 999,999,999 |
| SID | 0 - 999,999,999 |
| REV | 0 - 999 |

GID 1 is standard for Snort rules; GID 3 is used by Shared Objects (SO rules).

**Default rule ID**: If no sid/gid/rev is specified, defaults are GID=1, SID=0, REV=1.

## Variable Expansion

The generator supports variable expansion from the config. Default variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `$HOME_NET` | `10.0.0.0/24` | Home network CIDR |
| `$EXTERNAL_NET` | `any` | External network |
| `$HTTP_SERVERS` | `any` | HTTP servers |
| `$SMTP_SERVERS` | `any` | SMTP servers |
| `$DNS_SERVERS` | `any` | DNS servers |
| `$SSH_SERVERS` | `any` | SSH servers |

Variables are expanded in source/destination IP and port fields. `any` resolves to default IP/port.

### Config Variable Merging

Config vars are merged with defaults—config file vars override defaults, but defaults not in config are preserved:

```yaml
# Config with only $HOME_NET
vars:
  $HOME_NET: "192.168.0.0/16"

# Result: $HOME_NET="192.168.0.0/16", others use defaults
```

### Default Payload

When a rule has neither `content:` nor `pcre:`, the generator uses `"test payload"` as the packet payload.

### PCRE Literal Extraction

When only PCRE is specified (no content), the generator extracts literals:
1. First tries quoted strings: `"GET"` from `/GET/`
2. Then hex escapes: `\x47\x45\x54` from `/\x47\x45\x54/`
3. Strips PCRE constructs (quantifiers, groups) and tries again
4. Falls back to default payload if extraction fails

### Port Handling

| Port Format | Example | Behavior |
|-------------|---------|----------|
| Single port | `80` | Use as-is |
| Port range | `8000:9000` | Use first port (8000) |
| Port list | `80,443,8080` | Use first port (80) |
| Variable | `$HTTP_PORTS` | Resolved from vars config |
| `any` | `any` | Default port (80 for dst, 12345 for src) |

- **CIDR notation** (e.g., `192.168.1.0/24`): First IP of the subnet is used
- **Negated networks** (e.g., `!10.0.0.0/8`): Treated as `any` (resolved to default IP); negation is stored in the rule text but not semantically interpreted
- **IPv6**: Full IPv6 addresses are used directly; unsupported formats fall back to default IP
- **any/any**: Resolved to generator's default src/dst IP

## Configuration

YAML config via `--config` flag. All fields are optional—defaults are applied when omitted.

```yaml
app:
  name: snortx
  version: "1.0.0"

engine:
  worker_count: 0        # 0 = auto (NumCPU)
  rule_timeout: 30s
  total_timeout: 5m
  output_dir: ./output
  generator:
    default_src_ip: "192.168.1.100"
    default_dst_ip: "10.0.0.1"
    default_src_port: 12345
    default_dst_port: 80
    vars:
      $HOME_NET: "10.0.0.0/24"    # Variable expansion
      $EXTERNAL_NET: "any"
      $HTTP_SERVERS: "$HOME_NET"
  sender:
    interface: lo0
    snap_len: 65536
    timeout: 1s

api:
  address: ":8080"
  tls_enabled: false
  tls_cert: ""
  tls_key: ""
  cors_allowed_origins: ["*"]
  rate_limit: 100
  auth:
    enabled: false
    token: ""

cli:
  verbose: false
  json: false
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/rules/upload` | Upload rules file |
| POST | `/api/v1/rules/parse` | Parse rules text |
| POST | `/api/v1/tests/run` | Run test pipeline |
| GET | `/api/v1/tests/results?id=<id>` | Get test results |
| DELETE | `/api/v1/tests/results?id=<id>` | Delete test results |
| GET | `/api/v1/health` | Health check |

### API Request/Response Bodies

**POST /api/v1/rules/parse**
```json
// Request
{ "rules": "alert tcp any any -> any any (content:\"test\"; sid:1;)" }

// Response
{ "rules": [...], "count": 1, "errors": [] }
```

**POST /api/v1/tests/run**
```json
// Request
{
  "rules": "alert tcp any any -> any any (content:\"test\"; sid:1;)",
  "format": "both",      // json, html, both
  "interface": "lo0"
}

// Response
{
  "test_run_id": "run_1234567890",
  "status": "completed",
  "total": 1,
  "success": 1,
  "failed": 0,
  "message": "JSON: ./output/run_1234567890.json, HTML: ./output/run_1234567890.html",
  "json_path": "./output/run_1234567890.json",
  "html_path": "./output/run_1234567890.html",
  "report_errors": []
}
```

**DELETE /api/v1/tests/results?id=<id>**
```json
// Response
{
  "status": "deleted",
  "test_run_id": "run_1234567890"
}
```

### CLI vs API Test Flow

| Aspect | CLI `test` | API `POST /tests/run` |
|--------|------------|----------------------|
| Engine workers | Configurable via `-w` | Always NumCPU |
| Output PCAPs | `output/rule_<sid>.pcap` | `output/<test_run_id>/rule_<sid>.pcap` |
| Test run ID | Not exposed to user | Returned as `test_run_id` |
| Reports | Per-run in output root | Per-run in output root |
| Persistence | Not persisted | Persisted to test_runs/ |

### API File Upload

`POST /api/v1/rules/upload` accepts `multipart/form-data` with a `rules` file field. The file content is parsed with `ParseMulti()`.

### Rule Ordering

Rules are processed in the order they appear in the file. For batch processing, file order is preserved but concurrent workers process rules within each file in parallel.
```json
// Response (paginated)
{
  "test_run_id": "run_1234567890",
  "total_results": 100,
  "page": 1,
  "page_size": 50,
  "total_pages": 2,
  "results": [
    {
      "rule_sid": 1,
      "rule_msg": "TEST",
      "protocol": "tcp",
      "packets_gen": 1,
      "packets_sent": 1,
      "pcap_path": "./output/rule_1.pcap",
      "status": "success",
      "duration": "1.234ms"
    }
  ]
}
```

### API Result Persistence

Test run results are persisted to `output/test_runs/<test_run_id>.json` and loaded on server startup. The API maintains results in memory for fast access.

### API Middleware Stack

Middleware is applied in this order: logging → recovery → auth → CORS → rate limit

- **Recovery**: Panics are caught and return 500 (server does not crash)
- **Auth**: Bearer token in `Authorization` header; health endpoint bypasses auth
- **CORS**: Returns `Access-Control-Allow-Origin` matching config; supports `*` wildcard
- **Rate limit**: Per-IP tracking (uses `X-Forwarded-For` if present); resets per second

### API Pagination

`GET /api/v1/tests/results` supports pagination:
- `page`: Page number (default 1)
- `page_size`: Results per page (default 50, max 100)
- Omit both to get full result (backward compatible)

### API TLS

TLS is optional. Enable in config:
```yaml
api:
  tls_enabled: true
  tls_cert: "/path/to/cert.pem"
  tls_key: "/path/to/key.pem"
```

Server timeouts: 30s read, 30s write.

## Test Result Status

| Status | Description |
|--------|-------------|
| `success` | Packet generated and PCAP written successfully |
| `failed` | Generation failed, PCRE mismatch, or send error |

## Test Run Lifecycle

1. **TestRunResult creation**: `test_run_id = run_<unix_timestamp>`, `StartedAt = now`
2. **Rule processing**: Rules flow through engine workers (parallel)
3. **Result aggregation**: Main goroutine collects results via `resultChan`
4. **Completion**: `CompletedAt = now`, counts finalized
5. **Report generation**: JSON and/or HTML report written to output directory
6. **API persistence**: Result saved to `test_runs/<test_run_id>.json`

### Engine Processing Flow

1. Rules are sent through buffered `ruleChan` to worker goroutines
2. Each worker calls `Generator.Generate()` → if error, result is "failed"
3. If rule has PCRE matches, `Engine.validatePCRE()` checks payload against Go-compiled regex
4. On PCRE mismatch, result is "failed"
5. `Sender.SendAndRecord()` writes to PCAP and optionally injects
6. Results flow through buffered `resultChan` back to main goroutine
7. Main goroutine aggregates results with mutex protection

### Engine Reuse

Each `Engine.Run()` call creates fresh channels and resets `testRunResult` with a new `test_run_id` (format: `run_<unix_timestamp>`). The Engine can be reused for multiple test runs sequentially—channels are recreated on each Run call.

### Generator Shared State

The `Generator` is safe for concurrent use across multiple Engine workers. It contains only configuration (`Vars`, `DefaultSrcIP`, etc.) and no per-request state.

### PCRE Validation

PCRE validation occurs after packet generation:
- Pattern is compiled to Go regex (cached in `pcreCache` map)
- Modifiers `i`, `m`, `s` are converted to Go prefix flags (`(?i)`, `(?m)`, `(?s)`)
- Payload from first generated packet is matched
- If no payload (empty packet), validation fails

**PCRE cache**: The cache is per-Engine instance. Patterns are keyed by the Go-prefixed string (e.g., `(?i)GET `). Cache persists across `Run()` calls within the same process.

**PCRE cache eviction**: Max 1000 entries, auto-evicts oldest half when exceeding 1200 entries to prevent memory growth.

### Same IP Rules

The `sameip` option stores `sameip: "true"` in Options. The generator uses the same expanded IP for both src and dst when building packets.

## Report Formats

**JSON report** — Machine-readable, contains full `TestRunResult` with all rule results, timing, and PCAP paths. Filename: `report_<test_run_id>.json`

**HTML report** — Human-readable dashboard with:
- Summary statistics (total, success, failed, success rate)
- Protocol breakdown (per-protocol success/failure counts)
- Per-rule table with SID, message, protocol, packets, status, error, and PCAP link (relative path to `./rule_<sid>.pcap`)
- Filename: `report_<test_run_id>.html`

## Benchmark Metrics

The benchmark command reports:
- **Parsing**: time per file iteration, iterations/sec
- **Packet generation**: time per rule, time per packet, packets/sec
- **Memory**: Alloc delta, TotalAlloc delta, Mallocs delta (after GC)

### Benchmark Warmup

When `--warmup` is specified, one iteration runs without timing before the measured iterations begin. This primes CPU caches, regex compilation, and JIT-like optimizations.

## Implementation Notes

- **Packet construction**: Uses gopacket with `SerializeLayers` (Ethernet + IP + L4 + Payload)
- **PCAP writing**: Uses pcapgo; CaptureInfo requires correct CaptureLength/Length
- **Worker pool**: Buffered channels (capacity = WorkerCount*2), wait groups for coordination
- **PCRE validation**: Compiles to Go regex, cached by pattern; payload validated for `/pattern/modifiers` match
- **Variable expansion**: Generator expands `$HOME_NET`, `$EXTERNAL_NET`, etc. from configured vars map
- **Batch parallelism**: Uses a semaphore channel (size = worker count) to limit concurrent file processing; each file gets its own Engine instance with shared Generator but dedicated Sender
- **Batch summary**: Reports total rules, success, failed, and success rate after all files complete
- **Batch reports**: Each file gets its own HTML/JSON report generated in the output directory
- **Bidirectional rules**: Generate two packets (forward + reverse) for `<>` direction rules
- **Send modes**:
  - `pcap` — Write packets to PCAP file only (default for CLI `test`)
  - `inject` — Inject packets to network interface using pcap
  - `both` — Write to PCAP and inject simultaneously

## Output Structure

```
output/
├── rule_<sid1>.pcap      # One PCAP per rule SID
├── rule_<sid2>.pcap
├── ...
├── test_runs/
│   └── <test_run_id>.json    # Persisted test results (API only)
├── report_<test_run_id>.json  # JSON report
└── report_<test_run_id>.html  # HTML report
```

**Note**: CLI `test` writes PCAPs to `output/` directly as `rule_<sid>.pcap`. API runs write to `<outputDir>/test_runs/`. Report filenames include the `test_run_id` (e.g., `report_run_1234567890.json`).

### Output Directory Creation

The output directory is created automatically if it does not exist (`os.MkdirAll`). PCAP files overwrite existing files with the same SID.

### CLI Test Multiple Rules

When a rule file contains multiple rules, each rule gets its own PCAP file named `rule_<sid>.pcap`. If two rules share the same SID, the second overwrites the first (SID should be unique per ruleset).

## Rule Examples

```snort
# Basic TCP content match
alert tcp any any -> any any (msg:"TCP test"; content:"test"; sid:1; rev:1;)

# HTTP GET request
alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET"; nocase; sid:2; rev:1;)

# PCRE regex match
alert tcp any any -> any any (msg:"PCRE match"; content:"GET /"; pcre:"/GET \//"; sid:3; rev:1;)

# Hex content (ASCII "Hello")
alert tcp any any -> any any (msg:"Hex content"; content:"|48 65 6c 6c 6f|"; sid:4; rev:1;)

# Variable expansion
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Variable"; content:"test"; sid:5; rev:1;)

# Bidirectional traffic
alert tcp any any <> any any (msg:"Bidirectional"; content:"test"; sid:6; rev:1;)

# With flow control
alert tcp any any -> any any (msg:"Established"; content:"test"; flow:established; sid:7; rev:1;)

# VLAN tagged
alert tcp any any -> any any (msg:"VLAN"; content:"test"; vlan:100; sid:8; rev:1;)
```

## HTTP Modifiers

HTTP-specific content modifiers for inspecting HTTP traffic:

| Modifier | Description |
|----------|-------------|
| `http_uri` | Match in URI |
| `http_cookie` | Match in Cookie header |
| `http_header` | Match in any HTTP header |
| `http_method` | Match HTTP method (GET, POST, etc.) |
| `http_stat_code` | Match status code |
| `http_stat_msg` | Match status message |
| `http_client_body` | Match HTTP request body |
| `http_raw_uri` | Match raw URI (before normalization) |
| `http_raw_header` | Match raw headers |

The `uricontent:` option is equivalent to `content:"..."; http_uri;`.

**uricontent vs http_uri**: Both match in the URI, but `uricontent` is the older syntax. The parser stores both in `Options["uricontent"]` and `Options["http_uri"]` respectively.

HTTP modifiers are stored in both `ParsedRule.Options` (as key-value strings) and `ParsedRule.HTTPModifiers` (as structured `HTTPModifier` structs with Type, Modifies, Content fields).

## Detection Filters

Threshold and rate filtering for alert management:

**threshold**: `type <type>, track <by_src|by_dst>, count <n>, seconds <n>`
- `type`: `limit` (once per interval), `threshold` (every N), `both`, `suppress`

**rate_filter**: `type filter, track <by>, count <n>, seconds <n>, new_action <drop|alert|...>`

**detection_filter**: `track <by>, count <n>, seconds <n>` — rate limit detection

These are parsed into `ParsedRule.Threshold`, `ParsedRule.RateFilter`, and `ParsedRule.DetectionFilter` structs respectively, but do not affect snortx behavior.

## DSize Option

Payload size matching: `dsize:<n>` or `dsize:<min><><max>`

| Format | Description |
|--------|-------------|
| `dsize:100` | Exactly 100 bytes |
| `dsize:>100` | Greater than 100 |
| `dsize:<200` | Less than 200 |
| `dsize:50<>200` | Between 50 and 200 |

## Flowbits

Stateful flow tracking for rule chaining:

| Operation | Description |
|-----------|-------------|
| `flowbits:set,name` | Set a flowbit |
| `flowbits:isset,name` | Check if set |
| `flowbits:isnotset,name` | Check if not set |
| `flowbits:toggle,name` | Toggle state |
| `flowbits:unset,name` | Clear a flowbit |
| `flowbits:noalert` | Suppress alert for this match |

Flowbits are stored in `ParsedRule.Flowbits` as `[]Flowbit` with `Op` and `Name` fields. snortx implements flowbit state tracking across rules within a test run.

**Flowbit processing**: Rules are evaluated in order, with flowbit conditions checked before rule processing. On successful match, flowbits are set/toggled/unset. If a flowbit condition (isset/isnotset) is not met, the rule fails with "flowbit condition not met".

## IP/ICMP Options

| Option | Description |
|--------|-------------|
| `ttl:<n>` | Match TTL |
| `tos:<n>` | Match Type of Service |
| `ip_id:<n>` | Match IP ID field |
| `dsize:<n>` | Match payload size |
| `icmp_id:<n>` | Match ICMP ID (echo) |
| `icmp_seq:<n>` | Match ICMP sequence |
| `itype:<n>` | Match ICMP type |
| `icode:<n>` | Match ICMP code |

## IP Protocol Matching

| Option | Syntax | Description |
|--------|--------|-------------|
| `ip_proto` | `ip_proto:tcp` | Match specific IP protocol (tcp, udp, icmp, etc.) |
| `rawip` | `rawip` | Match raw IP packet |

## Detection Points

Data detection points for packet inspection:

| Option | Description |
|--------|-------------|
| `pkt_data` | Detect in packet data |
| `file_data` | Detect in file data |
| `base64_data` | Detect in base64-decoded data |
| `raw_data` | Detect in raw packet data |
| `pkt_header` | Detect in packet header |

These are recognized but do not affect snortx packet generation.

## TCP Flags

TCP flags option: `flags:<flags>[,<ignored>]`

| Flag | Meaning |
|------|---------|
| F | FIN |
| S | SYN |
| R | RST |
| P | PSH |
| A | ACK |
| U | URG |
| E | ECE |
| C | CWR |

Example: `flags:SF,RA` = SYN+FIN set, RST+ACK ignored

## Actions

| Action | Description |
|--------|-------------|
| `alert` | Log and alert (default) |
| `log` | Log only |
| `pass` | Ignore match |
| `drop` | Block and log (inline mode) |
| `reject` | Send RST/ICMP unreachable |
| `sdrop` | Silently drop |

**Note**: `drop`, `reject`, `sdrop` require Snort inline mode—they work in snortx but have no effect on actual traffic.

## Additional Rule Options

These options are recognized and stored but do not affect snortx packet generation:

| Option | Syntax | Description |
|--------|--------|-------------|
| `sameip` | `sameip` | Match when source IP equals destination IP |
| `logto` | `logto:"filename"` | Log to alternative file |
| `tag` | `tag:session` | Tag session packets for later capture |
| `classtype` | `classtype:misc-activity` | Classification type for categorization |
| `priority` | `priority:1` | Rule priority (1=highest) |
| `replace` | `replace:"content"` | Replace matched content (inline mode) |
| `activates` | `activates:1` | Activate rule ID on match (dynamic rules) |
| `activated_by` | `activated_by:1` | Rule activated by another rule |
| `count` | `count:5` | Packet count for dynamic rules |

## Activate/Dynamic Rules

Snort supports rule chaining via activate/dynamic rules:

```
activate tcp any any -> any any (content:"MALWARE"; activates:1; msg:"Malware detected"; sid:100;)
dynamic tcp any any -> any any (activated_by:1; count:50; msg:"Tracking malware session"; sid:101;)
```

snortx parses these options but does not implement dynamic rule state tracking.

## Metadata Options

Rule metadata and classification:

| Option | Syntax | Description |
|--------|--------|-------------|
| `metadata` | `metadata:key value` | Rule metadata as key-value pairs |
| `service` | `service:http` | Target service identifier |
| `reference` | `reference:url,example.com` | External reference URL |

These are stored in `ParsedRule.Options` but do not affect snortx behavior.

## Stream Options

| Option | Description |
|--------|-------------|
| `stream_reassemble:<enable|disable>` | Enable/disable stream reassembly |
| `stream_size:<normal|small|medium|large|zero>` | Set expected stream size |

These options are recognized and stored but do not affect packet generation in snortx.

## VLAN

VLAN tagging: `vlan:<vlan_id>`

Supported for both IPv4 and IPv6. Generates DOT1Q header with VLAN ID and appropriate Ethernet type.

## IPv6 Extension Headers

IPv6 extension header options (stored in `ParsedRule.IPv6ExtHeaders` as `[]IPv6ExtensionHeader`):

| Option | Description |
|--------|-------------|
| `hopopts:<value>` | IPv6 Hop-by-Hop Options |
| `dstopts:<value>` | IPv6 Destination Options |
| `routing:<value>` | Routing Header |
| `fragment:<value>` | Fragment Header |
| `ah:<value>` | Authentication Header |
| `esp:<value>` | Encapsulating Security Payload |
| `mip6:<value>` | Mobile IPv6 |

These are recognized and stored but do not affect snortx packet generation.

## Common Gotchas

- **Application protocols (http, dns, ssh, etc.)** are transparently mapped to TCP transport—the actual packet uses TCP layer, not application-layer parsing
- **`any` in network/port fields** resolves to the generator's default IP/port (configurable via `--config`)
- **PCRE payload extraction**: If a rule has PCRE but no `content:`, snortx extracts literal strings from the PCRE pattern to build the payload; complex patterns may not extract correctly
- **VLAN + IPv6**: VLAN tagging with IPv6 is supported (DOT1Q + IPv6 headers)
- **Negated content (`content:!"..."`)** generates a generic "test payload" since negation means "match anything except this"—snortx cannot determine what the negation should NOT contain
- **Empty rules file**: `ParseFile` returns empty `Rules` slice with no error (blank lines and comments are skipped)
