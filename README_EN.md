# snortx

A Go-based Snort rule testing tool for parsing Snort rules, generating matching network packets, recording to PCAP files, and producing HTML/JSON test reports.

## Features

- **Rule Parsing** — Full Snort rule syntax parsing with per-rule error reporting
- **Multi-Line Input** — `ParseFile` / `ParseMulti` for batch rule processing
- **Packet Generation** — Build matching gopacket packets from parsed rules
- **PCAP Recording** — Write generated packets to PCAP files
- **Test Reports** — HTML and JSON report generation
- **REST API** — HTTP API with auth, CORS, and rate limiting
- **Parallel Processing** — Worker pool-based concurrent rule processing
- **Port Scanning** — nmap/masscan-style high-concurrency TCP port scanner
- **Packet Flooding** — hping3-style high-speed customizable packet flood

## Supported Protocols

TCP, UDP, ICMP, IP (IPv4/IPv6), SCTP, DNS, ARP

Application-layer protocol identifiers (http, https, ftp, ssh, smtp, dns, etc.) are transparently mapped to TCP transport.

Additional rule semantics implemented:
- `sameip`
- `flags`
- `dsize`
- `itype` / `icode` / `icmp_id` / `icmp_seq`

## Quick Start

### Build

```bash
# Build CLI
go build -o snortx ./cmd/cli

# Build API server
go build -o snortx-api ./cmd/api
```

### CLI Commands

```bash
# Parse rules
./snortx parse examples/sample.rules

# Generate packets (no send)
./snortx generate examples/sample.rules

# Validate rules (no packet generation)
./snortx lint examples/sample.rules

# Run full test pipeline
./snortx test examples/sample.rules -o /tmp/output

# Batch test multiple files
./snortx batch rules1.rules rules2.rules

# Start API server
./snortx-api serve --addr :8080

# nmap/masscan-style scan (high concurrency)
./snortx scan 192.168.1.0/24 --top-ports 20 --workers 1024 --rate 2000

# hping3-style high-speed flood
./snortx flood 10.0.0.10 --protocol tcp --port 80 --tcp-flags syn --workers 8 --rate 50000 --duration 10s --engine pcap
```

### REST API

Start the server and access `http://localhost:8080/api/v1/health` for health check.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/rules/upload` | Upload rules file |
| POST | `/api/v1/rules/parse` | Parse rules text |
| POST | `/api/v1/tests/run` | Run test pipeline |
| GET | `/api/v1/tests/results?id=<id>` | Get test results |
| GET | `/api/v1/health` | Health check |

Notes:
- `/api/v1/rules/parse` and `/api/v1/rules/upload` return an `errors` array for per-line parse failures.
- `/api/v1/tests/run` returns `400` when all rules fail to parse; partial failures are returned in `parse_errors`.

TX engines:
- `pcap` — Default, stable on all platforms
- `sendmmsg` — Linux-only, raw socket batch send
- `afpacket` — Linux-only, AF_PACKET TX_RING for highest performance

### Configuration

snortx uses a YAML config file (optional, all fields have defaults):

```yaml
app:
  name: snortx
  version: "1.0.0"

engine:
  worker_count: 0  # 0 = auto (NumCPU)
  rule_timeout: 30s
  total_timeout: 5m
  output_dir: ./output
  generator:
    default_src_ip: "192.168.1.100"
    default_dst_ip: "10.0.0.1"
    default_src_port: 12345
    default_dst_port: 80

api:
  address: ":8080"
  cors_allowed_origins:
    - "*"
```

## Architecture

```
cmd/cli, cmd/api     → Entry points (cobra CLI, gorilla/mux HTTP)
internal/rules       → Snort rule parsing (Parser, models)
internal/packets     → Packet generation (Generator) and PCAP writing (Sender)
internal/engine      → Worker pool for parallel rule processing
internal/reports     → JSON and HTML report generation
internal/api         → HTTP server, handlers, routing
pkg/config           → Config structs and YAML loading
```

**Data flow**: Parser → Engine (Worker Pool) → Generator (creates packets) → Sender (writes PCAP)

**Engine design**: Uses `sync.WaitGroup` for worker coordination, `sync.Mutex` for thread-safe result aggregation, buffered channels (`ruleChan`, `resultChan`) sized at `workerCount*2`. PCRE patterns are cached in memory.

## Testing

```bash
# Run all tests
go test ./...

# Run a single test
go test ./internal/rules -run TestParseContentMatch -v
```

## Example Rules

```snort
# TCP content match
alert tcp any any -> any any (msg:"TEST TCP content"; content:"test"; sid:1000001; rev:1;)

# HTTP traffic
alert tcp any any -> any 80 (msg:"HTTP traffic"; content:"GET"; nocase; sid:1000005; rev:1;)

# PCRE match
alert tcp any any -> any any (msg:"TEST PCRE"; content:"GET /"; pcre:"/GET /"; sid:1000007; rev:1;)

# Bidirectional traffic
alert tcp any any <> any any (msg:"TEST bidirectional"; content:"test"; sid:1000027; rev:1;)
```

## License

MIT
