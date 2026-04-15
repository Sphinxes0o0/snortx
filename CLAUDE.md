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

## CLI Commands

| Command | Description |
|---------|-------------|
| `parse <file>` | Parse Snort rules from file |
| `generate <file>` | Generate packets from rules (without sending) |
| `lint <file>` | Validate rules without generating packets |
| `test <file>` | Run full test pipeline |
| `batch <files...>` | Run tests on multiple rule files |
| `benchmark <file>` | Performance benchmark on rule file |
| `diff <file1> <file2>` | Compare two rule files |
| `repl` | Interactive REPL for rule testing |
| `serve` | Start the REST API server |
| `version` | Show version information |

## Key Flags

```bash
# Test command
./snortx test rules.rules -o ./output        # Output directory (default: ./output)
./snortx test rules.rules -w 4               # Worker count (default: auto/NumCPU)
./snortx test rules.rules -r json            # Report format: json, html, both (default: both)
./snortx test rules.rules -i eth0            # Network interface (default: lo0)
./snortx test rules.rules --mode pcap        # Send mode: pcap, inject, both

# Parse command
./snortx parse rules.rules --json            # Output rules as JSON

# Batch command
./snortx batch rules1.rules rules2.rules -w 4  # Parallel workers (default: 4)

# Benchmark command
./snortx benchmark rules.rules -n 1000       # Iterations (default: 1000)
./snortx benchmark rules.rules --warmup      # Run warmup before benchmark

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

**Data flow**: Parser → Engine (worker pool with N goroutines) → Generator (creates packets) → Sender (writes PCAP)

**Engine design**: Uses sync.WaitGroup for worker coordination, sync.Mutex for thread-safe result aggregation, and buffered channels (`ruleChan`, `resultChan`) sized at `workerCount*2`. PCRE patterns are cached in a map keyed by pattern string.

**Protocol mapping**: Application-layer protocol specifiers (http, https, ftp, ssh, smtp, dns, etc.) are transparently mapped to TCP transport in `parseHeader()`.

## Key Interfaces

- `rules.Parser`: Parses Snort rules → `*ParsedRule`
- `packets.Generator`: Generates `gopacket.Packet` from `*ParsedRule`
- `packets.Sender`: Writes packets to PCAP files
- `engine.Engine`: Worker pool (NumCPU workers by default) with buffered channels

## Supported Protocols

TCP, UDP, ICMP, IP (IPv4/IPv6), SCTP, ARP, DNS
Application protocols mapped to TCP: HTTP, HTTPS, FTP, SSH, SMTP, DNS, SIP, SMB, etc.

## Configuration

YAML config via `--config` flag. See `examples/snortx.yaml` for schema.

```yaml
generator:
  vars:
    $HOME_NET: "192.168.1.0/24"    # Customize variable expansion
    $EXTERNAL_NET: "any"
    $HTTP_SERVERS: "$HOME_NET"
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/rules/upload` | Upload rules file |
| POST | `/api/v1/rules/parse` | Parse rules text |
| POST | `/api/v1/tests/run` | Run test pipeline |
| GET | `/api/v1/tests/results?id=<id>` | Get test results |
| GET | `/api/v1/health` | Health check |

## Implementation Notes

- **Packet construction**: Uses gopacket with `SerializeLayers` (Ethernet + IP + L4 + Payload)
- **PCAP writing**: Uses pcapgo; CaptureInfo requires correct CaptureLength/Length
- **Worker pool**: Buffered channels (capacity = WorkerCount*2), wait groups for coordination
- **PCRE validation**: Compiles to Go regex, cached by pattern; payload validated for `/pattern/modifiers` match
- **Variable expansion**: Generator expands `$HOME_NET`, `$EXTERNAL_NET`, etc. from configured vars map
