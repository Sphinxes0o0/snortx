# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

snortx is a Go-based tool that parses Snort rules, generates matching network packets, records them to PCAP files, and generates HTML/JSON test reports.

## Build Commands

```bash
# Build CLI
go build -o snortx ./cmd/cli

# Build API server
go build -o snortx-api ./cmd/api

# Run all tests
go test ./...

# Run a single test
go test ./internal/rules -run TestParseContentMatch -v

# Tidy dependencies
go mod tidy
```

## Running

```bash
# Show version
./snortx version

# Parse rules
./snortx parse examples/sample.rules

# Generate packets (without sending)
./snortx generate examples/sample.rules

# Lint rules (validate without generating)
./snortx lint examples/sample.rules

# Run full test pipeline
./snortx test examples/sample.rules -o /tmp/output

# Batch test multiple files
./snortx batch rules1.rules rules2.rules

# Start API server
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
| `serve` | Start the REST API server |
| `version` | Show version information |

## Architecture

```
cmd/cli, cmd/api     → Entry points
internal/rules       → Snort rule parsing (Parser, models)
internal/packets     → Packet generation (Generator) and PCAP writing (Sender)
internal/engine      → Worker pool for parallel rule processing
internal/reports     → JSON and HTML report generation
internal/api         → HTTP server, handlers, router (gorilla/mux)
pkg/config           → Configuration structs and YAML loading
```

**Data flow**: Parser → Engine (worker pool with N goroutines) → Generator (creates packets) → Sender (writes PCAP)

**Engine design**: Uses sync.WaitGroup for worker coordination, sync.Mutex for thread-safe result aggregation, and buffered channels (`ruleChan`, `resultChan`) sized at `workerCount*2`. PCRE patterns are cached in a map keyed by pattern string.

**Protocol mapping**: Application-layer protocol specifiers (http, https, ftp, ssh, smtp, dns, etc.) are transparently mapped to TCP transport in `parseHeader()`.

## Key Interfaces

- `rules.Parser`: Parses Snort rules → `*ParsedRule`
- `packets.Generator`: Generates `gopacket.Packet` from `*ParsedRule`
- `packets.Sender`: Writes packets to PCAP files
- `engine.Engine`: Worker pool that processes rules in parallel via channels

## Supported Protocols

TCP, UDP, ICMP, IP (IPv4/IPv6), SCTP, DNS, ARP. Application-layer specifiers (http, https, ftp, ssh, smtp, dns, etc.) are normalized to TCP.

## Configuration

snortx uses YAML configuration files. See `examples/snortx.yaml` for the full schema.

```bash
./snortx --config examples/snortx.yaml test rules.rules
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/rules/upload` | Upload rules file |
| POST | `/api/v1/rules/parse` | Parse rules text |
| POST | `/api/v1/tests/run` | Run test pipeline |
| GET | `/api/v1/tests/results?id=<id>` | Get test results |
| GET | `/api/v1/health` | Health check |

## Notes

- Uses gopacket for packet construction; requires `SerializeLayers` with all layers at once (Ethernet + IP + L4 + Payload) to produce valid packets
- PCAP writer uses pcapgo; CaptureInfo must have correct CaptureLength/Length set
- Worker pool uses buffered channels for rule input and results aggregation
- PCRE patterns are validated against generated payloads in the Engine (not during parsing) using Go's regexp with an in-memory cache keyed by pattern
- Config can be loaded via `--config` flag or defaults are used
