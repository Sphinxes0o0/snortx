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

# Build both
go build -o snortx ./cmd/cli && go build -o snortx-api ./cmd/api

# Run tests
go test ./...

# Tidy dependencies
go mod tidy
```

## Running

```bash
# Parse rules
./snortx parse examples/sample.rules

# Run full test pipeline
./snortx test examples/sample.rules -o /tmp/output

# Start API server
./snortx-api serve --addr :8080
```

## Architecture

```
cmd/cli, cmd/api     → Entry points
internal/rules       → Snort rule parsing (Parser, models)
internal/packets     → Packet generation (Generator) and PCAP writing (Sender)
internal/engine      → Worker pool for parallel rule processing
internal/reports     → JSON and HTML report generation
internal/api         → HTTP server, handlers, router (gorilla/mux)
pkg/config           → Configuration structs
```

## Key Interfaces

- `rules.Parser`: Parses Snort rules → `*ParsedRule`
- `packets.Generator`: Generates `gopacket.Packet` from `*ParsedRule`
- `packets.Sender`: Writes packets to PCAP files
- `engine.Engine`: Worker pool that processes rules in parallel via channels

## Notes

- Uses gopacket for packet construction; requires `SerializeLayers` with all layers at once (Ethernet + IP + L4 + Payload) to produce valid packets
- PCAP writer uses pcapgo; CaptureInfo must have correct CaptureLength/Length set
- Worker pool uses buffered channels for rule input and results aggregation
