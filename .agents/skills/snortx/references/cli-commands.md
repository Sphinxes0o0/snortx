# CLI commands

All commands accept the global `--config <file>` flag (place before or after the subcommand).

## `parse <file>`

Parse rules and print details. `--json` outputs as JSON.

## `generate <file>`

Generate packets without writing PCAP. Useful for validation.

## `lint <file>`

Static analysis — does NOT generate packets, but does:
- Verify constructibility
- Validate PCRE syntax
- Warn on negated content, `nocase` with multiple contents
- Report unsupported PCRE modifiers (`R`, `U`)
- Run `AnalyzePCRE` for nested quantifiers (ReDoS), overlapping alternation, unanchored trailing quantifiers, large char classes, Go regex incompatibilities

## `test <file>`

Full pipeline: parse → generate → PCAP write → optional inject.

Flags:
- `-o, --output` — output directory
- `-i, --interface` — interface for injection (default from config)
- `--mode` — `pcap` | `inject` | `both`
- `-w, --workers` — engine worker count
- `--format` — `json` | `html` | `both` (report formats)

## `batch <files...>`

Run `test` on multiple files in parallel. Uses a semaphore to limit concurrent files. Each file gets its own `Engine` instance with shared `Generator`.

## `benchmark <file>`

Performance benchmark. Reports:
- Parsing: time per file iteration, iterations/sec
- Packet generation: time per rule, time per packet, packets/sec
- Memory: `Alloc`, `TotalAlloc`, `Mallocs` delta (after GC)

Flags: `--iterations`, `--warmup` (run one unmeasured iteration first to prime caches).

## `diff <file1> <file2>`

Compare two rule files. Output:
- `[+SID]` — added rule
- `[-SID]` — removed rule
- `[~SID]` — modified rule (compared by content hash)

## `scan <target>`

TCP port scanner (nmap/masscan style).

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --ports` | `22,80,443` | Ports/ranges/lists |
| `--top-ports` | 0 | Use built-in top-N ports (overrides `--ports`) |
| `-w, --workers` | 512 | Parallel workers |
| `--rate` | 0 | Packets/sec (0 = unlimited) |
| `--timeout` | 1200ms | Per-port timeout |
| `--service-detect` | false | Grab service banners on open ports |
| `--json` | false | JSON output |
| `--max-hosts` | 4096 | Max hosts from CIDR expansion |

## `flood <target>`

High-speed packet flood (hping3 style).

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | 80 | Destination port |
| `--protocol` | tcp | `tcp` \| `udp` \| `icmp` |
| `--src-ip` | auto | Source IP |
| `--src-port` | 12345 | Source port |
| `--tcp-flags` | syn | e.g. `syn,ack,psh` |
| `--ttl` | 64 | TTL / IPv6 hop limit |
| `--payload` | `snortx-flood` | Payload string |
| `--payload-hex` | | Hex payload bytes |
| `--packet-size` | 0 | Total packet size (pads payload if smaller) |
| `-i, --interface` | lo0 | Network interface |
| `--mode` | inject | `inject` \| `both` |
| `--engine` | pcap | `pcap` \| `sendmmsg` \| `afpacket` (Linux-only) |
| `-w, --workers` | 4 | Sender workers |
| `--rate` | 0 | Packets/sec (0 = unlimited) |
| `--count` | 0 | Target packet count |
| `--strict` | false | Require exact count delivery |
| `--max-retries` | 3 | Retry budget per packet (strict mode) |
| `--duration` | 10s | Flood duration |
| `--stats-interval` | 1s | Stats print interval |
| `--stats-json` | false | JSON stats output |
| `--burst` | false | Single writer goroutine (no contention) |
| `--multi-handle` | false | One pcap handle per worker |
| `--raw-socket` | false | Raw sockets instead of pcap |
| `--buffer-pool` | false | Pre-allocated buffer pool |
| `--batch-size` | 0 | Batch sending (0 = disabled) |

## `repl`

Interactive REPL:
- `parse <rule>` — parse and show details
- `generate <rule>` — generate packets
- `<rule text>` — direct input, parse then show
- `help`, `exit`, `quit`

## `serve` (snortx-api only)

```
./snortx-api serve --addr :8080
```

Not a `snortx` CLI command — use `snortx-api` binary.

## `version`

Show version info.