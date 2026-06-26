---
name: snortx
description: Work with the snortx Go project — a Snort rule parser, packet generator, PCAP recorder, port scanner, and high-speed packet flooder. Use when editing, debugging, building, testing, extending, or running snortx (cmd/cli, cmd/api, internal/* packages), writing Snort rules for snortx to consume, or interpreting snortx CLI output. Triggers on mentions of "snortx", its subcommands (parse, generate, lint, test, batch, benchmark, diff, scan, flood, repl, serve), or changes to internal/rules, internal/packets, internal/engine, internal/scanner, internal/reports, internal/api, pkg/config.
---

# snortx

Go-based tool that parses Snort rules, generates matching packets, records them to PCAP files, and produces HTML/JSON test reports. Also provides TCP port scanning and high-speed packet flooding.

The project root is `~/workspace/github/snortx`. `CLAUDE.md` in that root contains the full reference. Read it whenever you need the canonical list of commands, flags, error phases, options, or output structure — this skill is the quick-start.

## When to load this skill

- User mentions `snortx`, `snortx-api`, or any subcommand (`parse`, `generate`, `lint`, `test`, `batch`, `benchmark`, `diff`, `scan`, `flood`, `repl`, `serve`)
- Edits to files under `cmd/cli`, `cmd/api`, `internal/rules`, `internal/packets`, `internal/engine`, `internal/scanner`, `internal/reports`, `internal/api`, `pkg/config`
- Writing or debugging Snort rule files consumed by snortx
- Questions about data flow: Parser → Engine → Generator → Sender

## Module

`github.com/user/snortx` — Go 1.x project, depends on `gopacket`, `pcapgo`, `cobra`, `gorilla/mux`.

## Build

```bash
cd ~/workspace/github/snortx
go build -o snortx ./cmd/cli
go build -o snortx-api ./cmd/api
go mod tidy
```

## Test

```bash
go test ./...                          # everything
go test ./internal/rules -v            # one package
go test -run TestParser ./...          # pattern match
```

## Common tasks

| Goal | Command |
|------|---------|
| Validate rules without sending | `./snortx lint examples/sample.rules` |
| Generate packets (no PCAP) | `./snortx generate examples/sample.rules` |
| Full pipeline parse → PCAP | `./snortx test examples/sample.rules -o ./output` |
| Parse → JSON view | `./snortx parse rules.rules --json` |
| Batch many files | `./snortx batch rules1.rules rules2.rules -w 8` |
| Compare rule files | `./snortx diff a.rules b.rules` |
| Benchmark | `./snortx benchmark rules.rules --iterations 1000` |
| REPL | `./snortx repl` |
| TCP port scan | `./snortx scan 192.168.1.0/24 -p 80,443 --workers 1024 --rate 2000` |
| Packet flood | `./snortx flood 10.0.0.10 -p 80 --duration 10s --engine pcap` |
| API server | `./snortx-api serve --addr :8080` |

## Config flag (global)

`--config` lives on the root command — place before OR after the subcommand:

```bash
./snortx --config snortx.yaml test rules.rules
./snortx test rules.rules --config snortx.yaml
```

YAML config lives at `examples/snortx.yaml`. Vars are merged with defaults; config vars override defaults, unspecified vars keep defaults.

## Architecture quick map

```
cmd/cli, cmd/api     → Entry points (cobra CLI, gorilla/mux HTTP)
internal/rules       → Parser + models (ParsedRule, ContentMatch, PCREMatch)
internal/packets     → Generator, Sender, TX engines (pcap/sendmmsg/afpacket), FloodEngine
internal/scanner     → TCP port scanner (nmap/masscan style)
internal/engine      → Worker pool: buffered channels, PCRE regex cache
internal/reports     → JSON + HTML report writers
internal/api         → HTTP server: auth, CORS, rate limit, result persistence
pkg/config           → YAML loader
```

**Data flow**: Parser → Engine (worker pool) → Generator (gopacket) → Sender (PCAP write / inject).

**`generate`** uses Generator only — no PCAP. **`test`** runs the full pipeline.

## Key gotchas

- **App protocols** (`http`, `dns`, `ssh`, ...) are mapped to TCP transport in `parseHeader()`.
- **`any`** in network/port fields resolves to generator defaults (`DefaultSrcIP`, `DefaultDstIP`, etc.).
- **PCRE literal extraction**: when only `pcre:` is specified, the generator pulls literal strings out of the pattern to build the payload. Complex patterns may fail extraction and fall back to default payload `"test payload"`.
- **Negated content** (`content:!"..."`) → generic "test payload", since negation has no positive payload.
- **Bidirectional** (`<>`) → generates two packets (forward + reverse).
- **Empty rules file** → empty `Rules` slice, no error (blank lines and comments skipped).
- **Parse errors are partial** — one bad rule does not abort the batch. `ParseResult.Rules` holds successes; `ParseResult.Errors` holds per-rule failures with `Line`, `CharOffset`, `Phase`, `Message`, `RuleText`.
- **Default rule ID**: missing sid/gid/rev → GID=1, SID=0, REV=1.
- **GID range** 0–999,999,999; **SID range** 0–999,999,999; **REV range** 0–999.
- **TX engines**: `pcap` works everywhere (default), `sendmmsg`/`afpacket` are Linux-only. Stub file `sendmmsg_stub.go` keeps non-Linux builds compiling.
- **Generator is goroutine-safe** (config-only state). **Engine can be reused** across `Run()` calls — channels are recreated each run. **PCRE cache** is per-Engine, capped at ~1000 entries with oldest-half eviction.

## Editing rules / adding options

When adding a new Snort option:

1. Parse it in `internal/rules/parser.go` and store in the appropriate struct on `ParsedRule` (see `internal/rules/models.go`).
2. If it affects packets, handle it in `internal/packets/generator.go`.
3. If it affects L4/protocol semantics, check `internal/packets/sender*.go` and the TX engine files.
4. Add a test in the matching `*_test.go` (e.g. `internal/rules/parser_test.go`, `internal/packets/generator_test.go`).
5. Update `CLAUDE.md` with the new option, syntax, and any defaults.

## Output layout

```
output/
├── rule_<sid>.pcap
├── test_runs/<test_run_id>.json   # API only
├── report_<test_run_id>.json
└── report_<test_run_id>.html
```

CLI `test` writes PCAPs to `output/` directly. API runs nest under `<outputDir>/test_runs/`.

## Detailed references

- [`references/architecture.md`](references/architecture.md) — package-by-package architecture, key types, concurrency model
- [`references/rule-options.md`](references/rule-options.md) — full list of supported Snort options with syntax
- [`references/cli-commands.md`](references/cli-commands.md) — every command and flag with defaults
- [`references/api.md`](references/api.md) — REST endpoints, request/response shapes, middleware order

Load these on demand via the read tool when the question gets specific.