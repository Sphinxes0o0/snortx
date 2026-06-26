# snortx architecture

Module: `github.com/user/snortx`

## Package map

| Path | Role |
|------|------|
| `cmd/cli` | cobra CLI: parse, generate, lint, test, batch, benchmark, diff, scan, flood, repl |
| `cmd/api` | cobra wrapper that boots the HTTP server in `internal/api` |
| `internal/rules` | Snort rule parser, AST models, PCRE static analyzer |
| `internal/packets` | packet generation (gopacket), PCAP writing, TX engine abstraction, flood engine |
| `internal/engine` | worker pool orchestrator with PCRE regex cache |
| `internal/scanner` | TCP port scanner (semaphore worker pool + ticker rate limiter) |
| `internal/reports` | JSON + HTML report writers |
| `internal/api` | gorilla/mux HTTP server: middleware (logging → recovery → auth → CORS → rate limit) + persistence |
| `pkg/config` | YAML config struct + loader; merged with defaults |

## Data flow

```
Snort rule text
   │
   ▼
rules.Parser.ParseFile / ParseMulti / ParseRule
   │  returns *rules.ParseResult (Rules + Errors)
   ▼
engine.Engine.Run(rules) ──► ruleChan (buffered, size = workers*2)
   │
   ▼  N workers
Generator.Generate(*rules.ParsedRule) → []gopacket.Packet
   │
   ▼  validatePCRE: compile PCRE (cached), match first packet payload
Sender.SendAndRecord(rule, packets) → PCAP write + optional inject
   │
   ▼
resultChan (buffered, size = workers*2)
   │
   ▼
TestRunResult aggregation (mutex-protected)
   │
   ▼
reports.WriteJSON / WriteHTML → ./output/
```

## Key types

### `internal/rules`
- `Parser` — entry point; methods: `ParseFile(path)`, `ParseMulti(text)`, `ParseRule(text)`
- `ParseResult` — `Rules []*ParsedRule`, `Errors []*ParseError`
- `ParseError` — `Line`, `CharOffset`, `Phase` (header|options|content|pcre|flow|rule_id|vlan|format), `Message`, `RuleText`, `Context`
- `ParsedRule` — see `models.go`; fields include `RuleID`, `Protocol` (post app-protocol mapping), `Contents []ContentMatch`, `PCREMatches []PCREMatch`, `ByteTests`, `ByteJumps`, `Direction`, `IsBidirectional`, `Options map[string]string`, `Flowbits`, `Threshold`, `RateFilter`, `DetectionFilter`, `HTTPModifiers`, `IPv6ExtHeaders`, `VLANID`, `RawText`
- `AnalyzePCRE(pattern)` — static analysis: nested quantifiers (ReDoS), overlapping alternation, unanchored trailing quantifiers, large char classes, Go regex compatibility

### `internal/packets`
- `Generator` — `Generate(rule) ([]gopacket.Packet, error)`; goroutine-safe (config-only state); default payload `"test payload"` when no content/PCRE
- `Sender` — `WritePacket(data)`, `SendAndRecord(rule, packets) (*SendResult, error)`
- `SendMode` — `pcap` (PCAP only), `inject` (interface inject), `both`
- `TxEngine` — `pcap` (default, all OS), `sendmmsg` (Linux raw socket batch), `afpacket` (Linux AF_PACKET TX_RING); non-Linux builds use `sendmmsg_stub.go`
- `FloodEngine` — wraps a sender with rate limiting, worker fan-out, burst vs streaming modes, multi-handle mode, buffer pool
- `SendResult` — `RuleSID`, `RuleMsg`, `Protocol`, `PacketsGen`, `PacketsSent`, `PacketsWritten`, `PCAPPath`, `Status` ("success"|"failed"), `Error`, `Duration`

### `internal/engine`
- `Engine` — `Run(rules []*ParsedRule) (*TestRunResult, error)`; creates fresh channels each call
- Fields: `WorkerCount`, `Generator`, `Sender`, `pcreCache map[string]*regexp.Regexp` (cap ~1000, evicts oldest half at 1200), `testRunResult`
- Buffered channels `ruleChan`, `resultChan` (size = `WorkerCount*2`)
- `sync.WaitGroup` for worker coordination, `sync.Mutex` for result aggregation

### `internal/scanner`
- `Scanner` — TCP connect scan with semaphore worker pool + optional ticker rate limiter
- Banner grab via `ServiceDetect` flag with configurable timeout
- Flags: `-p` / `--ports`, `--top-ports`, `-w`, `--rate`, `--timeout`, `--service-detect`, `--json`, `--max-hosts`

### `internal/api`
- gorilla/mux router
- Middleware stack (applied in order): logging → recovery → auth → CORS → rate limit
- Endpoints: `/api/v1/rules/upload`, `/api/v1/rules/parse`, `/api/v1/tests/run`, `/api/v1/tests/results`, `/api/v1/health`
- Persistence: writes `output/test_runs/<test_run_id>.json` on completion, loads on startup
- Pagination on `/tests/results`: `page`, `page_size` (max 100); omit both for full result
- TLS optional via `api.tls_enabled` + `tls_cert` + `tls_key`
- Server timeouts: 30s read, 30s write

### `pkg/config`
- YAML loader, defaults merged with config (config wins, unspecified defaults preserved)
- Top-level keys: `app`, `engine` (with nested `generator`, `sender`), `api` (with nested `auth`), `cli`
- `engine.generator.vars` — `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_SERVERS`, etc. (defaults shown in `CLAUDE.md`)

## Concurrency invariants

- `Generator` is safe for concurrent use across workers.
- Each `Engine.Run()` call creates fresh channels and a fresh `testRunResult`.
- `Engine` can be reused for sequential `Run()` calls — channels reset each run.
- PCRE cache persists across `Run()` calls within the same `Engine` instance.
- `batch` command uses a semaphore channel (size = worker count); each file gets its own `Engine` instance, shared `Generator`, dedicated `Sender`.
- `Sender` is NOT goroutine-safe in some modes — multi-handle / burst modes exist specifically to handle the contention.

## PCRE validation

After `Generator.Generate`:
1. Compile PCRE to Go regex (cached by Go-prefixed string).
2. Convert modifiers: `i` → `(?i)`, `m` → `(?m)`, `s` → `(?s)`.
3. Match first packet payload against compiled regex.
4. Failure → result status `"failed"`.

Unsupported modifiers flagged by `AnalyzePCRE`: `R` (PCRE_MATCH_END), `U` (PCRE_UNGREEDY).

## Protocol-specific packet building

`Generator.Generate` dispatches by `rule.Protocol`:

- `tcp` → `buildTCP` (Ethernet + IPv4/IPv6 + TCP + payload; handles VLAN via DOT1Q)
- `udp` → `buildUDP`
- `icmp` → `buildICMP`
- `ip` → `buildIP` (raw IPv4/IPv6)
- `dns` → `buildDNS` (UDP transport, builds DNS query with TXID 0x0001, type A, class IN)
- `sctp` → builds IPv4/IPv6 + SCTP chunk with src/dst ports
- `arp` → `buildARP` (Ethernet + ARP, broadcast dst MAC; payload from rule content; no request/reply distinction)
- App protocols (http, https, ftp, ssh, smtp, dns, sip, smb) → transparently mapped to TCP

## Output layout

```
output/
├── rule_<sid>.pcap                    # one per rule SID
├── test_runs/<test_run_id>.json       # API runs only
├── report_<test_run_id>.json
└── report_<test_run_id>.html
```

`MkdirAll` creates the directory tree on demand. PCAP files with the same SID are overwritten — SID should be unique per ruleset.