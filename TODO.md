# snortx Performance Roadmap (sendmmsg / AF_PACKET)

## Goal
- Keep current `pcap` path for compatibility.
- Add high-performance Linux TX paths for flooding:
  - `sendmmsg` (raw socket batch send)
  - `AF_PACKET` TX_RING (mmap ring buffer)
- Make engine selectable by flag/config and measurable by stable KPIs.

## Scope
- Target commands:
  - `snortx flood`
  - future: `snortx test --mode inject` hot path
- Linux first. macOS remains `pcap` fallback.

## Phase 0: Baseline and guardrails
- [x] Add benchmark command options for flood path (`--engine`, `--packet-size`, `--stats-json`).
- [x] Record baseline PPS/CPU/drop on current `pcap` engine.
- [x] Define acceptance thresholds:
  - [x] PPS uplift vs `pcap`
  - [x] CPU per Mpps
  - [x] drop/error budget
- [x] Implement `--multi-handle` flag (one pcap handle per worker)
- [x] Implement `--burst` flag (single writer goroutine)
- [x] Implement Buffer Pool for reduced GC pressure
- [x] Implement FloodEngine abstraction
- [ ] Implement batched sending mode (has deadlock issues, disabled)

### Baseline Measurements (pcap engine, macOS loopback)

| Packet Size | Workers | Steady-state PPS | Notes |
|-------------|---------|------------------|-------|
| 64B         | 1       | ~920K            | Best performance with single worker |
| 64B         | 4       | ~377K            | pcap handle serialization bottleneck |
| 64B         | 8       | ~228K            | Worse due to increased contention |
| 256B        | 4       | ~367K            | Slightly lower than 64B |
| 1400B       | 4       | ~326K            | Lower due to larger packet processing |

### Multi-Handle Results (macOS)

| Configuration | PPS | Improvement |
|--------------|------|-------------|
| Single handle (4 workers) | ~372K | baseline |
| Multi-handle (4 workers) | ~799K | **+115%** |
| Single handle (8 workers) | ~218K | baseline |
| Multi-handle (8 workers) | ~598K | **+174%** |

> **Conclusion**: Using separate pcap handles per worker significantly improves macOS performance by bypassing kernel-level handle serialization.

### Acceptance Thresholds (sendmmsg / AF_PACKET vs pcap)

| Metric | sendmmsg Target | AF_PACKET Target |
|--------|-----------------|------------------|
| PPS uplift vs pcap (1 worker) | ≥ 1.5x | ≥ 3x |
| Multi-worker scaling | 4-8 workers should scale linearly | 4-8 workers should scale linearly |
| CPU per Mpps reduction | ≥ 30% | ≥ 50% |
| Max drop rate | < 1% | < 1% |

> **Note**: Targets are for Linux with loopback interface. macOS loopback shows unusually high pcap performance (~920K PPS with 1 worker) which may be harder to beat.

## macOS Performance Research

### Current State: pcap

macOS loopback performance with 1 worker (~920K PPS). Multi-worker performance degrades due to pcap handle serialization.

### GCD Dispatch Batch vs Mutex (Experiment Results)

**Experiment**: Implemented BurstSender with channel-based queuing to test if single-writer goroutine reduces contention.

**Result**: ❌ Burst mode is slower than direct injection on macOS.

| Configuration | PPS | Notes |
|--------------|------|-------|
| 4 workers, direct | ~371K | Baseline |
| 4 workers, burst | ~336K | Slower (channel overhead) |
| 8 workers, direct | ~206K | More contention |
| 8 workers, burst | ~203K | Slower (channel overhead) |
| 1 worker | ~920K | **Best performance** |

### Multi-Handle Sender (Experiment Results) ✅

**Experiment**: Each worker uses a dedicated pcap handle instead of sharing one.

**Result**: ✅ **Significant improvement!**

| Configuration | PPS | Improvement |
|--------------|------|-------------| 
| Single handle (4 workers) | ~372K | baseline |
| **Multi-handle (4 workers)** | **~799K** | **+115%** |
| Single handle (8 workers) | ~218K | baseline |
| **Multi-handle (8 workers)** | **~598K** | **+174%** |
| 256B, 4 workers | ~366K → ~756K | +107% |

**Conclusion**: macOS kernel serializes writes per pcap handle, not per interface. Multiple handles bypass this bottleneck.

**Recommendation**: Use `--multi-handle` flag for macOS multi-worker scenarios. Still less efficient than single worker on loopback, but enables true parallel scaling.

### Raw Socket Experiment (Updated)

**Experiment**: Tested raw sockets with `IPPROTO_TCP` (no IP_HDRINCL) on physical NIC.

**Result**: ❌ **pcap is faster**

| Configuration | pcap PPS | raw socket PPS |
|--------------|----------|----------------|
| 1 worker, physical NIC | ~891K | ~205K (with failures) |
| 4 workers, physical NIC | ~379K | ~108K |

**Root cause analysis**:
- Using `IPPROTO_TCP` with kernel-added IP header (works on macOS)
- But kernel IP header insertion adds overhead per packet
- pcap has better buffering and batching optimizations
- Physical NIC is hitting wire speed limits anyway

**Conclusion**: pcap outperforms raw sockets on macOS for both loopback and physical NIC. Raw sockets provide no performance benefit.

**BPF Analysis Summary**:
- BPF is strictly ingress-only on macOS (no egress path)
- Raw socket with `IPPROTO_TCP` works but is slower than pcap
- No user-space bypass exists for egress packets on macOS with better performance
- NKE (deprecated) is the only option for true kernel-bypass on macOS

### macOS Kernel Extension / System Extension Options

| Approach | Raw Ethernet | Performance | Effort | Status |
|----------|--------------|-------------|--------|--------|
| **pcap (current)** | No (IP only) | ~920K PPS | - | ✅ Implemented |
| **GCD batch** | No (IP only) | TBD | Low | 🔲 Pending research |
| **libnet** | Yes | ~1-2x pcap | Medium | ⚠️ Abandoned, no ARM |
| **NEPacketTunnelProvider** | No (IP only) | ~200-500K PPS | Medium | 🔲 Alternative |
| **NKE (deprecated)** | Yes | ~1-2 Mpps | High | ⚠️ Deprecated |
| **DriverKit network** | No | N/A | Very High | ❌ Not supported |

**Conclusion**:
- GCD batch is the most practical near-term improvement for macOS
- NKE provides raw Ethernet at highest performance but is deprecated
- System Extensions (NEPacketTunnelProvider) require special entitlements from Apple

## Phase 1: Engine abstraction
- [x] Introduce sender engine interface in `internal/packets`:
  - [x] `pcap` (existing)
  - [x] `sendmmsg` (implemented, Linux-only)
  - [x] `afpacket` (implemented, Linux-only)
- [x] Add CLI flag: `snortx flood --engine pcap|sendmmsg|afpacket`.
- [x] Add config key (YAML): `engine.sender.tx_engine`.
- [x] Keep default as `pcap` for safety.
- [x] Add AF_PACKET implementation (Linux-only)

## Phase 2: sendmmsg implementation (Linux)
- [x] Add Linux-only file with build tags (`sendmmsg_linux.go`).
- [ ] Implement raw socket + `sendmmsg` batching:
  - [ ] batch size tuning (`--batch-size`)
  - [ ] socket buffer tuning (`SO_SNDBUF`)
  - [ ] optional busy-poll loop for high rate
- [ ] Expose runtime stats:
  - [ ] attempted/sent/failed
  - [ ] syscall count
  - [ ] effective batch size

## Phase 3: AF_PACKET TX_RING implementation (Linux)
- [x] Add Linux-only `AF_PACKET` sender.
- [x] Implement TX_RING setup and frame enqueue/commit.
- [x] Add ring tuning flags:
  - [x] block/frame size
  - [x] ring depth
  - [x] wakeup policy
- [x] Add clear fallback: if setup fails, fallback to `sendmmsg` or `pcap`.

**Implementation notes**:
- `AFpacketInjector`: Basic AF_PACKET socket sender (simple, portable)
- `MultiAFpacketInjector`: Multiple sockets with round-robin distribution
- `AFpacketTXRing`: Advanced TX_RING with memory-mapped buffer (higher performance)
- All implementations use `SOCK_RAW` with `ETH_P_ALL` for full packet control

## Phase 4: strict mode reliability
- [ ] Extend `flood --strict` with engine-aware completion semantics.
- [ ] Add optional egress verification (`--verify-egress`):
  - [ ] mirror capture on same NIC with BPF filter
  - [ ] correlate by tuple + payload signature
- [ ] Integrate NIC counters (`tx_packets`, `tx_dropped`) into report.

## Deep Review Findings (2026-05-10)

### Critical Issues (Fix Immediately)

| Issue | Severity | Location | Description |
|-------|----------|----------|-------------|
| sendmmsg shared sockaddr | High | `sendmmsg_linux.go:118-119` | All packets in batch share same sockaddr pointer; sendmmsg modifies it in-place, corrupting subsequent destinations |
| File handle leak | High | `sender.go:186-197` | If `WriteFileHeader` fails after `os.Create` succeeds, file descriptor leaks |
| Silent parseDSize errors | High | `parser.go:214-217,2278-2289` | `parseDSize` errors silently ignored; malformed range inputs accepted |
| Silent error ignoring | High | `sender.go:211` | `WritePacketData` errors silently ignored in `SendAndRecord` |
| Potential panic | High | `parser.go:1901-1902` | `decodeContent` panics on single-pipe input `"|"` |

### High Priority Issues

| Issue | Severity | Location | Description |
|-------|----------|----------|-------------|
| XSS via PCAPPath | High | `reports/html.go` | `PCAPPath` unescaped in HTML template - allows script injection |
| Path traversal | High | `reports/html.go`, `api/router.go` | User-controlled paths not validated against traversal attacks |
| IP spoofing | High | `api/router.go` | `X-Forwarded-For` header trusted for rate limiting without validation |
| Rate limit global state | High | `flood_cmd.go` | Token bucket uses global state, not per-interface |
| evictPCRECache deadlock | High | `engine.go:289-292` | Lock held during map iteration, causes deadlock under cache eviction |
| Context misuse | Medium-High | `flood_cmd.go` | `context.TODO()` left in code; `context.Background()` used inappropriately |

### Medium Priority Issues

| Issue | Severity | Location | Description |
|-------|----------|----------|-------------|
| ICMP IPv6 not supported | Medium | `generator.go:713-751` | ICMP builder only handles IPv4; inconsistent with TCP/UDP which support both |
| TCP flags from_client semantic | Medium | `generator.go:482-485` | `from_client` comment says "server-to-client" but should be client-to-server |
| Duplicate dsize check | Low-Medium | `parser.go:499-500` | Dead code - identical `dsize:` check appears twice |
| threshold/rate_filter silent ignore | Medium | `parser.go:484-487` | `threshold` and `rate_filter` errors silently ignored; only `detection_filter` validates |
| Protocol validation missing | Low | `parser.go:281-299` | Invalid protocol stored without error |
| Empty flowbits name | Low | `parser.go:2078-2104` | `flowbits:set,` (empty name) accepted without error |
| Unknown options silent | Low | `parser.go:1802-1809` | Malformed options with typos accepted as `name:"true"` |
| Repeated regex compilation | Low | `parser.go` (throughout) | `regexp.MustCompile` called per-parse instead of package-level |

### Known Issues (Previously Identified)

| Issue | Status | Location | Description |
|-------|--------|----------|-------------|
| Engine flowbit Lock/RLock deadlock | Fixed | `engine.go:139-141` | Fixed by removing internal RLock from `checkFlowbits` |
| FloodEngine batch deadlock | Known | `flood_cmd.go` | Dead code path with `if false { FloodEngine... }` |
| AFpacketTXRing SendTimeout | Known | `afpacket_linux.go` | `TPACKET_V3` timeout needs verification |
| Banner write timeout missing | Known | `scanner.go` | Service detection doesn't set write deadline |

## Testing
- [ ] Unit tests for engine selection and parameter validation.
- [ ] Integration tests for Linux build-tag paths.
- [ ] Load tests matrix:
  - [ ] 64B / 256B / 1400B payload
  - [ ] 1 / 4 / 8 workers
  - [ ] fixed PPS and unlimited mode
- [ ] Regression: ensure `pcap` behavior unchanged.

## Deliverables
- [ ] CLI/API docs update (`README.md` + examples).
- [ ] Performance report (before/after).
- [ ] Safe defaults and fallback behavior documented.

