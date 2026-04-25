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
- [ ] Add benchmark command options for flood path (`--engine`, `--packet-size`, `--stats-json`).
- [ ] Record baseline PPS/CPU/drop on current `pcap` engine.
- [ ] Define acceptance thresholds:
  - [ ] PPS uplift vs `pcap`
  - [ ] CPU per Mpps
  - [ ] drop/error budget

## Phase 1: Engine abstraction
- [ ] Introduce sender engine interface in `internal/packets`:
  - [ ] `pcap` (existing)
  - [ ] `sendmmsg` (new)
  - [ ] `afpacket` (new)
- [ ] Add CLI flag: `snortx flood --engine pcap|sendmmsg|afpacket`.
- [ ] Add config key (YAML): `engine.sender.tx_engine`.
- [ ] Keep default as `pcap` for safety.

## Phase 2: sendmmsg implementation (Linux)
- [ ] Add Linux-only file with build tags.
- [ ] Implement raw socket + `sendmmsg` batching:
  - [ ] batch size tuning (`--batch-size`)
  - [ ] socket buffer tuning (`SO_SNDBUF`)
  - [ ] optional busy-poll loop for high rate
- [ ] Expose runtime stats:
  - [ ] attempted/sent/failed
  - [ ] syscall count
  - [ ] effective batch size

## Phase 3: AF_PACKET TX_RING implementation (Linux)
- [ ] Add Linux-only `AF_PACKET` sender.
- [ ] Implement TX_RING setup and frame enqueue/commit.
- [ ] Add ring tuning flags:
  - [ ] block/frame size
  - [ ] ring depth
  - [ ] wakeup policy
- [ ] Add clear fallback: if setup fails, fallback to `sendmmsg` or `pcap`.

## Phase 4: strict mode reliability
- [ ] Extend `flood --strict` with engine-aware completion semantics.
- [ ] Add optional egress verification (`--verify-egress`):
  - [ ] mirror capture on same NIC with BPF filter
  - [ ] correlate by tuple + payload signature
- [ ] Integrate NIC counters (`tx_packets`, `tx_dropped`) into report.

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

