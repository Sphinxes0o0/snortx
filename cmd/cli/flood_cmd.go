package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/rules"
)

var (
	floodProtocol      string
	floodPort          int
	floodSrcIP         string
	floodSrcPort       int
	floodTCPFlags      string
	floodTTL           int
	floodPayload       string
	floodPayloadHex    string
	floodInterface     string
	floodMode          string
	floodEngine        string
	floodWorkers       int
	floodRate          int
	floodCount         int
	floodStrict        bool
	floodMaxRetries    int
	floodDuration      time.Duration
	floodStatsInterval time.Duration
	floodPacketSize    int
	floodStatsJSON     bool
	floodBurst         bool
	floodMultiHandle   bool
	floodRawSocket     bool
	floodBufferPool    bool
	floodBatchSize     int
)

var floodCmd = &cobra.Command{
	Use:   "flood <target>",
	Short: "High-speed packet flood (hping3 style)",
	Args:  cobra.ExactArgs(1),
	RunE:  runFlood,
}

func init() {
	rootCmd.AddCommand(floodCmd)

	floodCmd.Flags().StringVar(&floodProtocol, "protocol", "tcp", "Protocol: tcp, udp, icmp")
	floodCmd.Flags().IntVarP(&floodPort, "port", "p", 80, "Destination port (tcp/udp)")
	floodCmd.Flags().StringVar(&floodSrcIP, "src-ip", "", "Source IP")
	floodCmd.Flags().IntVar(&floodSrcPort, "src-port", 12345, "Source port (tcp/udp)")
	floodCmd.Flags().StringVar(&floodTCPFlags, "tcp-flags", "syn", "TCP flags, e.g. syn,ack,psh")
	floodCmd.Flags().IntVar(&floodTTL, "ttl", 64, "IP TTL / IPv6 hop limit")
	floodCmd.Flags().StringVar(&floodPayload, "payload", "snortx-flood", "Payload string")
	floodCmd.Flags().StringVar(&floodPayloadHex, "payload-hex", "", "Payload as hex bytes")
	floodCmd.Flags().IntVar(&floodPacketSize, "packet-size", 0, "Total packet size in bytes (payload is padded if smaller)")
	floodCmd.Flags().StringVarP(&floodInterface, "interface", "i", "lo0", "Network interface")
	floodCmd.Flags().StringVar(&floodMode, "mode", "inject", "Send mode: inject, both")
	floodCmd.Flags().StringVar(&floodEngine, "engine", "pcap", "TX engine: pcap, sendmmsg, afpacket")
	floodCmd.Flags().IntVarP(&floodWorkers, "workers", "w", 4, "Parallel sender workers")
	floodCmd.Flags().IntVar(&floodRate, "rate", 0, "Packets per second (0=unlimited)")
	floodCmd.Flags().IntVar(&floodCount, "count", 0, "Target packet count (strict=successful packets, best-effort=attempts; 0=use --duration)")
	floodCmd.Flags().BoolVar(&floodStrict, "strict", false, "Enable strict completion mode (requires --count)")
	floodCmd.Flags().IntVar(&floodMaxRetries, "max-retries", 3, "Retry budget per packet in strict mode")
	floodCmd.Flags().DurationVar(&floodDuration, "duration", 10*time.Second, "Flood duration")
	floodCmd.Flags().DurationVar(&floodStatsInterval, "stats-interval", time.Second, "Stats print interval")
	floodCmd.Flags().BoolVar(&floodStatsJSON, "stats-json", false, "Output flood stats as JSON")
	floodCmd.Flags().BoolVar(&floodBurst, "burst", false, "Use burst sender (single writer goroutine, reduces pcap handle contention)")
	floodCmd.Flags().BoolVar(&floodMultiHandle, "multi-handle", false, "Use multiple pcap handles (one per worker) for reduced contention")
	floodCmd.Flags().BoolVar(&floodRawSocket, "raw-socket", false, "Use raw sockets instead of pcap (may improve performance on some platforms)")
	floodCmd.Flags().BoolVar(&floodBufferPool, "buffer-pool", false, "Use pre-allocated buffer pool to reduce GC pressure")
	floodCmd.Flags().IntVar(&floodBatchSize, "batch-size", 0, "Batch size for packet sending (0=disabled, N=batch N packets)")
}

func runFlood(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()

	if err := validateFloodParams(floodWorkers, floodRate, floodCount, floodMaxRetries, floodStrict, floodDuration); err != nil {
		return err
	}

	mode, err := parseFloodMode(floodMode)
	if err != nil {
		return err
	}
	if mode == packets.ModePCAP {
		return fmt.Errorf("flood command requires inject or both mode")
	}

	engineName := floodEngine
	if !cmd.Flags().Changed("engine") && cfg.Engine.Sender.TxEngine != "" {
		engineName = cfg.Engine.Sender.TxEngine
	}
	txEngine, err := packets.ParseTxEngine(engineName)
	if err != nil {
		return err
	}

	targetIP, err := resolveTargetIP(args[0])
	if err != nil {
		return err
	}
	payload, err := parsePayload(floodPayload, floodPayloadHex)
	if err != nil {
		return err
	}

	// Pad payload to reach target packet size
	if floodPacketSize > 0 {
		payload, err = padPayload(payload, floodPacketSize)
		if err != nil {
			return err
		}
	}

	generator := packets.NewGenerator()
	if floodSrcIP != "" {
		generator.DefaultSrcIP = floodSrcIP
	}
	if floodSrcPort > 0 {
		generator.DefaultSrcPort = uint16(floodSrcPort)
	}
	if floodPort > 0 {
		generator.DefaultDstPort = uint16(floodPort)
	}
	generator.DefaultDstIP = targetIP

	protocol := strings.ToLower(strings.TrimSpace(floodProtocol))
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	rule := &rules.ParsedRule{
		Protocol:  protocol,
		SrcNet:    generator.DefaultSrcIP,
		DstNet:    targetIP,
		SrcPorts:  strconv.Itoa(int(generator.DefaultSrcPort)),
		DstPorts:  strconv.Itoa(int(generator.DefaultDstPort)),
		Direction: "->",
		RuleID:    rules.RuleID{SID: 9000001, REV: 1, GID: 1},
		Msg:       fmt.Sprintf("flood %s:%d", targetIP, floodPort),
		Contents:  []rules.ContentMatch{{Raw: payload}},
		Options: map[string]string{
			"ttl": strconv.Itoa(floodTTL),
		},
	}
	if protocol == "tcp" {
		rule.Options["tcp_flags"] = floodTCPFlags
	}

	pkts, err := generator.Generate(rule)
	if err != nil {
		return fmt.Errorf("failed to build flood packet: %w", err)
	}
	if len(pkts) == 0 || len(pkts[0].Data()) == 0 {
		return fmt.Errorf("no packet bytes generated")
	}
	packetData := pkts[0].Data()

	sender, err := packets.NewSenderWithModeAndEngine(outputDir, floodInterface, mode, txEngine)
	if err != nil {
		return fmt.Errorf("failed to create sender: %w", err)
	}
	defer sender.Close()

	// Determine packet injector based on flags
	var injector packets.PacketInjector
	if floodRawSocket && (mode == packets.ModeInject || mode == packets.ModeBoth) {
		// Use raw sockets instead of pcap
		rawInjector, err := packets.NewRawSocketInjector(floodWorkers)
		if err != nil {
			return fmt.Errorf("failed to create raw socket injector: %w", err)
		}
		defer rawInjector.Close()
		injector = rawInjector
	} else if txEngine == packets.TxEngineSendMmsg && (mode == packets.ModeInject || mode == packets.ModeBoth) {
		// Use sendmmsg for high-performance batch sending (Linux only)
		sendmmsgInjector, err := packets.NewMultiSendMmsgInjector(targetIP, floodPort, floodWorkers)
		if err != nil {
			return fmt.Errorf("failed to create sendmmsg injector: %w", err)
		}
		defer sendmmsgInjector.Close()
		injector = sendmmsgInjector
	} else if txEngine == packets.TxEngineAFPacket && (mode == packets.ModeInject || mode == packets.ModeBoth) {
		// Use AF_PACKET TX_RING for highest performance (Linux only)
		afpacketConfig := packets.DefaultAFpacketConfig(floodInterface)
		afpacketInjector, err := packets.NewMultiAFpacketInjector(afpacketConfig, floodWorkers)
		if err != nil {
			return fmt.Errorf("failed to create afpacket injector: %w", err)
		}
		defer afpacketInjector.Close()
		injector = afpacketInjector
	} else if floodMultiHandle && (mode == packets.ModeInject || mode == packets.ModeBoth) {
		// Use multiple pcap handles, one per worker
		multiSender, err := packets.NewMultiSender(floodInterface, floodWorkers)
		if err != nil {
			return fmt.Errorf("failed to create multi-handle sender: %w", err)
		}
		mi := packets.NewMultiInjector(multiSender)
		defer mi.Close() // MultiInjector.Close() closes the underlying MultiSender
		injector = mi
	} else if floodBurst && (mode == packets.ModeInject || mode == packets.ModeBoth) {
		// Use burst sender (single writer goroutine)
		burstSender := packets.NewBurstSender(sender, floodWorkers*256)
		defer burstSender.Close()
		injector = burstSender
	} else {
		injector = sender
	}

	// FloodEngine path is disabled - it has issues with rate limiter handling
	// and batch sending that need to be resolved before re-enabling.
	// The direct send path below handles all current use cases correctly.
	return runFloodDirect(cmd, injector, packetData, targetIP, protocol, engineName)
}

// runFloodDirect is the original direct send implementation
func runFloodDirect(cmd *cobra.Command, injector packets.PacketInjector, packetData []byte, targetIP, protocol, engineName string) error {
	var (
		sent      int64
		failed    int64
		attempted int64
	)

	requiredSuccess := int64(0)
	maxAttempts := int64(0)
	if floodStrict {
		requiredSuccess = int64(floodCount)
		maxAttempts = int64(floodCount) * int64(floodMaxRetries+1)
	}

	ctx := context.Background()
	cancel := func() {}
	if floodCount == 0 {
		ctx, cancel = context.WithTimeout(ctx, floodDuration)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	stopStats := make(chan struct{})
	if floodStatsJSON {
		go printFloodStatsJSON(stopStats, &sent, &failed, &attempted, floodStatsInterval, targetIP, protocol, floodPort, floodWorkers, floodPacketSize, engineName)
	} else {
		go printFloodStats(stopStats, &sent, &failed, floodStatsInterval)
	}

	tokenCh, stopRate := startRateLimiter(floodRate)
	defer stopRate()

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < floodWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				nextAttempt := atomic.AddInt64(&attempted, 1)
				if floodCount > 0 {
					if floodStrict {
						if nextAttempt > maxAttempts {
							cancel()
							return
						}
					} else if nextAttempt > int64(floodCount) {
						cancel()
						return
					}
				}

				if tokenCh != nil {
					select {
					case <-ctx.Done():
						return
					case <-tokenCh:
					}
				}

				if err := injector.WritePacket(packetData); err != nil {
					atomic.AddInt64(&failed, 1)
				} else {
					nextSent := atomic.AddInt64(&sent, 1)
					if floodStrict && nextSent >= requiredSuccess {
						cancel()
						return
					}
				}
			}
		}()
	}

	wg.Wait()
	close(stopStats)

	elapsed := time.Since(start)
	totalSent := atomic.LoadInt64(&sent)
	totalFailed := atomic.LoadInt64(&failed)
	totalAttempted := atomic.LoadInt64(&attempted)
	pps := 0.0
	if elapsed > 0 {
		pps = float64(totalSent) / elapsed.Seconds()
	}

	if floodStrict && totalSent < requiredSuccess {
		return fmt.Errorf(
			"strict flood incomplete: sent=%d required=%d attempted=%d failed=%d max_attempts=%d",
			totalSent, requiredSuccess, totalAttempted, totalFailed, maxAttempts,
		)
	}

	modeLabel := "best-effort"
	if floodStrict {
		modeLabel = "strict"
	}

	if floodStatsJSON {
		stats := FloodStats{
			Sent:       totalSent,
			Failed:     totalFailed,
			Attempted:  totalAttempted,
			Duration:   elapsed.String(),
			PPS:        pps,
			Target:     targetIP,
			Protocol:   protocol,
			Port:       floodPort,
			Workers:    floodWorkers,
			Engine:     engineName,
			PacketSize: floodPacketSize,
		}
		out, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Printf("Flood finished:\n%s\n", string(out))
	} else {
		fmt.Printf(
			"Flood finished: mode=%s target=%s protocol=%s attempted=%d sent=%d failed=%d duration=%s pps=%.2f\n",
			modeLabel, targetIP, protocol, totalAttempted, totalSent, totalFailed, elapsed, pps,
		)
	}

	return nil
}

// runFloodEngine uses the FloodEngine for high-performance flooding
func runFloodEngine(cmd *cobra.Command, injector packets.PacketInjector, packetData []byte, targetIP, protocol, engineName string) error {
	config := packets.FloodConfig{
		Workers:    floodWorkers,
		PacketSize: floodPacketSize,
		BufferPool: floodBufferPool,
		BatchSize:  floodBatchSize,
	}

	engine := packets.NewFloodEngine(config, injector)

	tokenCh, stopRate := startRateLimiter(floodRate)
	defer stopRate()

	// Run the flood - FloodEngine handles all timing internally
	result := engine.Run(packetData, int64(floodCount), floodDuration, tokenCh)

	if floodStrict && result.Sent < int64(floodCount) {
		return fmt.Errorf(
			"strict flood incomplete: sent=%d required=%d attempted=%d failed=%d",
			result.Sent, floodCount, result.Attempted, result.Failed,
		)
	}

	modeLabel := "best-effort"
	if floodStrict {
		modeLabel = "strict"
	}

	if floodStatsJSON {
		stats := FloodStats{
			Sent:       result.Sent,
			Failed:     result.Failed,
			Attempted:  result.Attempted,
			Duration:   result.Duration.String(),
			PPS:        result.PPS,
			Target:     targetIP,
			Protocol:   protocol,
			Port:       floodPort,
			Workers:    floodWorkers,
			Engine:     engineName,
			PacketSize: floodPacketSize,
		}
		out, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Printf("Flood finished:\n%s\n", string(out))
	} else {
		fmt.Printf(
			"Flood finished: mode=%s target=%s protocol=%s attempted=%d sent=%d failed=%d duration=%s pps=%.2f\n",
			modeLabel, targetIP, protocol, result.Attempted, result.Sent, result.Failed, result.Duration, result.PPS,
		)
	}

	return nil
}

func parseFloodMode(mode string) (packets.SendMode, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "inject":
		return packets.ModeInject, nil
	case "both":
		return packets.ModeBoth, nil
	case "pcap":
		return packets.ModePCAP, nil
	default:
		return packets.ModePCAP, fmt.Errorf("invalid mode: %s", mode)
	}
}

func validateFloodParams(workers, rate, count, maxRetries int, strict bool, duration time.Duration) error {
	if workers <= 0 {
		return fmt.Errorf("workers must be > 0")
	}
	if rate < 0 {
		return fmt.Errorf("rate must be >= 0")
	}
	if count < 0 {
		return fmt.Errorf("count must be >= 0")
	}
	if maxRetries < 0 {
		return fmt.Errorf("max-retries must be >= 0")
	}
	if strict && count <= 0 {
		return fmt.Errorf("strict mode requires --count > 0")
	}
	if duration <= 0 && count == 0 {
		return fmt.Errorf("duration must be > 0 when count is 0")
	}
	return nil
}

func resolveTargetIP(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("empty target")
	}
	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), nil
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target %s: %w", target, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	return "", fmt.Errorf("no ip found for target %s", target)
}

func parsePayload(payload string, payloadHex string) ([]byte, error) {
	payloadHex = strings.TrimSpace(payloadHex)
	if payloadHex != "" {
		decoded, err := hex.DecodeString(strings.ReplaceAll(payloadHex, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid payload-hex: %w", err)
		}
		return decoded, nil
	}
	return []byte(payload), nil
}

// startRateLimiter creates a token bucket rate limiter that is shared by all
// workers within a single flood operation. This is the correct behavior since
// the flood command operates on a single interface at a time. Each invocation
// of startRateLimiter creates an independent rate limiter for that flood.
func startRateLimiter(rate int) (<-chan struct{}, func()) {
	if rate <= 0 {
		return nil, func() {}
	}

	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	ticker := time.NewTicker(interval)
	ch := make(chan struct{}, 1024)
	stop := make(chan struct{})
	go func() {
		defer close(ch)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()

	return ch, func() {
		close(stop)
		ticker.Stop()
	}
}

func printFloodStats(stop <-chan struct{}, sent *int64, failed *int64, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastSent int64
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			curSent := atomic.LoadInt64(sent)
			curFailed := atomic.LoadInt64(failed)
			delta := curSent - lastSent
			lastSent = curSent
			pps := float64(delta) / interval.Seconds()
			fmt.Printf("flood stats: sent=%d failed=%d pps=%.2f\n", curSent, curFailed, pps)
		}
	}
}

// FloodStats holds flood execution statistics for JSON output
type FloodStats struct {
	Sent      int64   `json:"sent"`
	Failed    int64   `json:"failed"`
	Attempted int64   `json:"attempted"`
	Duration  string  `json:"duration"`
	PPS       float64 `json:"pps"`
	Target    string  `json:"target"`
	Protocol  string  `json:"protocol"`
	Port      int     `json:"port"`
	Workers   int     `json:"workers"`
	Engine    string  `json:"engine"`
	PacketSize int    `json:"packet_size,omitempty"`
}

func printFloodStatsJSON(stop <-chan struct{}, sent *int64, failed *int64, attempted *int64, interval time.Duration, target, protocol string, port, workers, packetSize int, engine string) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	start := time.Now()
	var lastSent int64
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			curSent := atomic.LoadInt64(sent)
			curFailed := atomic.LoadInt64(failed)
			curAttempted := atomic.LoadInt64(attempted)
			delta := curSent - lastSent
			lastSent = curSent
			elapsed := time.Since(start)
			pps := float64(delta) / interval.Seconds()

			stats := FloodStats{
				Sent:       curSent,
				Failed:     curFailed,
				Attempted:  curAttempted,
				Duration:   elapsed.String(),
				PPS:        pps,
				Target:     target,
				Protocol:   protocol,
				Port:       port,
				Workers:    workers,
				Engine:     engine,
				PacketSize: packetSize,
			}
			out, _ := json.MarshalIndent(stats, "", "  ")
			fmt.Println(string(out))
		}
	}
}

// padPayload pads payload to reach target packet size.
// Overhead: Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes
func padPayload(payload []byte, targetPacketSize int) ([]byte, error) {
	const overhead = 54 // Ethernet + IPv4 + TCP
	if targetPacketSize <= overhead {
		return nil, fmt.Errorf("packet size %d is too small (minimum: %d)", targetPacketSize, overhead+1)
	}
	targetPayloadSize := targetPacketSize - overhead
	if len(payload) >= targetPayloadSize {
		return payload[:targetPayloadSize], nil
	}
	// Pad by repeating the payload pattern
	padded := make([]byte, targetPayloadSize)
	for i := range padded {
		padded[i] = payload[i%len(payload)]
	}
	return padded, nil
}
