package main

import (
	"context"
	"encoding/hex"
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
	go printFloodStats(stopStats, &sent, &failed, floodStatsInterval)

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

				if err := sender.InjectPacket(packetData); err != nil {
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
	fmt.Printf(
		"Flood finished: mode=%s target=%s protocol=%s attempted=%d sent=%d failed=%d duration=%s pps=%.2f\n",
		modeLabel, targetIP, protocol, totalAttempted, totalSent, totalFailed, elapsed, pps,
	)

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
