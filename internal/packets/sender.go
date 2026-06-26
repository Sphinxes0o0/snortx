package packets

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/user/snortx/internal/rules"
)

type SendMode int

const (
	ModePCAP SendMode = iota
	ModeInject
	ModeBoth
)

type TxEngine string

const (
	TxEnginePCAP     TxEngine = "pcap"
	TxEngineSendMmsg TxEngine = "sendmmsg"
	TxEngineAFPacket TxEngine = "afpacket"
)

func ParseTxEngine(s string) (TxEngine, error) {
	switch TxEngine(strings.ToLower(strings.TrimSpace(s))) {
	case "", TxEnginePCAP:
		return TxEnginePCAP, nil
	case TxEngineSendMmsg:
		return TxEngineSendMmsg, nil
	case TxEngineAFPacket:
		return TxEngineAFPacket, nil
	default:
		return "", fmt.Errorf("invalid tx engine: %s", s)
	}
}

type SendResult struct {
	RuleSID        int           `json:"rule_sid"`
	RuleMsg        string        `json:"rule_msg"`
	Protocol       string        `json:"protocol"`
	PacketsGen     int           `json:"packets_generated"`
	PacketsSent    int           `json:"packets_sent"`
	PacketsWritten int           `json:"packets_written"`
	PCAPPath       string        `json:"pcap_path"`
	Status         string        `json:"status"`
	Error          string        `json:"error,omitempty"`
	Duration       time.Duration `json:"duration"`
}

// packetInjector is the internal interface for pcap handle injection
type packetInjector interface {
	WritePacketData(data []byte) error
	Close()
}

// PacketInjector is the exported interface for sending packets
type PacketInjector interface {
	WritePacket(data []byte) error
	Close()
}

// Ensure *Sender implements PacketInjector
var _ PacketInjector = (*Sender)(nil)

func (s *Sender) WritePacket(data []byte) error {
	return s.InjectPacket(data)
}

type Sender struct {
	OutputDir string
	Interface string
	Mode      SendMode
	TxEngine  TxEngine
	injector  packetInjector
}

func NewSender(outputDir, iface string) (*Sender, error) {
	return NewSenderWithMode(outputDir, iface, ModePCAP)
}

func NewSenderWithMode(outputDir, iface string, mode SendMode) (*Sender, error) {
	return NewSenderWithModeAndEngine(outputDir, iface, mode, TxEnginePCAP)
}

func NewSenderWithModeAndEngine(outputDir, iface string, mode SendMode, txEngine TxEngine) (*Sender, error) {
	parsedEngine, err := ParseTxEngine(string(txEngine))
	if err != nil {
		return nil, err
	}

	s := &Sender{
		OutputDir: outputDir,
		Interface: iface,
		Mode:      mode,
		TxEngine:  parsedEngine,
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	if mode == ModeInject || mode == ModeBoth {
		injector, err := newPacketInjector(iface, parsedEngine)
		if err != nil {
			return nil, err
		}
		s.injector = injector
	}

	return s, nil
}

func newPacketInjector(iface string, txEngine TxEngine) (packetInjector, error) {
	switch txEngine {
	case TxEnginePCAP:
		return newPcapHandle(iface)
	case TxEngineSendMmsg:
		// sendmmsg injector is created by the CLI directly
		// since it needs destination IP/port which the sender doesn't have
		return nil, nil
	case TxEngineAFPacket:
		// AF_PACKET injector is created by the CLI directly
		// since it may need custom configuration
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported tx engine: %s", txEngine)
	}
}

func (s *Sender) Close() {
	if s.injector != nil {
		s.injector.Close()
	}
}

// InjectPacket injects a raw packet when sender mode supports live injection.
func (s *Sender) InjectPacket(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty packet data")
	}
	if s.Mode != ModeInject && s.Mode != ModeBoth {
		return fmt.Errorf("sender mode does not support injection")
	}
	if s.injector == nil {
		return fmt.Errorf("pcap handle is not initialized")
	}
	return s.injector.WritePacketData(data)
}

func (s *Sender) SendAndRecord(rule *rules.ParsedRule, packets []gopacket.Packet) SendResult {
	var pcapFile string
	var f *os.File
	var bw *bufio.Writer
	var pcapWriter *pcapgo.Writer
	var err error

	if s.Mode != ModeInject {
		pcapFile = filepath.Join(s.OutputDir, fmt.Sprintf("rule_%d.pcap", rule.RuleID.SID))
		f, err = os.Create(pcapFile)
		if err != nil {
			return SendResult{
				RuleSID: rule.RuleID.SID,
				RuleMsg: rule.Msg,
				Status:  "failed",
				Error:   fmt.Sprintf("failed to create pcap file: %v", err),
			}
		}
		defer f.Close()

		// Use buffered writer for better performance
		bw = bufio.NewWriter(f)
		pcapWriter = pcapgo.NewWriter(bw)
		if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			f.Close()
			return SendResult{
				RuleSID: rule.RuleID.SID,
				RuleMsg: rule.Msg,
				Status:  "failed",
				Error:   fmt.Sprintf("failed to write pcap header: %v", err),
			}
		}
	}

	sent := 0
	written := 0
	var sendErr error

	for _, pkt := range packets {
		data := pkt.Data()
		if len(data) == 0 {
			continue
		}

		if s.Mode == ModeInject || s.Mode == ModeBoth {
			if s.injector != nil {
				if err := s.injector.WritePacketData(data); err != nil {
					sendErr = err
				} else {
					sent++
				}
			}
		} else {
			sent++
		}

		if s.Mode != ModeInject && f != nil && bw != nil && pcapWriter != nil {
			ci := pkt.Metadata().CaptureInfo
			if ci.CaptureLength == 0 {
				ci.CaptureLength = len(data)
			}
			if ci.Length == 0 {
				ci.Length = len(data)
			}
			if ci.Timestamp.IsZero() {
				ci.Timestamp = time.Now()
			}

			if err := pcapWriter.WritePacket(ci, data); err == nil {
				written++
			}
		}
	}

	// Flush buffer before closing
	if bw != nil {
		bw.Flush()
	}

	result := SendResult{
		RuleSID:        rule.RuleID.SID,
		RuleMsg:        rule.Msg,
		PacketsSent:    sent,
		PacketsWritten: written,
		PCAPPath:       pcapFile,
		Status:         "success",
	}
	if sendErr != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("packet send error: %v", sendErr)
	}
	return result
}

// BurstSender provides batched packet sending via a single writer goroutine.
// This avoids pcap handle contention when multiple goroutines call WritePacketData.
type BurstSender struct {
	sender  *Sender
	packetCh chan []byte
	done    chan struct{}
	wg      sync.WaitGroup
}

// Ensure *BurstSender implements PacketInjector
var _ PacketInjector = (*BurstSender)(nil)

// NewBurstSender creates a BurstSender that batches packet sends through a single goroutine.
func NewBurstSender(sender *Sender, queueSize int) *BurstSender {
	if queueSize <= 0 {
		queueSize = 4096
	}
	bs := &BurstSender{
		sender:  sender,
		packetCh: make(chan []byte, queueSize),
		done:    make(chan struct{}),
	}
	bs.wg.Add(1)
	go bs.writerLoop()
	return bs
}

// writerLoop reads packets from the channel and sends them one by one.
// This ensures only one goroutine touches the pcap handle.
func (bs *BurstSender) writerLoop() {
	defer bs.wg.Done()
	for {
		select {
		case <-bs.done:
			// Drain remaining packets
			for {
				select {
				case pkt := <-bs.packetCh:
					bs.sender.InjectPacket(pkt)
				default:
					return
				}
			}
		case pkt := <-bs.packetCh:
			bs.sender.InjectPacket(pkt)
		}
	}
}

// WritePacket queues a packet for batch sending.
func (bs *BurstSender) WritePacket(data []byte) error {
	select {
	case bs.packetCh <- data:
		return nil
	default:
		// Channel full, send directly
		return bs.sender.InjectPacket(data)
	}
}

// Close stops the writer loop and waits for completion.
func (bs *BurstSender) Close() {
	close(bs.done)
	bs.wg.Wait()
}


// RawSocketInjector uses raw sockets for packet injection.
// Raw sockets bypass some pcap/libpcap overhead on macOS.
type RawSocketInjector struct {
	addrs   []unix.SockaddrInet4
	fds     []int
	count   int
	nextIdx int32 // atomic: next socket to use
}

// Ensure *RawSocketInjector implements PacketInjector
var _ PacketInjector = (*RawSocketInjector)(nil)

// NewRawSocketInjector creates a raw socket injector with multiple sockets.
// Note: On macOS, use specific protocol (IPPROTO_TCP) instead of IPPROTO_RAW
// because RAW sockets have stricter requirements.
func NewRawSocketInjector(count int) (*RawSocketInjector, error) {
	return newRawSocketInjectorWithProtocol(count, unix.IPPROTO_TCP)
}

// newRawSocketInjectorWithProtocol creates a raw socket injector with a specific IP protocol.
func newRawSocketInjectorWithProtocol(count int, protocol int) (*RawSocketInjector, error) {
	if count <= 0 {
		count = 1
	}
	fds := make([]int, count)
	addrs := make([]unix.SockaddrInet4, count)
	for i := 0; i < count; i++ {
		// Create raw socket with specific protocol (not IPPROTO_RAW on macOS)
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, protocol)
		if err != nil {
			for j := 0; j < i; j++ {
				unix.Close(fds[j])
			}
			return nil, fmt.Errorf("failed to create raw socket: %w", err)
		}
		// Note: Do NOT set IP_HDRINCL with IPPROTO_TCP/UDP.
		// The kernel automatically adds the IP header for protocol-specific raw sockets.
		fds[i] = fd
	}
	return &RawSocketInjector{addrs: addrs, fds: fds, count: count, nextIdx: 0}, nil
}

// WritePacket sends a packet via raw socket.
// With IPPROTO_TCP (no IP_HDRINCL), we send only the L4 payload (TCP header + data).
// The kernel adds the IP header automatically.
func (rsi *RawSocketInjector) WritePacket(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty packet")
	}

	// Check IP version at byte 14 (top 4 bits)
	if len(data) < 15 {
		return fmt.Errorf("packet too short (need at least Ethernet header)")
	}
	version := data[14] >> 4

	if version == 4 {
		// IPv4: Ethernet(14) + IPv4(20) = 34 bytes header
		if len(data) < 34 {
			return fmt.Errorf("packet too short (need at least 34 bytes for Ethernet+IPv4)")
		}
		l4Payload := data[34:]
		if len(l4Payload) == 0 {
			return fmt.Errorf("no L4 payload")
		}
		socketIdx := atomic.AddInt32(&rsi.nextIdx, 1) - 1
		socketIdx = socketIdx % int32(rsi.count) // Round-robin across available sockets
		fd := rsi.fds[socketIdx]
		// Get destination from IPv4 header (bytes 16-19)
		dstIP := [4]byte{data[16], data[17], data[18], data[19]}
		// Get destination port from TCP header (bytes 36-37, after Ethernet+IPv4)
		srcPort := uint16(data[34])<<8 | uint16(data[35])
		dstPort := uint16(data[36])<<8 | uint16(data[37])
		_ = srcPort // unused

		addr := unix.SockaddrInet4{
			Addr: dstIP,
			Port: int(dstPort),
		}
		err := unix.Sendto(fd, l4Payload, 0, &addr)
		if err != nil {
			return err
		}
		return nil
	} else if version == 6 {
		// IPv6: Ethernet(14) + IPv6(40) = 54 bytes header
		// RawSocketInjector uses AF_INET (IPv4 only) so IPv6 is not supported
		return fmt.Errorf("IPv6 not supported with raw socket injector (uses AF_INET)")
	} else {
		return fmt.Errorf("unknown IP version: %d", version)
	}
}

// Close closes all raw sockets.
func (rsi *RawSocketInjector) Close() {
	for _, fd := range rsi.fds {
		unix.Close(fd)
	}
}
