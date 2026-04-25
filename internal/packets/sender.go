package packets

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

type packetInjector interface {
	WritePacketData(data []byte) error
	Close()
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
		handle, err := pcap.OpenLive(iface, 65536, true, -1)
		if err != nil {
			return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
		}
		return handle, nil
	case TxEngineSendMmsg:
		return nil, fmt.Errorf("tx engine %q is not implemented yet", txEngine)
	case TxEngineAFPacket:
		return nil, fmt.Errorf("tx engine %q is not implemented yet", txEngine)
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
		w := pcapgo.NewWriter(bw)
		if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
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

	for _, pkt := range packets {
		data := pkt.Data()
		if len(data) == 0 {
			continue
		}

		if s.Mode == ModeInject || s.Mode == ModeBoth {
			if s.injector != nil && s.injector.WritePacketData(data) == nil {
				sent++
			}
		} else {
			sent++
		}

		if s.Mode != ModeInject && f != nil && bw != nil {
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

			if err := pcapgo.NewWriter(bw).WritePacket(ci, data); err == nil {
				written++
			}
		}
	}

	// Flush buffer before closing
	if bw != nil {
		bw.Flush()
	}

	return SendResult{
		RuleSID:        rule.RuleID.SID,
		RuleMsg:        rule.Msg,
		PacketsSent:    sent,
		PacketsWritten: written,
		PCAPPath:       pcapFile,
		Status:         "success",
	}
}
