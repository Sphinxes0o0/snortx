package packets

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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

type Sender struct {
	OutputDir  string
	Interface  string
	Mode       SendMode
	pcapHandle *pcap.Handle
}

func NewSender(outputDir, iface string) (*Sender, error) {
	return NewSenderWithMode(outputDir, iface, ModePCAP)
}

func NewSenderWithMode(outputDir, iface string, mode SendMode) (*Sender, error) {
	s := &Sender{
		OutputDir: outputDir,
		Interface: iface,
		Mode:      mode,
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	if mode == ModeInject || mode == ModeBoth {
		handle, err := pcap.OpenLive(iface, 65536, true, -1)
		if err != nil {
			return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
		}
		s.pcapHandle = handle
	}

	return s, nil
}

func (s *Sender) Close() {
	if s.pcapHandle != nil {
		s.pcapHandle.Close()
	}
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
			if err := s.pcapHandle.WritePacketData(data); err == nil {
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
