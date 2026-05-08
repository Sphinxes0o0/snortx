package packets

import (
	"os"
	"strings"
	"testing"

	"github.com/user/snortx/internal/rules"
)

func TestParseTxEngine(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    TxEngine
		wantErr bool
	}{
		{name: "default empty", in: "", want: TxEnginePCAP},
		{name: "pcap", in: "pcap", want: TxEnginePCAP},
		{name: "sendmmsg", in: "sendmmsg", want: TxEngineSendMmsg},
		{name: "afpacket", in: "afpacket", want: TxEngineAFPacket},
		{name: "invalid", in: "foo", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTxEngine(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTxEngine() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseTxEngine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewSenderWithModeAndEngine_UnimplementedEngine(t *testing.T) {
	_, err := NewSenderWithModeAndEngine(t.TempDir(), "lo0", ModeInject, TxEngineSendMmsg)
	if err == nil {
		t.Fatal("expected error for unimplemented tx engine")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSender_SendAndRecord_WritesMultiplePackets(t *testing.T) {
	outputDir := t.TempDir()
	sender, err := NewSender(outputDir, "lo0")
	if err != nil {
		t.Fatalf("NewSender() error = %v", err)
	}
	defer sender.Close()

	generator := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:        "tcp",
		SrcNet:          "192.168.1.1",
		DstNet:          "10.0.0.1",
		SrcPorts:        "12345",
		DstPorts:        "80",
		Direction:       "<>",
		IsBidirectional: true,
		RuleID:          rules.RuleID{SID: 42},
		Contents:        []rules.ContentMatch{{Raw: []byte("payload")}},
	}

	pkts, err := generator.Generate(rule)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	result := sender.SendAndRecord(rule, pkts)
	if result.PacketsWritten != 2 {
		t.Fatalf("expected 2 packets written, got %d", result.PacketsWritten)
	}

	info, err := os.Stat(result.PCAPPath)
	if err != nil {
		t.Fatalf("expected pcap file to exist: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected non-empty pcap file")
	}
}
