package packets

import (
	"strings"
	"testing"
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
