package main

import (
	"testing"
	"time"

	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/pkg/config"
)

func TestExpandTargets_List(t *testing.T) {
	targets, err := expandTargets("127.0.0.1,localhost", 32)
	if err != nil {
		t.Fatalf("expandTargets() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
}

func TestExpandTargets_CIDR(t *testing.T) {
	targets, err := expandTargets("192.168.10.0/30", 16)
	if err != nil {
		t.Fatalf("expandTargets() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
}

func TestParsePayloadHex(t *testing.T) {
	payload, err := parsePayload("", "414243")
	if err != nil {
		t.Fatalf("parsePayload() error = %v", err)
	}
	if string(payload) != "ABC" {
		t.Fatalf("payload = %q, want %q", string(payload), "ABC")
	}
}

func TestValidateFloodParams(t *testing.T) {
	if err := validateFloodParams(1, 0, 0, 0, false, time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateFloodParams(1, 0, 0, 0, true, time.Second); err == nil {
		t.Fatal("expected error when strict mode has no count")
	}
	if err := validateFloodParams(1, 0, 10, 0, true, time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateFloodParams(1, 0, 0, 0, false, 0); err == nil {
		t.Fatal("expected error when count is 0 and duration is 0")
	}
}

func TestSenderTxEngineFromConfig(t *testing.T) {
	cfg := config.LoadDefault()
	engine, err := senderTxEngineFromConfig(cfg)
	if err != nil {
		t.Fatalf("senderTxEngineFromConfig() error = %v", err)
	}
	if engine != packets.TxEnginePCAP {
		t.Fatalf("senderTxEngineFromConfig() = %q, want %q", engine, packets.TxEnginePCAP)
	}

	cfg.Engine.Sender.TxEngine = "invalid_engine"
	if _, err := senderTxEngineFromConfig(cfg); err == nil {
		t.Fatal("expected error for invalid tx engine")
	}
}
