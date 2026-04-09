package engine

import (
	"os"
	"testing"

	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/rules"
)

func TestEngine_ProcessRule(t *testing.T) {
	tmpDir := t.TempDir()
	parser := rules.NewParser()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Parser:      parser,
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 1,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "any",
		DstNet:    "any",
		SrcPorts:  "any",
		DstPorts:  "80",
		Direction: "->",
		RuleID:    rules.RuleID{SID: 1},
		Msg:       "test rule",
		Contents: []rules.ContentMatch{
			{Raw: []byte("test")},
		},
	}

	result, err := eng.Run([]*rules.ParsedRule{rule})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != 1 {
		t.Errorf("expected 1 result, got %d", result.TotalRules)
	}
}

func TestEngine_Run(t *testing.T) {
	tmpDir := t.TempDir()
	parser := rules.NewParser()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Parser:      parser,
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 2,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rulesList := []*rules.ParsedRule{
		{
			Protocol:  "tcp",
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  "80",
			Direction: "->",
			RuleID:    rules.RuleID{SID: 1},
			Msg:       "test 1",
			Contents: []rules.ContentMatch{
				{Raw: []byte("test1")},
			},
		},
		{
			Protocol:  "udp",
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  "53",
			Direction: "->",
			RuleID:    rules.RuleID{SID: 2},
			Msg:       "test 2",
			Contents: []rules.ContentMatch{
				{Raw: []byte("test2")},
			},
		},
	}

	result, err := eng.Run(rulesList)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != 2 {
		t.Errorf("expected TotalRules 2, got %d", result.TotalRules)
	}

	if result.SuccessCount != 2 {
		t.Errorf("expected SuccessCount 2, got %d", result.SuccessCount)
	}

	if result.FailureCount != 0 {
		t.Errorf("expected FailureCount 0, got %d", result.FailureCount)
	}
}

func TestEngine_RunWithBadRule(t *testing.T) {
	tmpDir := t.TempDir()
	parser := rules.NewParser()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Parser:      parser,
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 2,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rulesList := []*rules.ParsedRule{
		{
			Protocol:  "tcp",
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  "80",
			Direction: "->",
			RuleID:    rules.RuleID{SID: 1},
			Msg:       "test 1",
			Contents: []rules.ContentMatch{
				{Raw: []byte("test1")},
			},
		},
		{
			Protocol: "unsupported_proto",
			RuleID:   rules.RuleID{SID: 2},
			Msg:      "bad rule",
		},
	}

	result, err := eng.Run(rulesList)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != 2 {
		t.Errorf("expected TotalRules 2, got %d", result.TotalRules)
	}

	if result.SuccessCount != 1 {
		t.Errorf("expected SuccessCount 1, got %d", result.SuccessCount)
	}

	if result.FailureCount != 1 {
		t.Errorf("expected FailureCount 1, got %d", result.FailureCount)
	}
}

func TestEngine_Stop(t *testing.T) {
	tmpDir := t.TempDir()
	parser := rules.NewParser()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Parser:      parser,
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 2,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	eng.Stop()
}

func TestEngine_New(t *testing.T) {
	tmpDir := t.TempDir()
	parser := rules.NewParser()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	tests := []struct {
		name       string
		cfg        EngineConfig
		wantErr    bool
		minWorkers int
	}{
		{
			name: "valid config with auto workers",
			cfg: EngineConfig{
				Parser:      parser,
				Generator:   generator,
				Sender:      sender,
				WorkerCount: 0,
				OutputDir:   tmpDir,
			},
			minWorkers: 1,
		},
		{
			name: "valid config with specified workers",
			cfg: EngineConfig{
				Parser:      parser,
				Generator:   generator,
				Sender:      sender,
				WorkerCount: 4,
				OutputDir:   tmpDir,
			},
			minWorkers: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng, err := New(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if eng.WorkerCount < tt.minWorkers {
				t.Errorf("WorkerCount = %d, want >= %d", eng.WorkerCount, tt.minWorkers)
			}
		})
	}
}

func TestEngine_NewWithInvalidConfig(t *testing.T) {
	eng, err := New(EngineConfig{
		Parser:    nil,
		Generator: nil,
		Sender:    nil,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if eng.WorkerCount < 1 {
		t.Errorf("expected WorkerCount >= 1, got %d", eng.WorkerCount)
	}
}

func TestEngine_EmptyRules(t *testing.T) {
	tmpDir := t.TempDir()
	parser := rules.NewParser()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Parser:      parser,
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 2,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := eng.Run([]*rules.ParsedRule{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != 0 {
		t.Errorf("expected TotalRules 0, got %d", result.TotalRules)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
