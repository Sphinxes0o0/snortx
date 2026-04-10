package engine

import (
	"os"
	"sync"
	"testing"

	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/rules"
)

func TestEngine_ProcessRule(t *testing.T) {
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
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
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
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
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
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
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
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
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
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

func TestEngine_ConcurrencyStress(t *testing.T) {
	// Run with race detector to catch data races
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	// Create engine with many workers for stress testing
	workerCount := 8
	eng, err := New(EngineConfig{
		Generator:   generator,
		Sender:      sender,
		WorkerCount: workerCount,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create many rules to stress test concurrency
	ruleCount := 100
	rulesList := make([]*rules.ParsedRule, ruleCount)
	protocols := []string{"tcp", "udp", "icmp", "ip"}
	ports := []string{"80", "443", "53", "8080"}

	for i := 0; i < ruleCount; i++ {
		proto := protocols[i%len(protocols)]
		port := ports[i%len(ports)]
		rulesList[i] = &rules.ParsedRule{
			Protocol:  proto,
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  port,
			Direction: "->",
			RuleID:    rules.RuleID{SID: i + 1},
			Msg:       "stress test rule",
			Contents: []rules.ContentMatch{
				{Raw: []byte("test")},
			},
		}
	}

	// Run the engine multiple times to stress test
	iterations := 10
	for iter := 0; iter < iterations; iter++ {
		result, err := eng.Run(rulesList)
		if err != nil {
			t.Fatalf("Run() iteration %d error = %v", iter, err)
		}

		if result.TotalRules != ruleCount {
			t.Errorf("iteration %d: expected TotalRules %d, got %d", iter, ruleCount, result.TotalRules)
		}

		if result.SuccessCount != ruleCount {
			t.Errorf("iteration %d: expected SuccessCount %d, got %d", iter, ruleCount, result.SuccessCount)
		}

		if result.FailureCount != 0 {
			t.Errorf("iteration %d: expected FailureCount 0, got %d", iter, result.FailureCount)
		}
	}
}

func TestEngine_ConcurrentRuleGeneration(t *testing.T) {
	// Test that concurrent packet generation doesn't cause data races
	// when each goroutine uses its own Engine instance
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	// Create rules with different protocols
	rulesList := []*rules.ParsedRule{
		{
			Protocol:  "tcp",
			SrcNet:    "192.168.1.1",
			DstNet:    "10.0.0.1",
			SrcPorts:  "12345",
			DstPorts:  "80",
			Direction: "->",
			RuleID:    rules.RuleID{SID: 1},
			Msg:       "TCP test",
			Contents: []rules.ContentMatch{
				{Raw: []byte("GET")},
			},
		},
		{
			Protocol:  "udp",
			SrcNet:    "192.168.1.2",
			DstNet:    "10.0.0.2",
			SrcPorts:  "54321",
			DstPorts:  "53",
			Direction: "->",
			RuleID:    rules.RuleID{SID: 2},
			Msg:       "UDP test",
			Contents: []rules.ContentMatch{
				{Raw: []byte("dns")},
			},
		},
		{
			Protocol:  "icmp",
			SrcNet:    "192.168.1.3",
			DstNet:    "10.0.0.3",
			SrcPorts:  "any",
			DstPorts:  "any",
			Direction: "->",
			RuleID:    rules.RuleID{SID: 3},
			Msg:       "ICMP test",
			Contents: []rules.ContentMatch{
				{Raw: []byte("ping")},
			},
		},
	}

	// Run multiple times concurrently with separate engine instances
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine creates its own engine to avoid data races
			eng, err := New(EngineConfig{
				Generator:   generator,
				Sender:      sender,
				WorkerCount: 4,
				OutputDir:   tmpDir,
			})
			if err != nil {
				t.Errorf("New() error = %v", err)
				return
			}
			result, err := eng.Run(rulesList)
			if err != nil {
				t.Errorf("Concurrent Run() error = %v", err)
				return
			}
			if result.TotalRules != len(rulesList) {
				t.Errorf("expected TotalRules %d, got %d", len(rulesList), result.TotalRules)
			}
		}()
	}
	wg.Wait()
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
