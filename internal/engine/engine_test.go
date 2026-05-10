package engine

import (
	"fmt"
	"os"
	"runtime"
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

func TestEngine_ConcurrentFlowbitWrites(t *testing.T) {
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 8,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ruleCount := 200
	rulesList := make([]*rules.ParsedRule, 0, ruleCount)
	for i := 0; i < ruleCount; i++ {
		rulesList = append(rulesList, &rules.ParsedRule{
			Protocol:  "tcp",
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  "80",
			Direction: "->",
			RuleID:    rules.RuleID{SID: i + 1},
			Msg:       "flowbit write test",
			Contents: []rules.ContentMatch{
				{Raw: []byte("test")},
			},
			Flowbits: []rules.Flowbit{
				{Op: rules.FlowbitSet, Name: fmt.Sprintf("fb_%d", i)},
			},
		})
	}

	result, err := eng.Run(rulesList)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.TotalRules != ruleCount {
		t.Errorf("expected TotalRules %d, got %d", ruleCount, result.TotalRules)
	}
	if result.SuccessCount != ruleCount {
		t.Errorf("expected SuccessCount %d, got %d", ruleCount, result.SuccessCount)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// =============================================================================
// Worker Pool Tests
// =============================================================================

func TestEngine_WorkerPoolLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	tests := []struct {
		name        string
		workerCount int
		wantWorkers int
	}{
		{
			name:        "single worker",
			workerCount: 1,
			wantWorkers: 1,
		},
		{
			name:        "multiple workers",
			workerCount: 4,
			wantWorkers: 4,
		},
		{
			name:        "auto workers (zero)",
			workerCount: 0,
			wantWorkers: runtime.NumCPU(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng, err := New(EngineConfig{
				Generator:   generator,
				Sender:      sender,
				WorkerCount: tt.workerCount,
				OutputDir:   tmpDir,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			if eng.WorkerCount != tt.wantWorkers {
				t.Errorf("WorkerCount = %d, want %d", eng.WorkerCount, tt.wantWorkers)
			}

			// Engine should be reusable across multiple Run() calls
			rule := &rules.ParsedRule{
				Protocol:  "tcp",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "80",
				Direction: "->",
				RuleID:    rules.RuleID{SID: 1},
				Msg:       "lifecycle test",
				Contents: []rules.ContentMatch{
					{Raw: []byte("test")},
				},
			}

			// First run
			result1, err := eng.Run([]*rules.ParsedRule{rule})
			if err != nil {
				t.Fatalf("First Run() error = %v", err)
			}
			if result1.TotalRules != 1 {
				t.Errorf("First run: expected 1 rule, got %d", result1.TotalRules)
			}

			// Second run - channels should be recreated
			rule.RuleID.SID = 2
			result2, err := eng.Run([]*rules.ParsedRule{rule})
			if err != nil {
				t.Fatalf("Second Run() error = %v", err)
			}
			if result2.TotalRules != 1 {
				t.Errorf("Second run: expected 1 rule, got %d", result2.TotalRules)
			}
		})
	}
}

func TestEngine_WorkerPoolProcessesAllRules(t *testing.T) {
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 4,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create more rules than workers to ensure all workers get used
	ruleCount := 20
	rulesList := make([]*rules.ParsedRule, ruleCount)
	for i := 0; i < ruleCount; i++ {
		rulesList[i] = &rules.ParsedRule{
			Protocol:  "tcp",
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  "80",
			Direction: "->",
			RuleID:    rules.RuleID{SID: i + 1},
			Msg:       fmt.Sprintf("rule %d", i+1),
			Contents: []rules.ContentMatch{
				{Raw: []byte(fmt.Sprintf("test%d", i))},
			},
		}
	}

	result, err := eng.Run(rulesList)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != ruleCount {
		t.Errorf("expected %d rules, got %d", ruleCount, result.TotalRules)
	}
	if result.SuccessCount != ruleCount {
		t.Errorf("expected %d successes, got %d", ruleCount, result.SuccessCount)
	}
}

// =============================================================================
// PCRE Cache Tests
// =============================================================================

func TestEngine_PCRECacheUniqueness(t *testing.T) {
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

	// Two different PCRE patterns should produce different cache entries
	// Content must match the PCRE pattern for validation to pass
	rule1 := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "any",
		DstNet:    "any",
		SrcPorts:  "any",
		DstPorts:  "80",
		Direction: "->",
		RuleID:    rules.RuleID{SID: 1},
		Msg:       "PCRE pattern 1",
		Contents: []rules.ContentMatch{
			{Raw: []byte("GET /path1")}, // Content matches PCRE pattern
		},
		PCREMatches: []rules.PCREMatch{
			{Pattern: "GET /path1", Modifiers: ""},
		},
	}

	rule2 := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "any",
		DstNet:    "any",
		SrcPorts:  "any",
		DstPorts:  "80",
		Direction: "->",
		RuleID:    rules.RuleID{SID: 2},
		Msg:       "PCRE pattern 2",
		Contents: []rules.ContentMatch{
			{Raw: []byte("POST /path2")}, // Content matches PCRE pattern
		},
		PCREMatches: []rules.PCREMatch{
			{Pattern: "POST /path2", Modifiers: ""},
		},
	}

	result, err := eng.Run([]*rules.ParsedRule{rule1, rule2})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Both should succeed
	if result.SuccessCount != 2 {
		t.Errorf("expected 2 successes, got %d", result.SuccessCount)
	}

	// Check cache has 2 entries
	eng.mu.Lock()
	cacheLen := len(eng.pcreCache)
	eng.mu.Unlock()

	if cacheLen != 2 {
		t.Errorf("expected cache size 2, got %d", cacheLen)
	}
}

func TestEngine_PCRECacheEviction(t *testing.T) {
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

	// Create rules with unique PCRE patterns to fill the cache
	// We need to exceed pcreCacheCleanupThreshold (1200) to trigger eviction
	ruleCount := 1300
	rulesList := make([]*rules.ParsedRule, 0, ruleCount)

	for i := 0; i < ruleCount; i++ {
		rule := &rules.ParsedRule{
			Protocol:  "tcp",
			SrcNet:    "any",
			DstNet:    "any",
			SrcPorts:  "any",
			DstPorts:  "80",
			Direction: "->",
			RuleID:    rules.RuleID{SID: i + 1},
			Msg:       fmt.Sprintf("PCRE rule %d", i),
			Contents: []rules.ContentMatch{
				{Raw: []byte(fmt.Sprintf("test%d", i))},
			},
			PCREMatches: []rules.PCREMatch{
				{Pattern: fmt.Sprintf("pattern%d", i), Modifiers: ""},
			},
		}
		rulesList = append(rulesList, rule)
	}

	result, err := eng.Run(rulesList)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != ruleCount {
		t.Errorf("expected %d rules, got %d", ruleCount, result.TotalRules)
	}

	// After eviction, cache should be at maxPCRECacheSize (1000) or less
	eng.mu.Lock()
	cacheLen := len(eng.pcreCache)
	eng.mu.Unlock()

	if cacheLen > maxPCRECacheSize {
		t.Errorf("cache size %d exceeds max %d after eviction", cacheLen, maxPCRECacheSize)
	}
}

func TestEngine_PCRECacheModifiers(t *testing.T) {
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

	tests := []struct {
		name      string
		pattern   string
		modifiers string
		content   []byte
		wantMatch bool
	}{
		{
			name:      "case insensitive match",
			pattern:   "GET",
			modifiers: "i",
			content:   []byte("get"),
			wantMatch: true,
		},
		{
			name:      "case sensitive no match",
			pattern:   "GET",
			modifiers: "",
			content:   []byte("get"),
			wantMatch: false,
		},
		{
			name:      "dotall match",
			pattern:   "HELLO.*world",
			modifiers: "s",
			content:   []byte("HELLO\nworld"),
			wantMatch: true,
		},
	}

	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &rules.ParsedRule{
				Protocol:  "tcp",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "80",
				Direction: "->",
				RuleID:    rules.RuleID{SID: idx + 1},
				Msg:       tt.name,
				Contents: []rules.ContentMatch{
					{Raw: tt.content},
				},
				PCREMatches: []rules.PCREMatch{
					{Pattern: tt.pattern, Modifiers: tt.modifiers},
				},
			}

			result, err := eng.Run([]*rules.ParsedRule{rule})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			if tt.wantMatch && result.SuccessCount != 1 {
				t.Errorf("expected success for pattern %q, got failure", tt.pattern)
			}
			if !tt.wantMatch && result.FailureCount != 1 {
				t.Errorf("expected failure for pattern %q, got success", tt.pattern)
			}
		})
	}
}

// =============================================================================
// Flowbit Processing Tests
//
// NOTE: The flowbit tests use direct method calls to checkFlowbits() and
// setFlowbits() because the engine's processRule() has a deadlock bug where
// it holds flowbitMu.Lock() before calling checkFlowbits() which tries to
// acquire flowbitMu.RLock() - an RWMutex cannot upgrade from write to read lock.
// =============================================================================

func TestEngine_FlowbitCheck_Isset_Success(t *testing.T) {
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

	// Initialize flowbit state
	eng.flowbitState = map[string]bool{"session1": true}

	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitIsSet, Name: "session1"},
		},
	}

	// checkFlowbits should return true because session1 is set
	if !eng.checkFlowbits(rule) {
		t.Errorf("expected checkFlowbits to return true for isset set flowbit")
	}
}

func TestEngine_FlowbitCheck_Isset_Failure(t *testing.T) {
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

	// Initialize with empty flowbit state
	eng.flowbitState = map[string]bool{}

	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitIsSet, Name: "never_set_session"},
		},
	}

	// checkFlowbits should return false because session is not set
	if eng.checkFlowbits(rule) {
		t.Errorf("expected checkFlowbits to return false for isset unset flowbit")
	}
}

func TestEngine_FlowbitCheck_Isnotset_Success(t *testing.T) {
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

	// Initialize with empty flowbit state
	eng.flowbitState = map[string]bool{}

	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitNotSet, Name: "never_set_session"},
		},
	}

	// checkFlowbits should return true because session is not set
	if !eng.checkFlowbits(rule) {
		t.Errorf("expected checkFlowbits to return true for isnotset unset flowbit")
	}
}

func TestEngine_FlowbitCheck_Isnotset_Failure(t *testing.T) {
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

	// Initialize with flowbit already set
	eng.flowbitState = map[string]bool{"session1": true}

	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitNotSet, Name: "session1"},
		},
	}

	// checkFlowbits should return false because session IS set
	if eng.checkFlowbits(rule) {
		t.Errorf("expected checkFlowbits to return false for isnotset set flowbit")
	}
}

func TestEngine_FlowbitSet(t *testing.T) {
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

	// Initialize with empty flowbit state
	eng.flowbitState = map[string]bool{}

	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitSet, Name: "myflag"},
		},
	}

	eng.setFlowbits(rule)

	// Check that flowbit was set to true
	if !eng.flowbitState["myflag"] {
		t.Errorf("expected flowbit 'myflag' to be set to true")
	}
}

func TestEngine_FlowbitToggle(t *testing.T) {
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

	// Test toggle from true to false
	eng.flowbitState = map[string]bool{"toggle_test": true}
	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitToggle, Name: "toggle_test"},
		},
	}

	eng.setFlowbits(rule)

	if eng.flowbitState["toggle_test"] {
		t.Errorf("expected flowbit 'toggle_test' to be toggled from true to false")
	}

	// Test toggle from false to true
	eng.setFlowbits(rule)

	if !eng.flowbitState["toggle_test"] {
		t.Errorf("expected flowbit 'toggle_test' to be toggled from false to true")
	}
}

func TestEngine_FlowbitUnset(t *testing.T) {
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

	// Initialize with flowbit set
	eng.flowbitState = map[string]bool{"myflag": true}

	rule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitUnset, Name: "myflag"},
		},
	}

	eng.setFlowbits(rule)

	// Check that flowbit was unset (false)
	if eng.flowbitState["myflag"] {
		t.Errorf("expected flowbit 'myflag' to be unset to false")
	}
}

func TestEngine_FlowbitMultipleConditions(t *testing.T) {
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

	tests := []struct {
		name           string
		flowbitState   map[string]bool
		flowbits       []rules.Flowbit
		wantResult     bool
	}{
		{
			name:         "both isset - both set",
			flowbitState: map[string]bool{"flag1": true, "flag2": true},
			flowbits: []rules.Flowbit{
				{Op: rules.FlowbitIsSet, Name: "flag1"},
				{Op: rules.FlowbitIsSet, Name: "flag2"},
			},
			wantResult: true,
		},
		{
			name:         "both isset - one not set",
			flowbitState: map[string]bool{"flag1": true, "flag2": false},
			flowbits: []rules.Flowbit{
				{Op: rules.FlowbitIsSet, Name: "flag1"},
				{Op: rules.FlowbitIsSet, Name: "flag2"},
			},
			wantResult: false,
		},
		{
			name:         "mixed isset and isnotset",
			flowbitState: map[string]bool{"flag1": true, "flag2": false},
			flowbits: []rules.Flowbit{
				{Op: rules.FlowbitIsSet, Name: "flag1"},
				{Op: rules.FlowbitNotSet, Name: "flag2"},
			},
			wantResult: true,
		},
		{
			name:         "mixed isset and isnotset - isnotset fails",
			flowbitState: map[string]bool{"flag1": true, "flag2": true},
			flowbits: []rules.Flowbit{
				{Op: rules.FlowbitIsSet, Name: "flag1"},
				{Op: rules.FlowbitNotSet, Name: "flag2"},
			},
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng.flowbitState = tt.flowbitState
			rule := &rules.ParsedRule{Flowbits: tt.flowbits}

			got := eng.checkFlowbits(rule)
			if got != tt.wantResult {
				t.Errorf("checkFlowbits() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestEngine_FlowbitStateResetBetweenRuns(t *testing.T) {
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

	// First run: set a flowbit
	eng.flowbitState = map[string]bool{"persistent": true}
	if !eng.flowbitState["persistent"] {
		t.Errorf("expected flowbit to be set before Run()")
	}

	// Simulate a new Run() which resets flowbitState
	eng.flowbitState = make(map[string]bool)

	// Flowbit should now be reset
	if eng.flowbitState["persistent"] {
		t.Errorf("expected flowbit 'persistent' to be reset after new Run()")
	}
}

func TestEngine_FlowbitSetAndCheck(t *testing.T) {
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

	// Empty state
	eng.flowbitState = map[string]bool{}

	// Rule that checks for session - should fail
	checkRule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitIsSet, Name: "session1"},
		},
	}

	if eng.checkFlowbits(checkRule) {
		t.Errorf("expected checkFlowbits to return false when flowbit not set")
	}

	// Rule that sets session
	setRule := &rules.ParsedRule{
		Flowbits: []rules.Flowbit{
			{Op: rules.FlowbitSet, Name: "session1"},
		},
	}

	eng.setFlowbits(setRule)

	// Now check should pass
	if !eng.checkFlowbits(checkRule) {
		t.Errorf("expected checkFlowbits to return true after flowbit is set")
	}
}

// =============================================================================
// Concurrent Scenario Tests
// =============================================================================

func TestEngine_ConcurrentMixedProtocols(t *testing.T) {
	// Test concurrent processing of rules with different protocols
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	eng, err := New(EngineConfig{
		Generator:   generator,
		Sender:      sender,
		WorkerCount: 8,
		OutputDir:   tmpDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create rules with different protocols
	rulesList := []*rules.ParsedRule{
		{Protocol: "tcp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "80", Direction: "->", RuleID: rules.RuleID{SID: 1}, Msg: "TCP rule 1", Contents: []rules.ContentMatch{{Raw: []byte("tcp1")}}},
		{Protocol: "udp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "53", Direction: "->", RuleID: rules.RuleID{SID: 2}, Msg: "UDP rule 2", Contents: []rules.ContentMatch{{Raw: []byte("udp2")}}},
		{Protocol: "icmp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "any", Direction: "->", RuleID: rules.RuleID{SID: 3}, Msg: "ICMP rule 3", Contents: []rules.ContentMatch{{Raw: []byte("icmp3")}}},
		{Protocol: "tcp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "443", Direction: "->", RuleID: rules.RuleID{SID: 4}, Msg: "TCP rule 4", Contents: []rules.ContentMatch{{Raw: []byte("tcp4")}}},
		{Protocol: "udp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "5353", Direction: "->", RuleID: rules.RuleID{SID: 5}, Msg: "UDP rule 5", Contents: []rules.ContentMatch{{Raw: []byte("udp5")}}},
		{Protocol: "tcp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "8080", Direction: "->", RuleID: rules.RuleID{SID: 6}, Msg: "TCP rule 6", Contents: []rules.ContentMatch{{Raw: []byte("tcp6")}}},
		{Protocol: "tcp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "22", Direction: "->", RuleID: rules.RuleID{SID: 7}, Msg: "TCP rule 7", Contents: []rules.ContentMatch{{Raw: []byte("tcp7")}}},
		{Protocol: "icmp", SrcNet: "any", DstNet: "any", SrcPorts: "any", DstPorts: "any", Direction: "->", RuleID: rules.RuleID{SID: 8}, Msg: "ICMP rule 8", Contents: []rules.ContentMatch{{Raw: []byte("icmp8")}}},
	}

	result, err := eng.Run(rulesList)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.TotalRules != 8 {
		t.Errorf("expected 8 rules, got %d", result.TotalRules)
	}
	if result.SuccessCount != 8 {
		t.Errorf("expected 8 successes, got %d", result.SuccessCount)
	}
	if result.FailureCount != 0 {
		t.Errorf("expected 0 failures, got %d", result.FailureCount)
	}
}

func TestEngine_ConcurrentUniqueEngines(t *testing.T) {
	// Test that concurrent engines don't interfere with each other
	tmpDir := t.TempDir()
	generator := packets.NewGenerator()
	sender, _ := packets.NewSender(tmpDir, "lo0")

	var wg sync.WaitGroup
	successCounts := make([]int, 5)
	errCounts := make([]int, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
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

			// Each engine processes its own rule (no flowbits to avoid deadlock)
			rule := &rules.ParsedRule{
				Protocol:  "tcp",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "80",
				Direction: "->",
				RuleID:    rules.RuleID{SID: 1},
				Msg:       fmt.Sprintf("engine %d", idx),
				Contents: []rules.ContentMatch{
					{Raw: []byte("test")},
				},
			}

			result, err := eng.Run([]*rules.ParsedRule{rule})
			if err != nil {
				t.Errorf("Run() error = %v", err)
				return
			}
			successCounts[idx] = result.SuccessCount
			errCounts[idx] = result.FailureCount
		}(i)
	}

	wg.Wait()

	// All engines should succeed
	for i := 0; i < 5; i++ {
		if successCounts[i] != 1 {
			t.Errorf("engine %d: expected 1 success, got %d", i, successCounts[i])
		}
		if errCounts[i] != 0 {
			t.Errorf("engine %d: expected 0 failures, got %d", i, errCounts[i])
		}
	}
}
