package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTestRunResult_AddResult(t *testing.T) {
	result := NewTestRunResult()

	result.AddResult(&TestResult{
		RuleSID:  1,
		RuleMsg:  "test 1",
		Status:   "success",
		PCAPPath: "/tmp/test1.pcap",
	})

	if result.TotalRules != 1 {
		t.Errorf("expected TotalRules 1, got %d", result.TotalRules)
	}
	if result.SuccessCount != 1 {
		t.Errorf("expected SuccessCount 1, got %d", result.SuccessCount)
	}
	if result.FailureCount != 0 {
		t.Errorf("expected FailureCount 0, got %d", result.FailureCount)
	}
	if len(result.PCAPFiles) != 1 {
		t.Errorf("expected 1 PCAP file, got %d", len(result.PCAPFiles))
	}

	result.AddResult(&TestResult{
		RuleSID: 2,
		RuleMsg: "test 2",
		Status:  "failed",
		Error:   "test error",
	})

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

func TestTestRunResult_SuccessRate(t *testing.T) {
	result := NewTestRunResult()

	result.AddResult(&TestResult{RuleSID: 1, Status: "success"})
	result.AddResult(&TestResult{RuleSID: 2, Status: "success"})
	result.AddResult(&TestResult{RuleSID: 3, Status: "failed"})

	total := result.TotalRules
	successes := result.SuccessCount

	expectedRate := float64(successes) / float64(total) * 100
	if expectedRate < 66.6 || expectedRate > 66.7 {
		t.Errorf("expected rate ~66.67%%, got %f%%", expectedRate)
	}
}

func TestJSONGenerator_Generate(t *testing.T) {
	tmpDir := t.TempDir()
	gen := NewJSONGenerator(tmpDir)

	result := &TestRunResult{
		TestRunID:    "test_run_123",
		StartedAt:    time.Now().Add(-time.Second),
		CompletedAt:  time.Now(),
		TotalRules:   2,
		SuccessCount: 1,
		FailureCount: 1,
		Results: []*TestResult{
			{RuleSID: 1, RuleMsg: "test 1", Status: "success", Protocol: "tcp", PacketsGen: 1, PacketsSent: 1},
			{RuleSID: 2, RuleMsg: "test 2", Status: "failed", Error: "test error", Protocol: "udp"},
		},
		PCAPFiles: []string{"/tmp/test1.pcap", "/tmp/test2.pcap"},
	}

	path, err := gen.Generate(result)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if path == "" {
		t.Error("expected non-empty path")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("file %s does not exist", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read generated file: %v", err)
	}

	var parsed TestRunResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if parsed.TotalRules != 2 {
		t.Errorf("expected TotalRules 2, got %d", parsed.TotalRules)
	}
}

func TestHTMLGenerator_Generate(t *testing.T) {
	tmpDir := t.TempDir()
	gen := NewHTMLGenerator(tmpDir)

	result := &TestRunResult{
		TestRunID:    "test_run_456",
		StartedAt:    time.Now().Add(-time.Second),
		CompletedAt:  time.Now(),
		TotalRules:   2,
		SuccessCount: 1,
		FailureCount: 1,
		Results: []*TestResult{
			{RuleSID: 1, RuleMsg: "test 1", Status: "success", Protocol: "tcp", PacketsSent: 1, PCAPPath: "/tmp/test1.pcap"},
			{RuleSID: 2, RuleMsg: "test 2", Status: "failed", Error: "test error", Protocol: "udp"},
		},
		PCAPFiles: []string{"/tmp/test1.pcap"},
	}

	path, err := gen.Generate(result)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if path == "" {
		t.Error("expected non-empty path")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("file %s does not exist", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read generated file: %v", err)
	}

	content := string(data)

	if !contains(content, "Snort Rule Test Report") {
		t.Error("expected HTML to contain title")
	}
	if !contains(content, "test 1") {
		t.Error("expected HTML to contain test 1")
	}
	if !contains(content, "test 2") {
		t.Error("expected HTML to contain test 2")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestJSONGenerator_PrettyPrint(t *testing.T) {
	tmpDir := t.TempDir()
	gen := NewJSONGenerator(tmpDir)

	if !gen.PrettyPrint {
		t.Error("expected PrettyPrint to be true by default")
	}

	gen.PrettyPrint = false

	result := NewTestRunResult()
	result.AddResult(&TestResult{RuleSID: 1, Status: "success"})

	path, err := gen.Generate(result)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	ext := filepath.Ext(path)
	if ext != ".json" {
		t.Errorf("expected extension .json, got %s", ext)
	}
}

func TestNewTestRunResult(t *testing.T) {
	result := NewTestRunResult()

	if result.Results == nil {
		t.Error("expected Results to be initialized")
	}
	if result.PCAPFiles == nil {
		t.Error("expected PCAPFiles to be initialized")
	}
	if result.TotalRules != 0 {
		t.Errorf("expected TotalRules 0, got %d", result.TotalRules)
	}
	if result.StartedAt.IsZero() {
		t.Error("expected StartedAt to be set")
	}
}
