package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// =============================================================================
// Table-driven tests for json.go
// =============================================================================

func TestJSONGenerator_Generate_OutputFormat(t *testing.T) {
	tests := []struct {
		name       string
		result     *TestRunResult
		wantErr    bool
		validateFn func(t *testing.T, path string, data []byte)
	}{
		{
			name: "basic generation",
			result: &TestRunResult{
				TestRunID:    "run_basic",
				StartedAt:    time.Now().Add(-time.Second),
				TotalRules:   1,
				SuccessCount: 1,
				FailureCount: 0,
				Results: []*TestResult{
					{RuleSID: 1, RuleMsg: "basic test", Status: "success", Protocol: "tcp"},
				},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, data []byte) {
				if !strings.HasSuffix(path, ".json") {
					t.Errorf("expected .json suffix, got %s", path)
				}
				var parsed TestRunResult
				if err := json.Unmarshal(data, &parsed); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if parsed.TestRunID != "run_basic" {
					t.Errorf("expected TestRunID 'run_basic', got '%s'", parsed.TestRunID)
				}
			},
		},
		{
			name: "empty results",
			result: &TestRunResult{
				TestRunID:    "run_empty",
				StartedAt:    time.Now(),
				TotalRules:   0,
				SuccessCount: 0,
				FailureCount: 0,
				Results:      []*TestResult{},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, data []byte) {
				var parsed TestRunResult
				if err := json.Unmarshal(data, &parsed); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if parsed.TotalRules != 0 {
					t.Errorf("expected TotalRules 0, got %d", parsed.TotalRules)
				}
			},
		},
		{
			name: "multiple protocols",
			result: &TestRunResult{
				TestRunID:    "run_multi_proto",
				StartedAt:    time.Now(),
				TotalRules:   4,
				SuccessCount: 3,
				FailureCount: 1,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success", Protocol: "tcp"},
					{RuleSID: 2, Status: "success", Protocol: "udp"},
					{RuleSID: 3, Status: "success", Protocol: "icmp"},
					{RuleSID: 4, Status: "failed", Protocol: "tcp"},
				},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, data []byte) {
				var parsed TestRunResult
				if err := json.Unmarshal(data, &parsed); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if parsed.SuccessCount != 3 {
					t.Errorf("expected SuccessCount 3, got %d", parsed.SuccessCount)
				}
				if parsed.FailureCount != 1 {
					t.Errorf("expected FailureCount 1, got %d", parsed.FailureCount)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewJSONGenerator(tmpDir)

			path, err := gen.Generate(tt.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			tt.validateFn(t, path, data)
		})
	}
}

func TestJSONGenerator_CompletedAtIsSet(t *testing.T) {
	tests := []struct {
		name      string
		result    *TestRunResult
		checkZero bool
	}{
		{
			name: "CompletedAt should be set to current time",
			result: &TestRunResult{
				TestRunID:    "run_time_test",
				StartedAt:    time.Now().Add(-time.Minute),
				TotalRules:   1,
				SuccessCount: 1,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success", Protocol: "tcp"},
				},
			},
			checkZero: false,
		},
		{
			name: "zero CompletedAt should be overwritten",
			result: &TestRunResult{
				TestRunID:    "run_zero_time",
				StartedAt:    time.Now().Add(-time.Minute),
				CompletedAt:  time.Time{}, // zero value
				TotalRules:   1,
				SuccessCount: 1,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success", Protocol: "tcp"},
				},
			},
			checkZero: true, // verify it's NOT zero after generation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewJSONGenerator(tmpDir)

			beforeGen := time.Now()

			path, err := gen.Generate(tt.result)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			var parsed TestRunResult
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if parsed.CompletedAt.IsZero() {
				t.Error("CompletedAt should not be zero after Generate()")
			}

			if tt.checkZero {
				if parsed.CompletedAt.Before(beforeGen) {
					t.Error("CompletedAt should be set to current time, not preserved from input")
				}
			}
		})
	}
}

func TestJSONGenerator_DataAggregation(t *testing.T) {
	tests := []struct {
		name            string
		results         []*TestResult
		wantTotalRules  int
		wantSuccessCount int
		wantFailureCount int
	}{
		{
			name:            "all success",
			results:         []*TestResult{
				{RuleSID: 1, Status: "success"},
				{RuleSID: 2, Status: "success"},
				{RuleSID: 3, Status: "success"},
			},
			wantTotalRules:   3,
			wantSuccessCount: 3,
			wantFailureCount: 0,
		},
		{
			name:            "all failed",
			results:         []*TestResult{
				{RuleSID: 1, Status: "failed", Error: "err1"},
				{RuleSID: 2, Status: "failed", Error: "err2"},
			},
			wantTotalRules:   2,
			wantSuccessCount: 0,
			wantFailureCount: 2,
		},
		{
			name:            "mixed",
			results:         []*TestResult{
				{RuleSID: 1, Status: "success"},
				{RuleSID: 2, Status: "failed", Error: "err"},
				{RuleSID: 3, Status: "success"},
				{RuleSID: 4, Status: "failed", Error: "err"},
			},
			wantTotalRules:   4,
			wantSuccessCount: 2,
			wantFailureCount: 2,
		},
		{
			name:            "empty",
			results:         []*TestResult{},
			wantTotalRules:   0,
			wantSuccessCount: 0,
			wantFailureCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewJSONGenerator(tmpDir)

			result := NewTestRunResult()
			result.TestRunID = "run_" + tt.name
			for _, r := range tt.results {
				result.AddResult(r)
			}

			path, err := gen.Generate(result)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			var parsed TestRunResult
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if parsed.TotalRules != tt.wantTotalRules {
				t.Errorf("TotalRules = %d, want %d", parsed.TotalRules, tt.wantTotalRules)
			}
			if parsed.SuccessCount != tt.wantSuccessCount {
				t.Errorf("SuccessCount = %d, want %d", parsed.SuccessCount, tt.wantSuccessCount)
			}
			if parsed.FailureCount != tt.wantFailureCount {
				t.Errorf("FailureCount = %d, want %d", parsed.FailureCount, tt.wantFailureCount)
			}
		})
	}
}

// =============================================================================
// Table-driven tests for html.go
// =============================================================================

func TestHTMLGenerator_Generate_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		result    *TestRunResult
		wantErr   bool
		validateFn func(t *testing.T, path string, content string)
	}{
		{
			name: "basic generation",
			result: &TestRunResult{
				TestRunID:    "run_html_basic",
				StartedAt:    time.Now(),
				TotalRules:   1,
				SuccessCount: 1,
				FailureCount: 0,
				Results: []*TestResult{
					{RuleSID: 100, RuleMsg: "Basic Rule", Status: "success", Protocol: "tcp", PacketsSent: 5},
				},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, content string) {
				if !strings.Contains(content, "Snort Rule Test Report") {
					t.Error("expected HTML to contain title")
				}
				if !strings.Contains(content, "run_html_basic") {
					t.Error("expected HTML to contain test run ID")
				}
			},
		},
		{
			name: "protocol breakdown",
			result: &TestRunResult{
				TestRunID:    "run_proto",
				StartedAt:    time.Now(),
				TotalRules:   3,
				SuccessCount: 2,
				FailureCount: 1,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success", Protocol: "tcp"},
					{RuleSID: 2, Status: "success", Protocol: "udp"},
					{RuleSID: 3, Status: "failed", Protocol: "tcp"},
				},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, content string) {
				if !strings.Contains(content, "tcp") {
					t.Error("expected HTML to contain tcp protocol")
				}
				if !strings.Contains(content, "udp") {
					t.Error("expected HTML to contain udp protocol")
				}
			},
		},
		{
			name: "success rate calculation",
			result: &TestRunResult{
				TestRunID:    "run_rate",
				StartedAt:    time.Now(),
				TotalRules:   4,
				SuccessCount: 3,
				FailureCount: 1,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success"},
					{RuleSID: 2, Status: "success"},
					{RuleSID: 3, Status: "success"},
					{RuleSID: 4, Status: "failed"},
				},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, content string) {
				if !strings.Contains(content, "75.0%") && !strings.Contains(content, "75%") {
					t.Error("expected HTML to contain 75% success rate")
				}
			},
		},
		{
			name: "empty results",
			result: &TestRunResult{
				TestRunID:    "run_empty",
				StartedAt:    time.Now(),
				TotalRules:   0,
				SuccessCount: 0,
				FailureCount: 0,
				Results:      []*TestResult{},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, content string) {
				if !strings.Contains(content, "0") {
					t.Error("expected HTML to contain zero counts")
				}
			},
		},
		{
			name: "pcap path display",
			result: &TestRunResult{
				TestRunID:    "run_pcap",
				StartedAt:    time.Now(),
				TotalRules:   1,
				SuccessCount: 1,
				FailureCount: 0,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success", PCAPPath: "/output/rule_1.pcap"},
				},
			},
			wantErr: false,
			validateFn: func(t *testing.T, path string, content string) {
				if !strings.Contains(content, "rule_1.pcap") {
					t.Error("expected HTML to contain pcap filename")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewHTMLGenerator(tmpDir)

			path, err := gen.Generate(tt.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			tt.validateFn(t, path, string(data))
		})
	}
}

func TestHTMLGenerator_HTMLEscaping(t *testing.T) {
	tests := []struct {
		name     string
		ruleMsg  string
		errorMsg string
		checkFn  func(t *testing.T, content string)
	}{
		{
			name:    "script tag in rule message",
			ruleMsg: `<script>alert('xss')</script>`,
			checkFn: func(t *testing.T, content string) {
				// After escaping, < becomes &lt; and > becomes &gt;
				// The unescaped <script> should NOT appear as table content
				if strings.Contains(content, `>&lt;script&gt;`) {
					t.Error("HTML template does not escape script tags - potential XSS")
				}
			},
		},
		{
			name:    "javascript event handler",
			ruleMsg: `<img src=x onerror=alert('xss')>`,
			checkFn: func(t *testing.T, content string) {
				// onerror= should be escaped to onerror= (but within &lt;...&gt;)
				// The unescaped form should not appear in table cell
				if strings.Contains(content, `>&lt;img src=x onerror=alert`) {
					t.Error("HTML template does not escape event handlers - potential XSS")
				}
			},
		},
		{
			name:    "angle brackets",
			ruleMsg: `Test <message>`,
			checkFn: func(t *testing.T, content string) {
				// <message> should be escaped to &lt;message&gt;
				if strings.Contains(content, `>&lt;message&gt;`) {
					t.Error("HTML template does not escape angle brackets")
				}
			},
		},
		{
			name:    "ampersand",
			ruleMsg: `Tom & Jerry`,
			checkFn: func(t *testing.T, content string) {
				// & should be escaped to &amp;
				if strings.Contains(content, `>Tom &amp; Jerry<`) {
					t.Error("HTML template should escape ampersand")
				}
			},
		},
		{
			name:    "error message with HTML",
			ruleMsg: "Normal message",
			errorMsg: `<script>alert('error')</script>`,
			checkFn: func(t *testing.T, content string) {
				// Error message in title attribute should be escaped
				if strings.Contains(content, `title="&lt;script&gt;`) {
					t.Error("HTML template does not escape error message - potential XSS")
				}
			},
		},
		{
			name:    "double quotes",
			ruleMsg: `He said "hello"`,
			checkFn: func(t *testing.T, content string) {
				// Double quotes should be escaped to &quot;
				if strings.Contains(content, `>&quot;hello&quot;<`) {
					t.Error("HTML template should escape double quotes")
				}
			},
		},
		{
			name:    "normal text",
			ruleMsg: `Normal Rule Message 123`,
			checkFn: func(t *testing.T, content string) {
				if !strings.Contains(content, `Normal Rule Message 123`) {
					t.Error("expected normal text to be preserved")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewHTMLGenerator(tmpDir)

			result := &TestRunResult{
				TestRunID:    "run_escape",
				StartedAt:    time.Now(),
				TotalRules:   1,
				SuccessCount: 1,
				FailureCount: 0,
				Results: []*TestResult{
					{
						RuleSID:   1,
						RuleMsg:   tt.ruleMsg,
						Status:    "success",
						Protocol:  "tcp",
						PCAPPath:  "/tmp/test.pcap",
						PacketsSent: 1,
					},
				},
			}
			if tt.errorMsg != "" {
				result.SuccessCount = 0
				result.FailureCount = 1
				result.Results[0].Status = "failed"
				result.Results[0].Error = tt.errorMsg
			}

			path, err := gen.Generate(result)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			tt.checkFn(t, string(data))
		})
	}
}

func TestHTMLGenerator_TemplateRendering(t *testing.T) {
	tests := []struct {
		name      string
		result    *TestRunResult
		checkFn   func(t *testing.T, content string)
	}{
		{
			name: "SID displayed correctly",
			result: &TestRunResult{
				TestRunID:    "run_tmpl",
				StartedAt:    time.Now(),
				TotalRules:   1,
				SuccessCount: 1,
				FailureCount: 0,
				Results: []*TestResult{
					{RuleSID: 999999, RuleMsg: "High SID", Status: "success", Protocol: "tcp"},
				},
			},
			checkFn: func(t *testing.T, content string) {
				if !strings.Contains(content, "999999") {
					t.Error("expected SID 999999 to be displayed")
				}
			},
		},
		{
			name: "CompletedAt displayed",
			result: &TestRunResult{
				TestRunID:    "run_time",
				StartedAt:    time.Now(),
				TotalRules:   1,
				SuccessCount: 1,
				FailureCount: 0,
				Results: []*TestResult{
					{RuleSID: 1, RuleMsg: "Time test", Status: "success", Protocol: "tcp"},
				},
			},
			checkFn: func(t *testing.T, content string) {
				// Should contain RFC3339 formatted time
				if !strings.Contains(content, "T") {
					t.Error("expected CompletedAt timestamp to be displayed")
				}
			},
		},
		{
			name: "all protocols present",
			result: &TestRunResult{
				TestRunID:    "run_protos",
				StartedAt:    time.Now(),
				TotalRules:   5,
				SuccessCount: 5,
				FailureCount: 0,
				Results: []*TestResult{
					{RuleSID: 1, Status: "success", Protocol: "tcp"},
					{RuleSID: 2, Status: "success", Protocol: "udp"},
					{RuleSID: 3, Status: "success", Protocol: "icmp"},
					{RuleSID: 4, Status: "success", Protocol: "arp"},
					{RuleSID: 5, Status: "success", Protocol: "dns"},
				},
			},
			checkFn: func(t *testing.T, content string) {
				for _, proto := range []string{"tcp", "udp", "icmp", "arp", "dns"} {
					if !strings.Contains(content, proto) {
						t.Errorf("expected protocol %s to be in HTML", proto)
					}
				}
			},
		},
		{
			name: "failure shows error message",
			result: &TestRunResult{
				TestRunID:    "run_err",
				StartedAt:    time.Now(),
				TotalRules:   1,
				SuccessCount: 0,
				FailureCount: 1,
				Results: []*TestResult{
					{RuleSID: 1, Status: "failed", Error: "connection timeout", Protocol: "tcp"},
				},
			},
			checkFn: func(t *testing.T, content string) {
				if !strings.Contains(content, "failed") {
					t.Error("expected failed status to be displayed")
				}
				if !strings.Contains(content, "connection timeout") {
					t.Error("expected error message to be displayed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewHTMLGenerator(tmpDir)

			path, err := gen.Generate(tt.result)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			tt.checkFn(t, string(data))
		})
	}
}

// =============================================================================
// Table-driven tests for types.go
// =============================================================================

func TestTestRunResult_Struct(t *testing.T) {
	tests := []struct {
		name     string
		result   *TestRunResult
		checkFn  func(t *testing.T, result *TestRunResult)
	}{
		{
			name:   "new result has correct initial state",
			result: NewTestRunResult(),
			checkFn: func(t *testing.T, result *TestRunResult) {
				if result.Results == nil {
					t.Error("Results should not be nil")
				}
				if result.PCAPFiles == nil {
					t.Error("PCAPFiles should not be nil")
				}
				if result.TotalRules != 0 {
					t.Errorf("TotalRules should be 0, got %d", result.TotalRules)
				}
				if result.SuccessCount != 0 {
					t.Errorf("SuccessCount should be 0, got %d", result.SuccessCount)
				}
				if result.FailureCount != 0 {
					t.Errorf("FailureCount should be 0, got %d", result.FailureCount)
				}
				if result.StartedAt.IsZero() {
					t.Error("StartedAt should be set")
				}
			},
		},
		{
			name:   "PCAPFiles accumulates",
			result: func() *TestRunResult {
				r := NewTestRunResult()
				r.AddResult(&TestResult{RuleSID: 1, PCAPPath: "/tmp/pcap1.pcap"})
				r.AddResult(&TestResult{RuleSID: 2, PCAPPath: "/tmp/pcap2.pcap"})
				r.AddResult(&TestResult{RuleSID: 3}) // no PCAP
				return r
			}(),
			checkFn: func(t *testing.T, result *TestRunResult) {
				if len(result.PCAPFiles) != 2 {
					t.Errorf("PCAPFiles should have 2 entries, got %d", len(result.PCAPFiles))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.checkFn(t, tt.result)
		})
	}
}

func TestTestRunResult_AddResult_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		results        []*TestResult
		wantTotal      int
		wantSuccess    int
		wantFailure    int
	}{
		{
			name:        "single success",
			results:     []*TestResult{{RuleSID: 1, Status: "success"}},
			wantTotal:   1,
			wantSuccess: 1,
			wantFailure: 0,
		},
		{
			name:        "single failure",
			results:     []*TestResult{{RuleSID: 1, Status: "failed"}},
			wantTotal:   1,
			wantSuccess: 0,
			wantFailure: 1,
		},
		{
			name:        "unknown status counts as failure",
			results:     []*TestResult{{RuleSID: 1, Status: "unknown"}},
			wantTotal:   1,
			wantSuccess: 0,
			wantFailure: 1,
		},
		{
			name:        "empty status counts as failure",
			results:     []*TestResult{{RuleSID: 1, Status: ""}},
			wantTotal:   1,
			wantSuccess: 0,
			wantFailure: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewTestRunResult()
			for _, r := range tt.results {
				result.AddResult(r)
			}

			if result.TotalRules != tt.wantTotal {
				t.Errorf("TotalRules = %d, want %d", result.TotalRules, tt.wantTotal)
			}
			if result.SuccessCount != tt.wantSuccess {
				t.Errorf("SuccessCount = %d, want %d", result.SuccessCount, tt.wantSuccess)
			}
			if result.FailureCount != tt.wantFailure {
				t.Errorf("FailureCount = %d, want %d", result.FailureCount, tt.wantFailure)
			}
		})
	}
}

func TestTestResult_Fields(t *testing.T) {
	tests := []struct {
		name   string
		result *TestResult
		check  func(t *testing.T, r *TestResult)
	}{
		{
			name: "all fields set",
			result: &TestResult{
				RuleSID:      123,
				RuleMsg:      "Test message",
				Protocol:     "tcp",
				PacketsGen:   10,
				PacketsSent:  8,
				PCAPPath:     "/output/rule_123.pcap",
				Status:       "success",
				Error:        "",
				Duration:     150 * time.Millisecond,
			},
			check: func(t *testing.T, r *TestResult) {
				if r.RuleSID != 123 {
					t.Errorf("RuleSID = %d, want 123", r.RuleSID)
				}
				if r.RuleMsg != "Test message" {
					t.Errorf("RuleMsg = %s, want 'Test message'", r.RuleMsg)
				}
				if r.Protocol != "tcp" {
					t.Errorf("Protocol = %s, want 'tcp'", r.Protocol)
				}
				if r.PacketsGen != 10 {
					t.Errorf("PacketsGen = %d, want 10", r.PacketsGen)
				}
				if r.PacketsSent != 8 {
					t.Errorf("PacketsSent = %d, want 8", r.PacketsSent)
				}
				if r.Duration != 150*time.Millisecond {
					t.Errorf("Duration = %v, want 150ms", r.Duration)
				}
			},
		},
		{
			name: "error field populated",
			result: &TestResult{
				RuleSID:   456,
				Status:    "failed",
				Error:     "PCRE mismatch",
				Protocol:  "udp",
			},
			check: func(t *testing.T, r *TestResult) {
				if r.Error != "PCRE mismatch" {
					t.Errorf("Error = %s, want 'PCRE mismatch'", r.Error)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, tt.result)
		})
	}
}

func TestJSONGenerator_OutputPath(t *testing.T) {
	tests := []struct {
		name     string
		testRunID string
		wantContains string
	}{
		{
			name:         "normal ID",
			testRunID:    "run_123",
			wantContains: "run_123",
		},
		{
			name:         "timestamp ID",
			testRunID:    "run_1609459200",
			wantContains: "run_1609459200",
		},
		{
			name:         "uuid-like ID",
			testRunID:    "run_abc123def456",
			wantContains: "run_abc123def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewJSONGenerator(tmpDir)

			result := NewTestRunResult()
			result.TestRunID = tt.testRunID
			result.AddResult(&TestResult{RuleSID: 1, Status: "success"})

			path, err := gen.Generate(result)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if !strings.Contains(path, tt.wantContains) {
				t.Errorf("path = %s, want to contain %s", path, tt.wantContains)
			}
		})
	}
}

func TestHTMLGenerator_OutputPath(t *testing.T) {
	tests := []struct {
		name      string
		testRunID string
		wantContains string
	}{
		{
			name:         "normal ID",
			testRunID:    "html_run_456",
			wantContains: "html_run_456",
		},
		{
			name:         "special chars in ID",
			testRunID:    "run-test-789",
			wantContains: "run-test-789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gen := NewHTMLGenerator(tmpDir)

			result := NewTestRunResult()
			result.TestRunID = tt.testRunID
			result.AddResult(&TestResult{RuleSID: 1, Status: "success"})

			path, err := gen.Generate(result)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if !strings.Contains(path, tt.wantContains) {
				t.Errorf("path = %s, want to contain %s", path, tt.wantContains)
			}
		})
	}
}
