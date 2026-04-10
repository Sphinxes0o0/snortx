package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/rules"
)

func TestContainsHelper(t *testing.T) {
	// Test the contains helper from main package
	tests := []struct {
		s   string
		c   rune
		want bool
	}{
		{"hello", 'h', true},
		{"hello", 'x', false},
		{"", 'a', false},
		{"test", 'e', true},
	}

	for _, tt := range tests {
		if got := contains(tt.s, tt.c); got != tt.want {
			t.Errorf("contains(%q, %c) = %v, want %v", tt.s, tt.c, got, tt.want)
		}
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		s    string
		sep  string
		want []string
	}{
		{"a,b,c", ",", []string{"a", "b", "c"}},
		{" a , b , c ", ",", []string{"a", "b", "c"}},
		{"", ",", nil},
		{"a", ",", []string{"a"}},
		{" a ", ",", []string{"a"}},
	}

	for _, tt := range tests {
		got := splitAndTrim(tt.s, tt.sep)
		if len(got) != len(tt.want) {
			t.Errorf("splitAndTrim(%q, %q) len = %d, want %d", tt.s, tt.sep, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitAndTrim(%q, %q)[%d] = %q, want %q", tt.s, tt.sep, i, got[i], tt.want[i])
			}
		}
	}
}

func TestLintIssue(t *testing.T) {
	issue := lintIssue{
		isError: true,
		msg:     "test error",
	}

	if !issue.isError {
		t.Error("expected isError to be true")
	}
	if issue.msg != "test error" {
		t.Errorf("expected msg 'test error', got %q", issue.msg)
	}
}

func TestValidateRule(t *testing.T) {
	generator := packets.NewGenerator()

	// Test rule with no content or PCRE
	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		RuleID:    rules.RuleID{SID: 1},
		Msg:       "test",
		SrcNet:    "any",
		DstNet:    "any",
		SrcPorts:  "any",
		DstPorts:  "80",
		Direction: "->",
		Contents:  []rules.ContentMatch{},
	}

	issues := validateRule(rule, generator)
	if len(issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].isError {
		t.Error("expected warning, not error")
	}
}

func TestValidateRule_WithContent(t *testing.T) {
	generator := packets.NewGenerator()

	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		RuleID:    rules.RuleID{SID: 1},
		Msg:       "test",
		SrcNet:    "any",
		DstNet:    "any",
		SrcPorts:  "any",
		DstPorts:  "80",
		Direction: "->",
		Contents:  []rules.ContentMatch{{Raw: []byte("test")}},
	}

	issues := validateRule(rule, generator)
	// Should have no issues for valid rule
	for _, issue := range issues {
		if issue.isError {
			t.Errorf("unexpected error: %s", issue.msg)
		}
	}
}

func TestLintRule_ValidRule(t *testing.T) {
	generator := packets.NewGenerator()

	rule := &rules.ParsedRule{
		Protocol:    "tcp",
		RuleID:      rules.RuleID{SID: 1},
		Msg:         "test",
		Contents:    []rules.ContentMatch{{Raw: []byte("test")}},
		PCREMatches: []rules.PCREMatch{},
	}

	issues := validateRule(rule, generator)
	for _, issue := range issues {
		if issue.isError {
			t.Errorf("unexpected error: %s", issue.msg)
		}
	}
}

func TestLintRule_WithNegatedContent(t *testing.T) {
	generator := packets.NewGenerator()

	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		RuleID:    rules.RuleID{SID: 1},
		Msg:       "test",
		Contents:  []rules.ContentMatch{{IsNegated: true, Raw: []byte("blocked")}},
	}

	issues := validateRule(rule, generator)
	found := false
	for _, issue := range issues {
		if !issue.isError && issue.msg != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected warning for negated content")
	}
}

func TestLintRule_UnsupportedProtocol(t *testing.T) {
	generator := packets.NewGenerator()

	rule := &rules.ParsedRule{
		Protocol: "unsupported_proto",
		RuleID:   rules.RuleID{SID: 1},
		Msg:      "test",
	}

	issues := validateRule(rule, generator)
	found := false
	for _, issue := range issues {
		if issue.isError && issue.msg != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected error for unsupported protocol")
	}
}

func TestWriteReadRuleFile(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test.rules")

	content := `alert tcp any any -> any any (msg:"TEST"; content:"test"; sid:1; rev:1;)
alert udp any any -> any any (msg:"UDP"; content:"test"; sid:2; rev:1;)
`
	if err := os.WriteFile(ruleFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}

	parser := rules.NewParser()
	result, err := parser.ParseFile(ruleFile)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if len(result.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result.Rules))
	}
}

func TestBatchFilesProcessing(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two rule files
	file1 := filepath.Join(tmpDir, "rules1.rules")
	file2 := filepath.Join(tmpDir, "rules2.rules")

	content1 := `alert tcp any any -> any any (msg:"TEST1"; content:"test"; sid:1; rev:1;)`
	content2 := `alert udp any any -> any any (msg:"TEST2"; content:"test"; sid:2; rev:1;)`

	if err := os.WriteFile(file1, []byte(content1), 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte(content2), 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	parser := rules.NewParser()

	rules1, err := parser.ParseFile(file1)
	if err != nil {
		t.Fatalf("ParseFile(file1) error = %v", err)
	}
	if len(rules1.Rules) != 1 {
		t.Errorf("expected 1 rule in file1, got %d", len(rules1.Rules))
	}

	rules2, err := parser.ParseFile(file2)
	if err != nil {
		t.Fatalf("ParseFile(file2) error = %v", err)
	}
	if len(rules2.Rules) != 1 {
		t.Errorf("expected 1 rule in file2, got %d", len(rules2.Rules))
	}
}
