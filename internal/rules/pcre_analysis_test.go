package rules

import (
	"testing"
)

func TestAnalyzePCRE_EmptyPattern(t *testing.T) {
	issues := AnalyzePCRE("", "")
	if len(issues) == 0 {
		t.Error("expected issues for empty pattern")
	}
	if issues[0].Severity != "error" {
		t.Errorf("expected error severity, got %s", issues[0].Severity)
	}
}

func TestAnalyzePCRE_NestedQuantifiers(t *testing.T) {
	// These should trigger warnings
	patterns := []string{
		"(a+)+",
		"(a*)*",
		"(a+)*",
		"((a+)+)",
	}

	for _, p := range patterns {
		issues := AnalyzePCRE(p, "")
		found := false
		for _, issue := range issues {
			if issue.Severity == "warning" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected warning for nested quantifier pattern: %s", p)
		}
	}
}

func TestAnalyzePCRE_ValidPattern(t *testing.T) {
	patterns := []string{
		"GET",
		"/\\x47\\x45\\x54/",
		"test.*",
	}

	for _, p := range patterns {
		issues := AnalyzePCRE(p, "")
		for _, issue := range issues {
			if issue.Severity == "error" {
				t.Errorf("unexpected error for pattern %s: %s", p, issue.Message)
			}
		}
	}
}

func TestAnalyzePCRE_InvalidPattern(t *testing.T) {
	patterns := []string{
		"[",           // unclosed bracket
		"(",           // unclosed paren
		"**",          // nothing to repeat
		"+++",         // nothing to repeat
	}

	for _, p := range patterns {
		issues := AnalyzePCRE(p, "")
		found := false
		for _, issue := range issues {
			if issue.Severity == "error" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected error for invalid pattern: %s", p)
		}
	}
}

func TestHasNestedQuantifiers(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"(a+)+", true},
		{"(a+)*", true},
		{"(a*)*", true},
		{"((a+)+)", true},
		{"simple", false},
		{"(test)", false},
		{"(a|b)+", false},
		{"a+", false},
	}

	for _, tt := range tests {
		got := hasNestedQuantifiers(tt.pattern)
		if got != tt.want {
			t.Errorf("hasNestedQuantifiers(%q) = %v, want %v", tt.pattern, got, tt.want)
		}
	}
}

func TestHasUnanchoredQuantifiers(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"test+", true},
		{"test*", true},
		{"test?", true},
		{"^test$", false},
		{"test", false},
		{"^abc", false},
	}

	for _, tt := range tests {
		got := hasUnanchoredQuantifiers(tt.pattern)
		if got != tt.want {
			t.Errorf("hasUnanchoredQuantifiers(%q) = %v, want %v", tt.pattern, got, tt.want)
		}
	}
}

func TestHasLargeCharClass(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"[a-zA-Z0-9]", true},
		{"[a-z]", false},
		{"[a-zA-Z]", false},
		{"[a-z0-9]", false},
		{"test", false},
	}

	for _, tt := range tests {
		got := hasLargeCharClass(tt.pattern)
		if got != tt.want {
			t.Errorf("hasLargeCharClass(%q) = %v, want %v", tt.pattern, got, tt.want)
		}
	}
}
