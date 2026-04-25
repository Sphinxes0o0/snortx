package rules

import (
	"strings"
	"testing"
)

func TestParser_ParseRule(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name    string
		rule    string
		wantErr bool
		check   func(*testing.T, *ParsedRule)
	}{
		{
			name:    "basic TCP rule",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:"test"; sid:1; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if r.Protocol != "tcp" {
					tt.Errorf("expected protocol tcp, got %s", r.Protocol)
				}
				if r.RuleID.SID != 1 {
					tt.Errorf("expected SID 1, got %d", r.RuleID.SID)
				}
				if r.Msg != "TEST" {
					tt.Errorf("expected msg TEST, got %s", r.Msg)
				}
				if len(r.Contents) != 1 {
					tt.Errorf("expected 1 content match, got %d", len(r.Contents))
				}
			},
		},
		{
			name:    "TCP with hex content",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:"|48 65 6c 6c 6f|"; sid:2; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if len(r.Contents) != 1 {
					tt.Fatalf("expected 1 content, got %d", len(r.Contents))
				}
				if string(r.Contents[0].Raw) != "Hello" {
					tt.Errorf("expected 'Hello', got %x", r.Contents[0].Raw)
				}
				if !r.Contents[0].IsHex {
					tt.Error("expected IsHex to be true")
				}
			},
		},
		{
			name:    "content with negation",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:!"test"; sid:3; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if len(r.Contents) != 1 {
					tt.Fatalf("expected 1 content, got %d", len(r.Contents))
				}
				if !r.Contents[0].IsNegated {
					tt.Error("expected IsNegated to be true")
				}
			},
		},
		{
			name:    "content with nocase",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:"test"; nocase; sid:4; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if len(r.Contents) != 1 {
					tt.Fatalf("expected 1 content, got %d", len(r.Contents))
				}
				if !r.Contents[0].Nocase {
					tt.Error("expected Nocase to be true")
				}
			},
		},
		{
			name:    "TCP with flow established",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:"test"; flow:established; sid:5; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if r.Flow != "established" {
					tt.Errorf("expected flow 'established', got %s", r.Flow)
				}
			},
		},
		{
			name:    "TCP with offset and depth",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:"test"; offset:5; depth:10; sid:6; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if len(r.Contents) != 1 {
					tt.Fatalf("expected 1 content, got %d", len(r.Contents))
				}
				if r.Contents[0].Offset == nil || *r.Contents[0].Offset != 5 {
					tt.Error("expected offset 5")
				}
				if r.Contents[0].Depth == nil || *r.Contents[0].Depth != 10 {
					tt.Error("expected depth 10")
				}
			},
		},
		{
			name:    "UDP rule",
			rule:    `alert udp any any -> any any (msg:"UDP"; content:"test"; sid:7; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if r.Protocol != "udp" {
					tt.Errorf("expected protocol udp, got %s", r.Protocol)
				}
			},
		},
		{
			name:    "ICMP rule",
			rule:    `alert icmp any any -> any any (msg:"ICMP"; content:"ping"; sid:8; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if r.Protocol != "icmp" {
					tt.Errorf("expected protocol icmp, got %s", r.Protocol)
				}
			},
		},
		{
			name:    "IP rule",
			rule:    `alert ip any any -> any any (msg:"IP"; sid:9; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if r.Protocol != "ip" {
					tt.Errorf("expected protocol ip, got %s", r.Protocol)
				}
			},
		},
		{
			name:    "rule with gid and sid",
			rule:    `alert tcp any any -> any any (msg:"TEST"; content:"test"; gid:3; sid:100; rev:1;)`,
			wantErr: false,
			check: func(tt *testing.T, r *ParsedRule) {
				if r.RuleID.GID != 3 {
					tt.Errorf("expected GID 3, got %d", r.RuleID.GID)
				}
				if r.RuleID.SID != 100 {
					tt.Errorf("expected SID 100, got %d", r.RuleID.SID)
				}
			},
		},
		{
			name:    "empty rule",
			rule:    "",
			wantErr: true,
			check:   nil,
		},
		{
			name:    "comment line",
			rule:    "# this is a comment",
			wantErr: true,
			check:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			r, err := parser.ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				st.Errorf("ParseRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && r != nil {
				tt.check(st, r)
			}
		})
	}
}

func TestParser_ParseRule_MissingDstPort(t *testing.T) {
	parser := NewParser()
	rule := `alert tcp any any -> any (sid:1; rev:1;)`

	if _, err := parser.ParseRule(rule); err == nil {
		t.Fatal("expected parse error for missing dst port")
	}
}

func TestParser_ParseMulti(t *testing.T) {
	parser := NewParser()

	text := `
# Comment
alert tcp any any -> any any (msg:"TEST 1"; content:"test"; sid:1; rev:1;)

alert udp any any -> any any (msg:"TEST 2"; content:"test"; sid:2; rev:1;)
`
	result, err := parser.ParseMulti(text)
	if err != nil {
		t.Fatalf("ParseMulti() error = %v", err)
	}
	if len(result.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result.Rules))
	}
}

func TestDecodeContent(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"Hello", []byte("Hello")},
		{"|48 65 6c 6c 6f|", []byte("Hello")},
		{"|48656c6c6f|", []byte("Hello")},
		{"|48 65|", []byte{0x48, 0x65}},
	}

	for _, tt := range tests {
		result := decodeContent(tt.input)
		if string(result) != string(tt.expected) {
			t.Errorf("decodeContent(%q) = %x, want %x", tt.input, result, tt.expected)
		}
	}
}

func TestContentMatch_IsNegated(t *testing.T) {
	parser := NewParser()

	rule := `alert tcp any any -> any any (msg:"TEST"; content:!"blocked"; sid:1; rev:1;)`

	r, err := parser.ParseRule(rule)
	if err != nil {
		t.Fatalf("ParseRule() error = %v", err)
	}

	if len(r.Contents) != 1 {
		t.Fatalf("expected 1 content, got %d", len(r.Contents))
	}
	if !r.Contents[0].IsNegated {
		t.Error("expected IsNegated to be true for content:!'blocked'")
	}
}

func TestContentMatch_PCRENotMatched(t *testing.T) {
	parser := NewParser()

	rule := `alert tcp any any -> any any (msg:"TEST"; pcre:"/content/i"; sid:1; rev:1;)`

	r, err := parser.ParseRule(rule)
	if err != nil {
		t.Fatalf("ParseRule() error = %v", err)
	}

	found := false
	for _, c := range r.Contents {
		if strings.Contains(string(c.Raw), "content") {
			found = true
			break
		}
	}
	if found {
		t.Error("PCRE /content/i should not be parsed as content match")
	}
}

func TestPCRE_Parsing(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		rule     string
		pattern  string
		modifier string
	}{
		{
			name:     "simple PCRE",
			rule:     `alert tcp any any -> any any (msg:"TEST"; pcre:"/test/"; sid:1; rev:1;)`,
			pattern:  "test",
			modifier: "",
		},
		{
			name:     "PCRE with case-insensitive modifier",
			rule:     `alert tcp any any -> any any (msg:"TEST"; pcre:"/content/i"; sid:2; rev:1;)`,
			pattern:  "content",
			modifier: "i",
		},
		{
			name:     "PCRE with multiline modifier",
			rule:     `alert tcp any any -> any any (msg:"TEST"; pcre:"/^GET/m"; sid:3; rev:1;)`,
			pattern:  "^GET",
			modifier: "m",
		},
		{
			name:     "PCRE with multiple modifiers",
			rule:     `alert tcp any any -> any any (msg:"TEST"; pcre:"/test/ims"; sid:4; rev:1;)`,
			pattern:  "test",
			modifier: "ims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parser.ParseRule(tt.rule)
			if err != nil {
				t.Fatalf("ParseRule() error = %v", err)
			}
			if len(r.PCREMatches) != 1 {
				t.Fatalf("expected 1 PCRE match, got %d", len(r.PCREMatches))
			}
			if r.PCREMatches[0].Pattern != tt.pattern {
				t.Errorf("expected pattern %q, got %q", tt.pattern, r.PCREMatches[0].Pattern)
			}
			if r.PCREMatches[0].Modifiers != tt.modifier {
				t.Errorf("expected modifier %q, got %q", tt.modifier, r.PCREMatches[0].Modifiers)
			}
		})
	}
}
