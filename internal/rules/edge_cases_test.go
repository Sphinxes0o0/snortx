package rules

import (
	"testing"
)

func TestParser_EdgeCases(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name    string
		rule    string
		wantErr bool
		desc    string
	}{
		// Empty content - parser rejects this
		{
			name:    "empty content",
			rule:    `alert tcp any any -> any any (content:""; sid:1; rev:1;)`,
			wantErr: true,
			desc:    "Empty quoted content is rejected",
		},
		// Malformed PCRE - parser doesn't validate PCRE syntax
		{
			name:    "malformed pcre - unbalanced parens",
			rule:    `alert tcp any any -> any any (pcre:"/(test/"; sid:1; rev:1;)`,
			wantErr: false, // Parser doesn't validate PCRE syntax
			desc:    "PCRE syntax not validated at parse time",
		},
		// Zero port - allowed by parser
		{
			name:    "zero port",
			rule:    `alert tcp any any -> any 0 (sid:1; rev:1;)`,
			wantErr: false,
			desc:    "Zero port is parsed (generator may reject)",
		},
		// Invalid CIDR - allowed by parser
		{
			name:    "invalid CIDR - too many bits",
			rule:    `alert tcp 10.0.0.0/33 any -> any any (sid:1; rev:1;)`,
			wantErr: false,
			desc:    "Invalid CIDR is parsed (not validated)",
		},
		// VLAN ID - parser accepts any uint16
		{
			name:    "vlan out of range",
			rule:    `alert tcp any any -> any any (vlan:5000; sid:1; rev:1;)`,
			wantErr: false, // VLAN is stored as uint16, not range-checked
			desc:    "VLAN ID not range-checked at parse time",
		},
		// Hex content with odd digits - auto-corrected
		{
			name:    "hex content odd digits",
			rule:    `alert tcp any any -> any any (content:"|48656c|"; sid:1; rev:1;)`,
			wantErr: false,
			desc:    "Hex with odd digits is auto-padded",
		},
		// Very long content
		{
			name:    "long content",
			rule:    `alert tcp any any -> any any (content:"` + longString(1000) + `"; sid:1; rev:1;)`,
			wantErr: false,
			desc:    "Very long content should be parsed",
		},
		// IP protocol
		{
			name:    "ip protocol rule",
			rule:    `alert ip any any -> any any (msg:"IP"; sid:1; rev:1;)`,
			wantErr: false,
			desc:    "IP protocol rules should be valid",
		},
		// Whitespace only rule
		{
			name:    "whitespace only",
			rule:    "   ",
			wantErr: true,
			desc:    "Whitespace-only input should error",
		},
		// Missing closing paren - auto-fixed
		{
			name:    "missing closing paren",
			rule:    `alert tcp any any -> any any (msg:"TEST"`,
			wantErr: false, // Parser auto-fixes missing closing paren
			desc:    "Missing closing paren is auto-fixed",
		},
		// Invalid direction - parser only allows ->, <>, and <-
		{
			name:    "invalid direction",
			rule:    `alert tcp any any <= any any (sid:1; rev:1;)`,
			wantErr: true,
			desc:    "Only ->, <>, and <- directions allowed",
		},
		// Missing SID
		{
			name:    "missing sid",
			rule:    `alert tcp any any -> any any (msg:"TEST"; rev:1;)`,
			wantErr: false,
			desc:    "Missing SID defaults to 0",
		},
		// Negative offset - not validated
		{
			name:    "negative offset",
			rule:    `alert tcp any any -> any any (content:"test"; offset:-1; sid:1; rev:1;)`,
			wantErr: false, // Offset not validated at parse time
			desc:    "Negative offset is parsed",
		},
		// Invalid flow value - validated
		{
			name:    "invalid flow",
			rule:    `alert tcp any any -> any any (flow:invalid; sid:1; rev:1;)`,
			wantErr: true,
			desc:    "Invalid flow value should error",
		},
		// SCTP protocol
		{
			name:    "sctp protocol",
			rule:    `alert sctp any any -> any any (msg:"SCTP"; sid:1; rev:1;)`,
			wantErr: false,
			desc:    "SCTP protocol should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRule() error = %v, wantErr %v (%s)", err, tt.wantErr, tt.desc)
			}
		})
	}
}

// longString generates a string of given length
func longString(n int) string {
	result := make([]byte, n)
	for i := range result {
		result[i] = 'a'
	}
	return string(result)
}

func TestParser_ByteTestParsing(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{
			name:    "byte_test basic",
			rule:    `alert tcp any any -> any any (byte_test:4,=,0x01020304,0; sid:1; rev:1;)`,
			wantErr: false,
		},
		{
			name:    "byte_test with relative",
			rule:    `alert tcp any any -> any any (byte_test:2,>,100,0,relative; sid:1; rev:1;)`,
			wantErr: false,
		},
		{
			name:    "byte_jump basic",
			rule:    `alert tcp any any -> any any (byte_jump:4,0; sid:1; rev:1;)`,
			wantErr: false,
		},
		{
			name:    "byte_jump with align",
			rule:    `alert tcp any any -> any any (byte_jump:2,0,align4; sid:1; rev:1;)`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parser.ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && r != nil {
				if len(r.ByteTests) == 0 && len(r.ByteJumps) == 0 {
					t.Error("expected byte_test/byte_jump to be parsed")
				}
			}
		})
	}
}

func TestParser_DNSDomainExtraction(t *testing.T) {
	parser := NewParser()

	// DNS query with domain in content
	// dns protocol is mapped to tcp (app protocol modifier)
	rule := `alert dns any any -> any any (content:"example.com"; sid:1; rev:1;)`

	r, err := parser.ParseRule(rule)
	if err != nil {
		t.Fatalf("ParseRule() error = %v", err)
	}

	// dns is mapped to tcp as the transport protocol
	if r.Protocol != "tcp" {
		t.Errorf("expected protocol tcp for dns, got %s", r.Protocol)
	}

	if len(r.Contents) != 1 {
		t.Fatalf("expected 1 content, got %d", len(r.Contents))
	}

	expectedDomain := "example.com"
	if string(r.Contents[0].Raw) != expectedDomain {
		t.Errorf("expected domain %q, got %q", expectedDomain, string(r.Contents[0].Raw))
	}
}