package packets

import (
	"testing"

	"github.com/user/snortx/internal/rules"
)

func TestGenerator_Generate(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name      string
		rule      *rules.ParsedRule
		wantProto string
		wantErr   bool
	}{
		{
			name: "TCP rule",
			rule: &rules.ParsedRule{
				Protocol:  "tcp",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "80",
				Direction: "->",
				Contents: []rules.ContentMatch{
					{Raw: []byte("test")},
				},
			},
			wantProto: "tcp",
			wantErr:   false,
		},
		{
			name: "UDP rule",
			rule: &rules.ParsedRule{
				Protocol:  "udp",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "53",
				Direction: "->",
				Contents: []rules.ContentMatch{
					{Raw: []byte("dns")},
				},
			},
			wantProto: "udp",
			wantErr:   false,
		},
		{
			name: "ICMP rule",
			rule: &rules.ParsedRule{
				Protocol:  "icmp",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "any",
				Direction: "->",
				Contents: []rules.ContentMatch{
					{Raw: []byte("ping")},
				},
			},
			wantProto: "icmp",
			wantErr:   false,
		},
		{
			name: "IP rule",
			rule: &rules.ParsedRule{
				Protocol:  "ip",
				SrcNet:    "any",
				DstNet:    "any",
				SrcPorts:  "any",
				DstPorts:  "any",
				Direction: "->",
				Contents: []rules.ContentMatch{
					{Raw: []byte("data")},
				},
			},
			wantProto: "ip",
			wantErr:   false,
		},
		{
			name: "ARP rule",
			rule: &rules.ParsedRule{
				Protocol:  "arp",
				SrcNet:    "192.168.1.1",
				DstNet:    "192.168.1.2",
				SrcPorts:  "any",
				DstPorts:  "any",
				Direction: "->",
				Contents: []rules.ContentMatch{
					{Raw: []byte("arp")},
				},
			},
			wantProto: "arp",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkts, err := g.Generate(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(pkts) == 0 {
				t.Error("Generate() returned empty packet slice")
			}
		})
	}
}

func TestGenerator_expandPort(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		ports  string
		expect uint16
	}{
		{"any", 80},
		{"80", 80},
		{"443", 443},
		{"8080", 8080},
		{"80:90", 80},
		{"100:200", 100},
		{"$HTTP_PORT", 80},
		{"!80", 80},
	}

	for _, tt := range tests {
		t.Run(tt.ports, func(t *testing.T) {
			got := g.expandPort(tt.ports)
			if got != tt.expect {
				t.Errorf("expandPort(%q) = %d, want %d", tt.ports, got, tt.expect)
			}
		})
	}
}

func TestGenerator_expandIP(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		net    string
		expect string
	}{
		{"any", "10.0.0.1"},
		{"", "10.0.0.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"$HOME_NET", "10.0.0.0"},
		{"10.0.0.0/24", "10.0.0.0"},
		{"192.168.1.0/24", "192.168.1.0"},
		{"!10.0.0.0/8", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.net, func(t *testing.T) {
			got := g.expandIP(tt.net)
			if got != tt.expect {
				t.Errorf("expandIP(%q) = %q, want %q", tt.net, got, tt.expect)
			}
		})
	}
}

func TestGenerator_buildPayload(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name     string
		contents []rules.ContentMatch
		want     []byte
	}{
		{
			name:     "empty contents",
			contents: []rules.ContentMatch{},
			want:     []byte("test payload"),
		},
		{
			name: "single content",
			contents: []rules.ContentMatch{
				{Raw: []byte("hello")},
			},
			want: []byte("hello"),
		},
		{
			name: "multiple contents",
			contents: []rules.ContentMatch{
				{Raw: []byte("hello")},
				{Raw: []byte("world")},
			},
			want: []byte("helloworld"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.buildPayload(tt.contents, nil)
			if string(got) != string(tt.want) {
				t.Errorf("buildPayload() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerator_BidirectionalRules(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name             string
		rule             *rules.ParsedRule
		expectedPktCount int
	}{
		{
			name: "unidirectional rule ->",
			rule: &rules.ParsedRule{
				Protocol:  "tcp",
				SrcNet:    "192.168.1.1",
				DstNet:    "10.0.0.1",
				SrcPorts:  "12345",
				DstPorts:  "80",
				Direction: "->",
				Contents: []rules.ContentMatch{
					{Raw: []byte("test")},
				},
			},
			expectedPktCount: 1,
		},
		{
			name: "bidirectional rule <>",
			rule: &rules.ParsedRule{
				Protocol:        "tcp",
				SrcNet:          "192.168.1.1",
				DstNet:          "10.0.0.1",
				SrcPorts:        "12345",
				DstPorts:        "80",
				Direction:       "<>",
				IsBidirectional: true,
				Contents: []rules.ContentMatch{
					{Raw: []byte("test")},
				},
			},
			expectedPktCount: 2,
		},
		{
			name: "bidirectional UDP rule",
			rule: &rules.ParsedRule{
				Protocol:        "udp",
				SrcNet:          "192.168.1.1",
				DstNet:          "10.0.0.1",
				SrcPorts:        "53",
				DstPorts:        "53",
				Direction:       "<>",
				IsBidirectional: true,
				Contents: []rules.ContentMatch{
					{Raw: []byte("dns")},
				},
			},
			expectedPktCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkts, err := g.Generate(tt.rule)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}
			if len(pkts) != tt.expectedPktCount {
				t.Errorf("Generate() returned %d packets, want %d", len(pkts), tt.expectedPktCount)
			}
		})
	}
}
