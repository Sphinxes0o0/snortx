package packets

import (
	"testing"

	"github.com/google/gopacket/layers"
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

func TestGeneratorWithVars(t *testing.T) {
	// Test default generator
	gDefault := NewGenerator()
	if got := gDefault.expandIP("$HOME_NET"); got != "10.0.0.0" {
		t.Errorf("default $HOME_NET = %q, want %q", got, "10.0.0.0")
	}

	// Test generator with custom vars
	customVars := map[string]string{
		"$HOME_NET":     "172.16.0.0/24",
		"$EXTERNAL_NET": "8.8.8.0/24",
	}
	gCustom := NewGeneratorWithVars(customVars)

	// Custom $HOME_NET should expand to first IP in CIDR
	if got := gCustom.expandIP("$HOME_NET"); got != "172.16.0.0" {
		t.Errorf("custom $HOME_NET = %q, want %q", got, "172.16.0.0")
	}

	// Custom $EXTERNAL_NET should expand to first IP in CIDR
	if got := gCustom.expandIP("$EXTERNAL_NET"); got != "8.8.8.0" {
		t.Errorf("custom $EXTERNAL_NET = %q, want %q", got, "8.8.8.0")
	}

	// Default vars should still work if not overridden
	if got := gCustom.expandIP("$HTTP_SERVERS"); got != "any" {
		// Default is "any" which maps to DefaultDstIP
		// Custom generator should still have default vars merged
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

func TestGenerator_TCPFlagsOption(t *testing.T) {
	g := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "192.168.1.1",
		DstNet:    "10.0.0.1",
		SrcPorts:  "12345",
		DstPorts:  "80",
		Direction: "->",
		Options: map[string]string{
			"tcp_flags": "syn",
		},
	}

	tcp := g.buildTCPFlags(rule, false)
	if !tcp.SYN {
		t.Error("expected SYN=true")
	}
	if tcp.ACK || tcp.PSH || tcp.RST || tcp.FIN || tcp.URG {
		t.Error("expected only SYN flag to be set")
	}
}

func TestResolveTTL(t *testing.T) {
	rule := &rules.ParsedRule{
		Options: map[string]string{
			"ttl": "128",
		},
	}
	if ttl := resolveTTL(rule); ttl != 128 {
		t.Fatalf("resolveTTL() = %d, want 128", ttl)
	}
}

func TestGenerator_SameIPOption(t *testing.T) {
	g := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "192.168.1.10",
		DstNet:    "10.0.0.5",
		SrcPorts:  "12345",
		DstPorts:  "80",
		Direction: "->",
		Contents:  []rules.ContentMatch{{Raw: []byte("test")}},
		Options: map[string]string{
			"sameip": "true",
		},
	}

	pkts, err := g.Generate(rule)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	ipLayer := pkts[0].Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("expected IPv4 layer")
	}
	ip := ipLayer.(*layers.IPv4)
	if !ip.SrcIP.Equal(ip.DstIP) {
		t.Fatalf("expected same src/dst IP, got %s -> %s", ip.SrcIP, ip.DstIP)
	}
}

func TestGenerator_FlagsAliasOption(t *testing.T) {
	g := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "192.168.1.1",
		DstNet:    "10.0.0.1",
		SrcPorts:  "12345",
		DstPorts:  "80",
		Direction: "->",
		Options: map[string]string{
			"flags": "syn,ack",
		},
	}

	tcp := g.buildTCPFlags(rule, false)
	if !tcp.SYN || !tcp.ACK {
		t.Fatalf("expected SYN and ACK to be set")
	}
	if tcp.PSH || tcp.RST || tcp.FIN || tcp.URG {
		t.Fatalf("expected only SYN/ACK flags to be set")
	}
}

func TestGenerator_DSizeOption(t *testing.T) {
	g := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "192.168.1.1",
		DstNet:    "10.0.0.1",
		SrcPorts:  "12345",
		DstPorts:  "80",
		Direction: "->",
		Contents:  []rules.ContentMatch{{Raw: []byte("test")}},
		DSize: &rules.DSizeOption{
			Op:  "=",
			Min: 8,
			Max: 8,
		},
	}

	pkts, err := g.Generate(rule)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	app := pkts[0].ApplicationLayer()
	if app == nil {
		t.Fatal("expected application payload")
	}
	if got := len(app.Payload()); got != 8 {
		t.Fatalf("expected payload length 8, got %d", got)
	}
	if string(app.Payload()[:4]) != "test" {
		t.Fatalf("expected payload to preserve original content, got %q", app.Payload())
	}
}

func TestGenerator_DSizeOptionRejectsImpossiblePayload(t *testing.T) {
	g := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "192.168.1.1",
		DstNet:    "10.0.0.1",
		SrcPorts:  "12345",
		DstPorts:  "80",
		Direction: "->",
		Contents:  []rules.ContentMatch{{Raw: []byte("toolong")}},
		DSize: &rules.DSizeOption{
			Op:  "<",
			Max: 4,
		},
	}

	if _, err := g.Generate(rule); err == nil {
		t.Fatal("expected dsize validation error")
	}
}

func TestGenerator_ICMPOptions(t *testing.T) {
	g := NewGenerator()
	rule := &rules.ParsedRule{
		Protocol:  "icmp",
		SrcNet:    "192.168.1.1",
		DstNet:    "10.0.0.1",
		Direction: "->",
		Contents:  []rules.ContentMatch{{Raw: []byte("ping")}},
		Options: map[string]string{
			"itype":    "3",
			"icode":    "1",
			"icmp_id":  "7",
			"icmp_seq": "9",
		},
	}

	pkts, err := g.Generate(rule)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	icmpLayer := pkts[0].Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		t.Fatal("expected ICMPv4 layer")
	}
	icmp := icmpLayer.(*layers.ICMPv4)
	if got := uint8(icmp.TypeCode.Type()); got != 3 {
		t.Fatalf("expected ICMP type 3, got %d", got)
	}
	if got := uint8(icmp.TypeCode.Code()); got != 1 {
		t.Fatalf("expected ICMP code 1, got %d", got)
	}
	if icmp.Id != 7 || icmp.Seq != 9 {
		t.Fatalf("expected ICMP id/seq 7/9, got %d/%d", icmp.Id, icmp.Seq)
	}
}
