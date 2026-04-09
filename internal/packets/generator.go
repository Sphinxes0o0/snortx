package packets

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/user/snortx/internal/rules"
)

type Generator struct {
	DefaultSrcIP   string
	DefaultDstIP   string
	DefaultSrcPort uint16
	DefaultDstPort uint16
	Vars           map[string]string
}

func NewGenerator() *Generator {
	return &Generator{
		DefaultSrcIP:   "192.168.1.100",
		DefaultDstIP:   "10.0.0.1",
		DefaultSrcPort: 12345,
		DefaultDstPort: 80,
		Vars: map[string]string{
			"$HOME_NET":     "10.0.0.0/24",
			"$EXTERNAL_NET": "any",
			"$HTTP_SERVERS": "any",
			"$SMTP_SERVERS": "any",
			"$DNS_SERVERS":  "any",
			"$SSH_SERVERS":  "any",
		},
	}
}

func (g *Generator) Generate(rule *rules.ParsedRule) ([]gopacket.Packet, error) {
	var pkts []gopacket.Packet
	var err error

	switch rule.Protocol {
	case "tcp":
		pkts, err = g.buildTCP(rule, false)
	case "udp":
		pkts, err = g.buildUDP(rule, false)
	case "icmp":
		pkts, err = g.buildICMP(rule, false)
	case "ip":
		pkts, err = g.buildIP(rule, false)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", rule.Protocol)
	}

	if err != nil {
		return nil, err
	}

	if rule.IsBidirectional {
		var reversePkts []gopacket.Packet
		switch rule.Protocol {
		case "tcp":
			reversePkts, err = g.buildTCP(rule, true)
		case "udp":
			reversePkts, err = g.buildUDP(rule, true)
		case "icmp":
			reversePkts, err = g.buildICMP(rule, true)
		case "ip":
			reversePkts, err = g.buildIP(rule, true)
		}
		if err == nil {
			pkts = append(pkts, reversePkts...)
		}
	}

	return pkts, nil
}

func (g *Generator) buildTCP(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
	srcIP := g.expandIP(rule.SrcNet)
	dstIP := g.expandIP(rule.DstNet)
	srcPort := g.expandPort(rule.SrcPorts)
	dstPort := g.expandPort(rule.DstPorts)

	if reverse {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	payload := g.buildPayload(rule.Contents, rule.PCREMatches)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		IHL:      5,
		TTL:      64,
	}

	tcp := g.buildTCPFlags(rule, reverse)

	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	var err error
	err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return []gopacket.Packet{packet}, nil
}

func (g *Generator) buildTCPFlags(rule *rules.ParsedRule, reverse bool) *layers.TCP {
	srcPort := g.expandPort(rule.SrcPorts)
	dstPort := g.expandPort(rule.DstPorts)

	if reverse {
		srcPort, dstPort = dstPort, srcPort
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     100,
		Window:  65535,
		SYN:     true,
		ACK:     true,
	}

	flow := rule.Flow
	if flow == "" {
		return tcp
	}

	switch {
	case strings.Contains(flow, "established"):
		tcp.SYN = false
		tcp.ACK = true
		tcp.PSH = true
	case strings.Contains(flow, "to_server"):
		tcp.SYN = true
		tcp.ACK = false
		tcp.PSH = false
	case strings.Contains(flow, "to_client"):
		tcp.SYN = true
		tcp.ACK = true
		tcp.PSH = true
	case strings.Contains(flow, "from_server"):
		tcp.SYN = false
		tcp.ACK = true
		tcp.PSH = true
	case strings.Contains(flow, "from_client"):
		tcp.SYN = false
		tcp.ACK = true
		tcp.PSH = true
	case strings.Contains(flow, "only_stream"):
		tcp.SYN = false
		tcp.ACK = true
	}

	return tcp
}

func (g *Generator) buildUDP(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
	srcIP := g.expandIP(rule.SrcNet)
	dstIP := g.expandIP(rule.DstNet)
	srcPort := g.expandPort(rule.SrcPorts)
	dstPort := g.expandPort(rule.DstPorts)

	if reverse {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	payload := g.buildPayload(rule.Contents, rule.PCREMatches)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		IHL:      5,
		TTL:      64,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return []gopacket.Packet{packet}, nil
}

func (g *Generator) buildICMP(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
	srcIP := g.expandIP(rule.SrcNet)
	dstIP := g.expandIP(rule.DstNet)

	if reverse {
		srcIP, dstIP = dstIP, srcIP
	}

	payload := g.buildPayload(rule.Contents, rule.PCREMatches)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolICMPv4,
		Version:  4,
		IHL:      5,
		TTL:      64,
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return []gopacket.Packet{packet}, nil
}

func (g *Generator) buildIP(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
	srcIP := g.expandIP(rule.SrcNet)
	dstIP := g.expandIP(rule.DstNet)

	if reverse {
		srcIP, dstIP = dstIP, srcIP
	}

	payload := g.buildPayload(rule.Contents, rule.PCREMatches)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	srcIPParsed := net.ParseIP(srcIP)
	dstIPParsed := net.ParseIP(dstIP)

	buf := gopacket.NewSerializeBuffer()

	if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
		// IPv4
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			SrcIP:   srcIPParsed,
			DstIP:   dstIPParsed,
			Version: 4,
			IHL:     5,
			TTL:     64,
		}
		err := gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(payload))
		if err != nil {
			return nil, err
		}
	} else {
		// IPv6
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip6 := &layers.IPv6{
			SrcIP:      srcIPParsed,
			DstIP:      dstIPParsed,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocol(0), // No next header for raw IP payload
		}
		err := gopacket.SerializeLayers(buf, opts, eth, ip6, gopacket.Payload(payload))
		if err != nil {
			return nil, err
		}
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return []gopacket.Packet{packet}, nil
}

func (g *Generator) buildPayload(contents []rules.ContentMatch, pcreMatches []rules.PCREMatch) []byte {
	if len(contents) > 0 {
		result := make([]byte, 0)
		for _, c := range contents {
			result = append(result, c.Raw...)
		}
		return result
	}

	// Try to extract literals from PCRE
	if len(pcreMatches) > 0 {
		for _, pcre := range pcreMatches {
			if lit := extractLiteralFromPCRE(pcre.Pattern); lit != nil {
				return lit
			}
		}
	}

	return []byte("test payload")
}

// extractLiteralFromPCRE tries to extract a literal string from a PCRE pattern
func extractLiteralFromPCRE(pattern string) []byte {
	// First, try simple quoted strings
	if lit := extractQuotedString(pattern); lit != nil {
		return lit
	}

	// Try to extract hex escapes
	if lit := extractHexEscapes(pattern); lit != nil {
		return lit
	}

	// Strip complex PCRE constructs and try to find literal content
	stripped := stripPCREConstructs(pattern)
	if stripped == "" {
		return nil
	}

	// After stripping, try quoted strings and hex again
	if lit := extractQuotedString(stripped); lit != nil {
		return lit
	}
	if lit := extractHexEscapes(stripped); lit != nil {
		return lit
	}

	// Try to decode remaining escaped characters as literal bytes
	return decodeEscapedString(stripped)
}

func extractQuotedString(pattern string) []byte {
	re := regexp.MustCompile(`["']([^"']+)["']`)
	matches := re.FindStringSubmatch(pattern)
	if len(matches) > 1 {
		return []byte(matches[1])
	}
	return nil
}

func extractHexEscapes(pattern string) []byte {
	hexRe := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	hexMatches := hexRe.FindAllStringSubmatch(pattern, -1)
	if len(hexMatches) > 0 {
		result := make([]byte, 0)
		for _, m := range hexMatches {
			if b, err := strconv.ParseUint(m[1], 16, 8); err == nil {
				result = append(result, byte(b))
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return nil
}

// stripPCREConstructs removes lookahead, lookbehind, non-capturing groups,
// quantifiers, anchors, and other PCRE constructs to extract the literal core
func stripPCREConstructs(pattern string) string {
	// Remove lookahead/lookbehind: (?=...), (?!...), (?<=...), (?<!...)
	// and non-capturing groups: (?:...)
	lookRe := regexp.MustCompile(`\(\?(?:[=!]|<[=!]?)?[^)]*\)`)
	pattern = lookRe.ReplaceAllString(pattern, "")

	// Remove atomic groups and possessive quantifiers: (?>...), *+, ++, ?+
	atomicRe := regexp.MustCompile(`\(\?>[^)]*\)|\([^+?]+\+|[+?]\+`)
	pattern = atomicRe.ReplaceAllString(pattern, "")

	// Remove anchors that Go regex doesn't support: \A, \z
	pattern = strings.ReplaceAll(pattern, "\\A", "")
	pattern = strings.ReplaceAll(pattern, "\\z", "")

	// Remove word boundaries that might cause issues: \b, \B
	pattern = strings.ReplaceAll(pattern, "\\b", "")
	pattern = strings.ReplaceAll(pattern, "\\B", "")

	// Remove quantifiers: *, +, ?, {n,m}
	quantRe := regexp.MustCompile(`[+*?]\??|\{[^}]*\}`)
	pattern = quantRe.ReplaceAllString(pattern, "")

	// Handle alternation - take first alternative
	if idx := strings.Index(pattern, "|"); idx > 0 {
		pattern = pattern[:idx]
	}

	// Remove remaining parentheses (capturing groups)
	parenRe := regexp.MustCompile(`\([^)]*\)`)
	for parenRe.MatchString(pattern) {
		pattern = parenRe.ReplaceAllString(pattern, "")
	}

	// Remove character class negation at start: [^...]
	classNegRe := regexp.MustCompile(`\[\^[^\]]+\]`)
	pattern = classNegRe.ReplaceAllString(pattern, "")

	return pattern
}

func decodeEscapedString(pattern string) []byte {
	// Handle common escape sequences that represent single bytes
	result := make([]byte, 0)
	i := 0
	for i < len(pattern) {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			next := pattern[i+1]
			switch next {
			case 'x':
				// Hex escape \xNN
				if i+3 < len(pattern) {
					if b, err := strconv.ParseUint(pattern[i+2:i+4], 16, 8); err == nil {
						result = append(result, byte(b))
						i += 4
						continue
					}
				}
				i += 2
			case 'd', 'w', 's', 'D', 'W', 'S':
				// Character class escapes - can't convert to literal
				i += 2
			case 'n':
				result = append(result, '\n')
				i += 2
			case 'r':
				result = append(result, '\r')
				i += 2
			case 't':
				result = append(result, '\t')
				i += 2
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				// Backreference or octal - skip
				i += 2
			default:
				// Escaped literal character
				result = append(result, next)
				i += 2
			}
		} else if pattern[i] >= 32 && pattern[i] < 127 {
			// Printable ASCII
			result = append(result, pattern[i])
			i++
		} else {
			// Non-printable or non-ASCII - skip
			i++
		}
	}
	return result
}

func (g *Generator) expandIP(net_ string) string {
	if net_ == "any" || net_ == "" {
		return g.DefaultDstIP
	}

	if net_[0] == '$' {
		if val, ok := g.Vars[net_]; ok {
			if val == "any" || val == "$EXTERNAL_NET" {
				return g.DefaultDstIP
			}
			if ip := g.extractIPFromCIDR(val); ip != "" {
				return ip
			}
			return val
		}
		return g.DefaultDstIP
	}

	if net_[0] == '!' {
		return g.DefaultDstIP
	}

	if strings.Contains(net_, "/") {
		return g.extractIPFromCIDR(net_)
	}

	return net_
}

func (g *Generator) extractIPFromCIDR(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	ip := ipNet.IP.To4()
	if ip != nil {
		return ip.String()
	}
	return cidr
}

func (g *Generator) expandPort(ports string) uint16 {
	if ports == "any" || ports == "" {
		return g.DefaultDstPort
	}
	if ports[0] == '$' {
		// Look up variable
		if val, ok := g.Vars[ports]; ok {
			if val == "any" {
				return g.DefaultDstPort
			}
			// Try to parse as port number
			if port, err := strconv.Atoi(val); err == nil && port > 0 && port < 65536 {
				return uint16(port)
			}
			// Handle port lists like "80,443"
			if strings.Contains(val, ",") {
				parts := strings.Split(val, ",")
				if p, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
					return uint16(p)
				}
			}
			// Handle port ranges like "8000:9000"
			if strings.Contains(val, ":") {
				rangeParts := strings.Split(val, ":")
				if p, err := strconv.Atoi(strings.TrimSpace(rangeParts[0])); err == nil {
					return uint16(p)
				}
			}
		}
		return g.DefaultDstPort
	}
	if ports[0] == '!' {
		return g.DefaultDstPort
	}

	if strings.Contains(ports, ":") {
		parts := strings.Split(ports, ":")
		if len(parts) == 2 {
			var startPort, endPort uint64
			fmt.Sscanf(parts[0], "%d", &startPort)
			fmt.Sscanf(parts[1], "%d", &endPort)
			if startPort > 0 && startPort < 65536 {
				return uint16(startPort)
			}
			if endPort > 0 && endPort < 65536 {
				return uint16(endPort)
			}
		}
		return g.DefaultDstPort
	}

	var port uint64
	fmt.Sscanf(ports, "%d", &port)
	if port > 0 && port < 65536 {
		return uint16(port)
	}
	return g.DefaultDstPort
}
