package packets

import (
	"crypto/rand"
	"encoding/binary"
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
	RandomMAC      bool
	RandomSeq      bool
}

func NewGenerator() *Generator {
	return NewGeneratorWithVars(nil)
}

func NewGeneratorWithVars(vars map[string]string) *Generator {
	// Default vars
	defaultVars := map[string]string{
		"$HOME_NET":     "10.0.0.0/24",
		"$EXTERNAL_NET": "any",
		"$HTTP_SERVERS": "any",
		"$SMTP_SERVERS": "any",
		"$DNS_SERVERS":  "any",
		"$SSH_SERVERS":  "any",
	}

	// Merge with provided vars (provided vars override defaults)
	if vars != nil {
		for k, v := range vars {
			defaultVars[k] = v
		}
	}

	return &Generator{
		DefaultSrcIP:   "192.168.1.100",
		DefaultDstIP:   "10.0.0.1",
		DefaultSrcPort: 12345,
		DefaultDstPort: 80,
		Vars:           defaultVars,
		RandomMAC:      false,
		RandomSeq:      false,
	}
}

// randomMAC generates a random MAC address with the local bit set
func randomMAC() net.HardwareAddr {
	mac := make([]byte, 6)
	rand.Read(mac)
	// Set local bit and clear multicast bit
	mac[0] = (mac[0] & 0xfe) | 0x02
	return net.HardwareAddr(mac)
}

var defaultSrcMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
var defaultDstMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

func (g *Generator) srcMAC() net.HardwareAddr {
	if g.RandomMAC {
		return randomMAC()
	}
	return defaultSrcMAC
}

func (g *Generator) dstMAC() net.HardwareAddr {
	if g.RandomMAC {
		return randomMAC()
	}
	return defaultDstMAC
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
	case "sctp":
		pkts, err = g.buildSCTP(rule, false)
	case "dns":
		pkts, err = g.buildDNS(rule, false)
	case "arp":
		pkts, err = g.buildARP(rule, false)
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
		case "sctp":
			reversePkts, err = g.buildSCTP(rule, true)
		case "dns":
			reversePkts, err = g.buildDNS(rule, true)
		case "arp":
			reversePkts, err = g.buildARP(rule, true)
		}
		if err == nil {
			pkts = append(pkts, reversePkts...)
		}
	}

	return pkts, nil
}

func (g *Generator) buildARP(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
	srcIP := g.expandIP(rule.SrcNet)
	dstIP := g.expandIP(rule.DstNet)

	if reverse {
		srcIP, dstIP = dstIP, srcIP
	}

	payload := g.buildPayload(rule.Contents, rule.PCREMatches)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	buf := gopacket.NewSerializeBuffer()

	// ARP Request: Who has dstIP? Tell srcIP
	// ARP Reply: srcIP is at my MAC
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(g.srcMAC()),
		SourceProtAddress: net.ParseIP(srcIP).To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    net.ParseIP(dstIP).To4(),
	}

	eth := &layers.Ethernet{
		SrcMAC:       g.srcMAC(),
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		EthernetType: layers.EthernetTypeARP,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, arp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return []gopacket.Packet{packet}, nil
}

func (g *Generator) buildDNS(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
	srcIP := g.expandIP(rule.SrcNet)
	dstIP := g.expandIP(rule.DstNet)
	srcPort := g.expandPort(rule.SrcPorts)
	dstPort := g.expandPort(rule.DstPorts)

	if reverse {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	// Default DNS ports
	if dstPort == 0 {
		dstPort = 53
	}
	if srcPort == 0 {
		srcPort = 12345
	}

	payload := g.buildDNSQueryPayload(rule.Contents)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	srcIPParsed := net.ParseIP(srcIP)
	dstIPParsed := net.ParseIP(dstIP)

	buf := gopacket.NewSerializeBuffer()

	if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
		// IPv4
		eth := &layers.Ethernet{
			SrcMAC:       g.srcMAC(),
			DstMAC:       g.dstMAC(),
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			SrcIP:    srcIPParsed,
			DstIP:    dstIPParsed,
			Protocol: layers.IPProtocolUDP,
			Version:  4,
			IHL:      5,
			TTL:      resolveTTL(rule),
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
			return nil, err
		}
	} else {
		// IPv6
		eth := &layers.Ethernet{
			SrcMAC:       g.srcMAC(),
			DstMAC:       g.dstMAC(),
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip6 := &layers.IPv6{
			SrcIP:      srcIPParsed,
			DstIP:      dstIPParsed,
			Version:    6,
			HopLimit:   resolveTTL(rule),
			NextHeader: layers.IPProtocolUDP,
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ip6)
		if err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload(payload)); err != nil {
			return nil, err
		}
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return []gopacket.Packet{packet}, nil
}

func (g *Generator) buildDNSQueryPayload(contents []rules.ContentMatch) []byte {
	if len(contents) > 0 {
		// Use content match as the query domain
		var domain []byte
		for _, c := range contents {
			domain = append(domain, c.Raw...)
		}
		return g.buildDNSQuery(domain)
	}
	// Default query for example.com
	return g.buildDNSQuery([]byte("example.com"))
}

func (g *Generator) buildDNSQuery(domain []byte) []byte {
	// Build a basic DNS query packet
	buf := make([]byte, 0)

	// Transaction ID (2 bytes)
	buf = append(buf, 0x00, 0x01)

	// Flags: standard query (2 bytes)
	// 0x0100 = QR=0 (query), OPCODE=0 (standard), AA=0, TC=0, RD=0
	// 0x0000 = RA=0, Z=0, RCODE=0
	buf = append(buf, 0x01, 0x00)

	// Questions count (2 bytes) - 1 question
	buf = append(buf, 0x00, 0x01)

	// Answer RRs (2 bytes) - 0
	buf = append(buf, 0x00, 0x00)

	// Authority RRs (2 bytes) - 0
	buf = append(buf, 0x00, 0x00)

	// Additional RRs (2 bytes) - 0
	buf = append(buf, 0x00, 0x00)

	// Query name (domain)
	domainStr := string(domain)
	labels := strings.Split(domainStr, ".")
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00) // Null terminator

	// Query type (2 bytes) - A (host address) = 1
	buf = append(buf, 0x00, 0x01)

	// Query class (2 bytes) - IN (internet) = 1
	buf = append(buf, 0x00, 0x01)

	return buf
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

	srcIPParsed := net.ParseIP(srcIP)
	dstIPParsed := net.ParseIP(dstIP)

	buf := gopacket.NewSerializeBuffer()

	if rule.VLANID > 0 {
		if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
			// IPv4 with VLAN
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeDot1Q,
			}
			vlan := &layers.Dot1Q{
				VLANIdentifier: rule.VLANID,
				Type:           layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				SrcIP:    srcIPParsed,
				DstIP:    dstIPParsed,
				Protocol: layers.IPProtocolTCP,
				Version:  4,
				IHL:      5,
				TTL:      resolveTTL(rule),
			}
			tcp := g.buildTCPFlags(rule, reverse)
			tcp.SetNetworkLayerForChecksum(ip)
			if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip, tcp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			// IPv6 with VLAN
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeDot1Q,
			}
			vlan := &layers.Dot1Q{
				VLANIdentifier: rule.VLANID,
				Type:           layers.EthernetTypeIPv6,
			}
			ip6 := &layers.IPv6{
				SrcIP:      srcIPParsed,
				DstIP:      dstIPParsed,
				Version:    6,
				HopLimit:   resolveTTL(rule),
				NextHeader: layers.IPProtocolTCP,
			}
			tcp := g.buildTCPFlags(rule, reverse)
			tcp.SetNetworkLayerForChecksum(ip6)
			if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip6, tcp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		}
	} else {
		if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
			// IPv4
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				SrcIP:    srcIPParsed,
				DstIP:    dstIPParsed,
				Protocol: layers.IPProtocolTCP,
				Version:  4,
				IHL:      5,
				TTL:      resolveTTL(rule),
			}
			tcp := g.buildTCPFlags(rule, reverse)
			tcp.SetNetworkLayerForChecksum(ip)
			if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			// IPv6
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeIPv6,
			}
			ip6 := &layers.IPv6{
				SrcIP:      srcIPParsed,
				DstIP:      dstIPParsed,
				Version:    6,
				HopLimit:   resolveTTL(rule),
				NextHeader: layers.IPProtocolTCP,
			}
			tcp := g.buildTCPFlags(rule, reverse)
			tcp.SetNetworkLayerForChecksum(ip6)
			if err := gopacket.SerializeLayers(buf, opts, eth, ip6, tcp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		}
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

	seq := uint32(100)
	if g.RandomSeq {
		var b [4]byte
		rand.Read(b[:])
		seq = binary.BigEndian.Uint32(b[:])
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Window:  65535,
		SYN:     true,
		ACK:     true,
	}

	if flagsRaw, ok := getRuleOption(rule, "tcp_flags"); ok && applyTCPFlags(tcp, flagsRaw) {
		return tcp
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

func getRuleOption(rule *rules.ParsedRule, key string) (string, bool) {
	if rule == nil || rule.Options == nil {
		return "", false
	}
	if v, ok := rule.Options[key]; ok {
		return strings.TrimSpace(v), true
	}
	for k, v := range rule.Options {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func applyTCPFlags(tcp *layers.TCP, flagsRaw string) bool {
	flagsRaw = strings.TrimSpace(strings.ToLower(flagsRaw))
	if flagsRaw == "" {
		return false
	}

	tcp.SYN = false
	tcp.ACK = false
	tcp.PSH = false
	tcp.RST = false
	tcp.FIN = false
	tcp.URG = false

	applied := false
	parts := strings.FieldsFunc(flagsRaw, func(r rune) bool {
		return r == ',' || r == '|' || r == ' ' || r == '+'
	})
	for _, part := range parts {
		switch strings.TrimSpace(part) {
		case "":
			continue
		case "all":
			tcp.SYN = true
			tcp.ACK = true
			tcp.PSH = true
			tcp.RST = true
			tcp.FIN = true
			tcp.URG = true
			applied = true
		case "none":
			applied = true
		case "syn":
			tcp.SYN = true
			applied = true
		case "ack":
			tcp.ACK = true
			applied = true
		case "psh":
			tcp.PSH = true
			applied = true
		case "rst":
			tcp.RST = true
			applied = true
		case "fin":
			tcp.FIN = true
			applied = true
		case "urg":
			tcp.URG = true
			applied = true
		}
	}

	return applied
}

func resolveTTL(rule *rules.ParsedRule) uint8 {
	const defaultTTL = 64
	if rule == nil {
		return defaultTTL
	}

	if raw, ok := getRuleOption(rule, "ttl"); ok {
		if ttl, err := strconv.Atoi(raw); err == nil && ttl >= 1 && ttl <= 255 {
			return uint8(ttl)
		}
	}
	if raw, ok := getRuleOption(rule, "hop_limit"); ok {
		if ttl, err := strconv.Atoi(raw); err == nil && ttl >= 1 && ttl <= 255 {
			return uint8(ttl)
		}
	}

	return defaultTTL
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

	srcIPParsed := net.ParseIP(srcIP)
	dstIPParsed := net.ParseIP(dstIP)

	buf := gopacket.NewSerializeBuffer()

	if rule.VLANID > 0 {
		if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
			// IPv4 with VLAN
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeDot1Q,
			}
			vlan := &layers.Dot1Q{
				VLANIdentifier: rule.VLANID,
				Type:           layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				SrcIP:    srcIPParsed,
				DstIP:    dstIPParsed,
				Protocol: layers.IPProtocolUDP,
				Version:  4,
				IHL:      5,
				TTL:      resolveTTL(rule),
			}
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(srcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(ip)
			if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip, udp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			// IPv6 with VLAN
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeDot1Q,
			}
			vlan := &layers.Dot1Q{
				VLANIdentifier: rule.VLANID,
				Type:           layers.EthernetTypeIPv6,
			}
			ip6 := &layers.IPv6{
				SrcIP:      srcIPParsed,
				DstIP:      dstIPParsed,
				Version:    6,
				HopLimit:   resolveTTL(rule),
				NextHeader: layers.IPProtocolUDP,
			}
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(srcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(ip6)
			if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip6, udp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		}
	} else {
		if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
			// IPv4
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				SrcIP:    srcIPParsed,
				DstIP:    dstIPParsed,
				Protocol: layers.IPProtocolUDP,
				Version:  4,
				IHL:      5,
				TTL:      resolveTTL(rule),
			}
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(srcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(ip)
			if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			// IPv6
			eth := &layers.Ethernet{
				SrcMAC:       g.srcMAC(),
				DstMAC:       g.dstMAC(),
				EthernetType: layers.EthernetTypeIPv6,
			}
			ip6 := &layers.IPv6{
				SrcIP:      srcIPParsed,
				DstIP:      dstIPParsed,
				Version:    6,
				HopLimit:   resolveTTL(rule),
				NextHeader: layers.IPProtocolUDP,
			}
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(srcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(ip6)
			if err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		}
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
		SrcMAC:       g.srcMAC(),
		DstMAC:       g.dstMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolICMPv4,
		Version:  4,
		IHL:      5,
		TTL:      resolveTTL(rule),
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
			SrcMAC:       g.srcMAC(),
			DstMAC:       g.dstMAC(),
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			SrcIP:   srcIPParsed,
			DstIP:   dstIPParsed,
			Version: 4,
			IHL:     5,
			TTL:     resolveTTL(rule),
		}
		err := gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(payload))
		if err != nil {
			return nil, err
		}
	} else {
		// IPv6
		eth := &layers.Ethernet{
			SrcMAC:       g.srcMAC(),
			DstMAC:       g.dstMAC(),
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip6 := &layers.IPv6{
			SrcIP:      srcIPParsed,
			DstIP:      dstIPParsed,
			Version:    6,
			HopLimit:   resolveTTL(rule),
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

func (g *Generator) buildSCTP(rule *rules.ParsedRule, reverse bool) ([]gopacket.Packet, error) {
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

	srcIPParsed := net.ParseIP(srcIP)
	dstIPParsed := net.ParseIP(dstIP)

	buf := gopacket.NewSerializeBuffer()

	if srcIPParsed.To4() != nil || dstIPParsed.To4() != nil {
		// IPv4
		eth := &layers.Ethernet{
			SrcMAC:       g.srcMAC(),
			DstMAC:       g.dstMAC(),
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			SrcIP:    srcIPParsed,
			DstIP:    dstIPParsed,
			Protocol: layers.IPProtocolSCTP,
			Version:  4,
			IHL:      5,
			TTL:      resolveTTL(rule),
		}
		sctp := &layers.SCTP{
			SrcPort: layers.SCTPPort(srcPort),
			DstPort: layers.SCTPPort(dstPort),
		}
		err := gopacket.SerializeLayers(buf, opts, eth, ip, sctp, gopacket.Payload(payload))
		if err != nil {
			return nil, err
		}
	} else {
		// IPv6
		eth := &layers.Ethernet{
			SrcMAC:       g.srcMAC(),
			DstMAC:       g.dstMAC(),
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip6 := &layers.IPv6{
			SrcIP:      srcIPParsed,
			DstIP:      dstIPParsed,
			Version:    6,
			HopLimit:   resolveTTL(rule),
			NextHeader: layers.IPProtocolSCTP,
		}
		sctp := &layers.SCTP{
			SrcPort: layers.SCTPPort(srcPort),
			DstPort: layers.SCTPPort(dstPort),
		}
		err := gopacket.SerializeLayers(buf, opts, eth, ip6, sctp, gopacket.Payload(payload))
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
