//go:build linux
// +build linux

package packets

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SendMmsgInjector uses raw sockets with sendmmsg for high-performance batch sending on Linux.
type SendMmsgInjector struct {
	fd     int
	addr   unix.SockaddrInet4
	closed bool
	mu     sync.Mutex
}

// NewSendMmsgInjector creates a raw socket-based injector using sendmmsg batching.
func NewSendMmsgInjector(dstIP string, dstPort int) (*SendMmsgInjector, error) {
	// Create raw socket for UDP
	// SOCK_RAW with IPPROTO_UDP allows us to craft full packets including Ethernet header
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// Set IP_HDRINCL to manually include IP header in our packets
	// This allows us to send arbitrary IP packets
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Increase socket buffer for high throughput
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*1024*1024); err != nil {
		// Non-fatal, continue with default
	}

	// Set SO_SNDTIMEO to avoid blocking forever
	// Not strictly necessary since we control the send loop

	// Parse destination IP
	ip := net.ParseIP(dstIP)
	if ip == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("invalid destination IP: %s", dstIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("not an IPv4 address: %s", dstIP)
	}

	addr := unix.SockaddrInet4{
		Port: dstPort,
	}
	copy(addr.Addr[:], ip4)

	return &SendMmsgInjector{
		fd:   fd,
		addr: addr,
	}, nil
}

// WritePacket sends a single packet.
func (si *SendMmsgInjector) WritePacket(data []byte) error {
	if si.closed {
		return fmt.Errorf("injector is closed")
	}

	// Send the packet via raw socket
	n, err := unix.Sendto(si.fd, data, 0, &si.addr)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("incomplete send: sent %d of %d bytes", n, len(data))
	}
	return nil
}

// WritePackets sends multiple packets using sendmmsg for batching.
func (si *SendMmsgInjector) WritePackets(packets [][]byte) error {
	if si.closed {
		return fmt.Errorf("injector is closed")
	}
	if len(packets) == 0 {
		return nil
	}

	// Use sendmmsg to batch send packets
	// Each packet has its own iovec but same destination address
	n, err := unix.Sendmmsg(si.fd, si.buildMsghdrs(packets), 0)
	if err != nil {
		return err
	}
	if n != len(packets) {
		return fmt.Errorf("incomplete batch send: sent %d of %d packets", n, len(packets))
	}
	return nil
}

// buildMsghdrs builds msghdr structures for sendmmsg.
func (si *SendMmsgInjector) buildMsghdrs(packets [][]byte) []unix.Msghdr {
	msghdrs := make([]unix.Msghdr, len(packets))
	iovs := make([]unix.Iovec, len(packets))

	for i, pkt := range packets {
		iovs[i].Base = &pkt[0]
		iovs[i].SetLen(len(pkt))

		msghdrs[i].MsgName = (*byte)(unsafe.Pointer(&si.addr))
		msghdrs[i].MsgNamelen = unix.SizeofSockaddrInet4
		msghdrs[i].MsgIov = &iovs[i]
		msghdrs[i].MsgIovlen = 1
	}

	return msghdrs
}

// Close closes the raw socket.
func (si *SendMmsgInjector) Close() error {
	si.mu.Lock()
	defer si.mu.Unlock()
	if si.closed {
		return nil
	}
	si.closed = true
	return unix.Close(si.fd)
}

// Ensure SendMmsgInjector implements PacketInjector
var _ PacketInjector = (*SendMmsgInjector)(nil)

// MultiSendMmsgInjector uses multiple raw sockets with sendmmsg for parallel batch sending.
type MultiSendMmsgInjector struct {
	injectors []*SendMmsgInjector
	count     int
	nextIdx   int32
}

// NewMultiSendMmsgInjector creates multiple sendmmsg injectors for parallel sending.
func NewMultiSendMmsgInjector(dstIP string, dstPort int, numSockets int) (*MultiSendMmsgInjector, error) {
	if numSockets <= 0 {
		numSockets = 1
	}

	injectors := make([]*SendMmsgInjector, numSockets)
	for i := 0; i < numSockets; i++ {
		inj, err := NewSendMmsgInjector(dstIP, dstPort)
		if err != nil {
			// Close already created injectors
			for j := 0; j < i; j++ {
				injectors[j].Close()
			}
			return nil, fmt.Errorf("failed to create injector %d: %w", i, err)
		}
		injectors[i] = inj
	}

	return &MultiSendMmsgInjector{
		injectors: injectors,
		count:     numSockets,
	}, nil
}

// WritePacket writes to a round-robin injector.
func (mi *MultiSendMmsgInjector) WritePacket(data []byte) error {
	idx := atomic.AddInt32(&mi.nextIdx, 1) - 1
	return mi.injectors[idx%int32(mi.count)].WritePacket(data)
}

// WritePackets writes to a specific injector (caller should round-robin).
func (mi *MultiSendMmsgInjector) WritePackets(packets [][]byte) error {
	idx := atomic.AddInt32(&mi.nextIdx, 1) - 1
	return mi.injectors[idx%int32(mi.count)].WritePackets(packets)
}

// Close closes all underlying injectors.
func (mi *MultiSendMmsgInjector) Close() error {
	for _, inj := range mi.injectors {
		inj.Close()
	}
	return nil
}

// Ensure MultiSendMmsgInjector implements PacketInjector
var _ PacketInjector = (*MultiSendMmsgInjector)(nil)
