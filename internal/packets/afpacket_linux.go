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

// AFpacketConfig holds configuration for AF_PACKET sender.
type AFpacketConfig struct {
	Interface  string
	BlockSize  int // Must be power of 2, >= 4096
	FrameSize  int // Must be power of 2, >= 4096
	BlockCount int
}

// DefaultAFpacketConfig returns sensible defaults for high-performance TX.
func DefaultAFpacketConfig(iface string) AFpacketConfig {
	return AFpacketConfig{
		Interface:  iface,
		BlockSize:  4096 * 64, // 256KB blocks
		FrameSize:  2048,      // 2KB frames
		BlockCount: 64,        // 16MB total ring buffer
	}
}

// AFpacketInjector uses AF_PACKET socket for high-performance packet sending.
type AFpacketInjector struct {
	iface  string
	fd     int
	closed bool
	mu     sync.Mutex
}

// NewAFpacketInjector creates an AF_PACKET injector.
func NewAFpacketInjector(config AFpacketConfig) (*AFpacketInjector, error) {
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", config.Interface, err)
	}

	// Create AF_PACKET socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET socket: %w", err)
	}

	// Bind to interface
	addr := unix.SockaddrLinkLayer{
		Ifindex: int32(iface.Index),
	}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind to interface: %w", err)
	}

	return &AFpacketInjector{
		iface: config.Interface,
		fd:    fd,
	}, nil
}

// WritePacket sends a single packet.
func (ai *AFpacketInjector) WritePacket(data []byte) error {
	if ai.closed {
		return fmt.Errorf("injector is closed")
	}
	if len(data) == 0 {
		return fmt.Errorf("empty packet")
	}

	n, err := unix.Sendto(ai.fd, data, 0, nil)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("incomplete send: sent %d of %d bytes", n, len(data))
	}
	return nil
}

// WritePackets sends multiple packets.
func (ai *AFpacketInjector) WritePackets(packets [][]byte) error {
	if ai.closed {
		return fmt.Errorf("injector is closed")
	}
	for _, pkt := range packets {
		if err := ai.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the socket.
func (ai *AFpacketInjector) Close() error {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	if ai.closed {
		return nil
	}
	ai.closed = true
	return unix.Close(ai.fd)
}

// Ensure AFpacketInjector implements PacketInjector
var _ PacketInjector = (*AFpacketInjector)(nil)

// MultiAFpacketInjector uses multiple AF_PACKET sockets for parallel sending.
type MultiAFpacketInjector struct {
	injectors []*AFpacketInjector
	count     int
	nextIdx   int32
}

// NewMultiAFpacketInjector creates multiple AF_PACKET injectors for parallel sending.
func NewMultiAFpacketInjector(config AFpacketConfig, numSockets int) (*MultiAFpacketInjector, error) {
	if numSockets <= 0 {
		numSockets = 1
	}

	injectors := make([]*AFpacketInjector, numSockets)
	for i := 0; i < numSockets; i++ {
		inj, err := NewAFpacketInjector(config)
		if err != nil {
			for j := 0; j < i; j++ {
				injectors[j].Close()
			}
			return nil, fmt.Errorf("failed to create AF_PACKET injector %d: %w", i, err)
		}
		injectors[i] = inj
	}

	return &MultiAFpacketInjector{
		injectors: injectors,
		count:     numSockets,
	}, nil
}

// WritePacket writes to a round-robin injector.
func (mi *MultiAFpacketInjector) WritePacket(data []byte) error {
	idx := atomic.AddInt32(&mi.nextIdx, 1) - 1
	return mi.injectors[idx%int32(mi.count)].WritePacket(data)
}

// WritePackets writes to a specific injector (caller should round-robin).
func (mi *MultiAFpacketInjector) WritePackets(packets [][]byte) error {
	idx := atomic.AddInt32(&mi.nextIdx, 1) - 1
	return mi.injectors[idx%int32(mi.count)].WritePackets(packets)
}

// Close closes all underlying injectors.
func (mi *MultiAFpacketInjector) Close() error {
	for _, inj := range mi.injectors {
		inj.Close()
	}
	return nil
}

// Ensure MultiAFpacketInjector implements PacketInjector
var _ PacketInjector = (*MultiAFpacketInjector)(nil)

// AFpacketTXRing provides true zero-copy TX via memory-mapped ring buffer.
type AFpacketTXRing struct {
	fd        int
	iface     string
	ring      []byte
	frameSize int
	blockSize int
	blockNr   int
	frameNr   int

	// Producer state
	head int32

	mu     sync.Mutex
	closed bool
}

// NewAFpacketTXRing creates an AF_PACKET TX_RING sender with memory-mapped buffer.
func NewAFpacketTXRing(iface string, frameSize, blockSize, blockNr int) (*AFpacketTXRing, error) {
	ifIndex, err := getInterfaceIndex(iface)
	if err != nil {
		return nil, err
	}

	// Create socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Bind to interface
	addr := unix.SockaddrLinkLayer{Ifindex: ifIndex}
	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	// Align sizes
	if frameSize < 2048 {
		frameSize = 2048
	}
	if blockSize < 4096 {
		blockSize = 4096
	}
	if blockNr < 8 {
		blockNr = 8
	}

	framesPerBlock := blockSize / frameSize
	frameNr := framesPerBlock * blockNr

	// Request TX ring
	ringReq := unix.TpacketRingReq{
		BlockSize: uint32(blockSize),
		BlockNr:   uint32(blockNr),
		FrameSize: uint32(frameSize),
		FrameNr:   uint32(frameNr),
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_TX_RING, ringReq); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set TX ring: %w", err)
	}

	// Mmap the ring
	mmapSize := blockSize * blockNr
	ring, err := unix.Mmap(fd, 0, int(mmapSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to mmap: %w", err)
	}

	return &AFpacketTXRing{
		fd:        fd,
		iface:     iface,
		ring:      ring,
		frameSize: frameSize,
		blockSize: blockSize,
		blockNr:   blockNr,
		frameNr:   frameNr,
		head:      0,
	}, nil
}

// getInterfaceIndex returns the index for a named interface.
func getInterfaceIndex(iface string) (int, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("failed to find interface %s: %w", iface, err)
	}
	return ifi.Index, nil
}

// WritePacket transmits a packet via the TX ring.
func (tx *AFpacketTXRing) WritePacket(data []byte) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.closed {
		return fmt.Errorf("ring is closed")
	}
	if len(data) > tx.frameSize {
		return fmt.Errorf("packet too large: %d > %d", len(data), tx.frameSize)
	}

	// Wait for an available frame using poll
	for {
		if tx.closed {
			return fmt.Errorf("ring is closed")
		}
		// Poll for POLLOUT to wait for available frames
		var fds [1]unix.PollFd
		fds[0].Fd = int32(tx.fd)
		fds[0].Events = unix.POLLOUT
		fds[0].Revents = 0
		n, err := unix.Poll(fds[:], 100) // 100ms timeout
		if err != nil {
			return fmt.Errorf("poll failed: %w", err)
		}
		if n > 0 && fds[0].Revents&unix.POLLOUT != 0 {
			break // Frame available
		}
		// Continue waiting
	}

	// Reserve frame
	frameIdx := atomic.AddInt32(&tx.head, 1) - 1
	frameIdx = frameIdx % int32(tx.frameNr)

	// Calculate frame offset and copy data
	frameOffset := int(frameIdx) * tx.frameSize
	copy(tx.ring[frameOffset:], data)

	// Get header and set send request
	hdr := (*unix.TpacketPkgHdr)(unsafe.Pointer(&tx.ring[frameOffset]))
	hdr.Status = unix.TPACKET_WR_TX

	// Trigger transmission via send
	_, err := unix.Send(tx.fd, nil, unix.MSG_DONTWAIT)
	if err != nil && err != unix.EAGAIN {
		return fmt.Errorf("send failed: %w", err)
	}

	return nil
}

// WritePackets transmits multiple packets.
func (tx *AFpacketTXRing) WritePackets(packets [][]byte) error {
	for _, pkt := range packets {
		if err := tx.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// Close releases resources.
func (tx *AFpacketTXRing) Close() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.closed {
		return nil
	}
	tx.closed = true

	var errs []error
	if len(tx.ring) > 0 {
		if err := unix.Munmap(tx.ring); err != nil {
			errs = append(errs, err)
		}
	}
	if tx.fd >= 0 {
		if err := unix.Close(tx.fd); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Ensure AFpacketTXRing implements PacketInjector
var _ PacketInjector = (*AFpacketTXRing)(nil)
