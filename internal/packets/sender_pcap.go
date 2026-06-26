//go:build cgo

package packets

import (
	"fmt"
	"sync/atomic"

	"github.com/google/gopacket/pcap"
)

// newPcapHandle opens a live pcap handle for packet injection.
func newPcapHandle(iface string) (packetInjector, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}
	return handle, nil
}

// MultiSender manages multiple pcap handles, one per worker.
// This may reduce handle contention on some platforms.
type MultiSender struct {
	handles []*pcap.Handle
	count   int
}

// NewMultiSender creates a sender with multiple pcap handles.
func NewMultiSender(iface string, handleCount int) (*MultiSender, error) {
	if handleCount <= 0 {
		handleCount = 1
	}
	handles := make([]*pcap.Handle, handleCount)
	for i := 0; i < handleCount; i++ {
		h, err := pcap.OpenLive(iface, 65536, true, -1)
		if err != nil {
			// Close already opened handles
			for j := 0; j < i; j++ {
				handles[j].Close()
			}
			return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
		}
		handles[i] = h
	}
	return &MultiSender{handles: handles, count: handleCount}, nil
}

// GetHandle returns the pcap handle for the given worker ID (round-robin).
func (ms *MultiSender) GetHandle(workerID int) *pcap.Handle {
	return ms.handles[workerID%ms.count]
}

// Close closes all pcap handles.
func (ms *MultiSender) Close() {
	for _, h := range ms.handles {
		h.Close()
	}
}

// WriteTo writes a packet using the specified handle.
func (ms *MultiSender) WriteTo(workerID int, data []byte) error {
	return ms.GetHandle(workerID).WritePacketData(data)
}

// MultiInjector distributes packets across multiple pcap handles using round-robin.
// This allows each worker goroutine to use a dedicated handle.
type MultiInjector struct {
	ms          *MultiSender
	handleCount int
	nextHandle  int32 // atomic: next handle to use
}

// Ensure *MultiInjector implements PacketInjector
var _ PacketInjector = (*MultiInjector)(nil)

// NewMultiInjector creates a packet injector that distributes across multiple handles.
func NewMultiInjector(ms *MultiSender) *MultiInjector {
	return &MultiInjector{
		ms:          ms,
		handleCount: ms.count,
		nextHandle:  0,
	}
}

// WritePacket writes to a pcap handle, rotating handles for each call.
func (mi *MultiInjector) WritePacket(data []byte) error {
	handleIdx := atomic.AddInt32(&mi.nextHandle, 1) - 1
	return mi.ms.WriteTo(int(handleIdx), data)
}

// Close closes all underlying handles.
func (mi *MultiInjector) Close() {
	mi.ms.Close()
}
