//go:build !cgo

package packets

import "fmt"

// newPcapHandle stub — pcap requires cgo.
func newPcapHandle(iface string) (packetInjector, error) {
	return nil, fmt.Errorf("pcap not available: build without cgo")
}

// MultiSender stub — pcap requires cgo.
type MultiSender struct{}

// NewMultiSender always returns an error when built without cgo.
func NewMultiSender(iface string, handleCount int) (*MultiSender, error) {
	return nil, fmt.Errorf("pcap not available: build without cgo")
}

func (ms *MultiSender) Close() {}

func (ms *MultiSender) WriteTo(workerID int, data []byte) error {
	return fmt.Errorf("pcap not available: build without cgo")
}

// MultiInjector stub — pcap requires cgo.
type MultiInjector struct{}

// NewMultiInjector creates a stub injector (never used because NewMultiSender fails).
func NewMultiInjector(ms *MultiSender) *MultiInjector {
	return &MultiInjector{}
}

func (mi *MultiInjector) WritePacket(data []byte) error {
	return fmt.Errorf("pcap not available: build without cgo")
}

func (mi *MultiInjector) Close() {}
