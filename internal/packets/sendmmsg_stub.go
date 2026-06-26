package packets

import (
	"fmt"
)

// SendMmsgInjector is a stub for non-Linux platforms.
type SendMmsgInjector struct{}

// NewSendMmsgInjector returns an error on non-Linux platforms.
func NewSendMmsgInjector(dstIP string, dstPort int) (*SendMmsgInjector, error) {
	return nil, fmt.Errorf("sendmmsg is only available on Linux")
}

// WritePacket returns an error on non-Linux platforms.
func (si *SendMmsgInjector) WritePacket(data []byte) error {
	return fmt.Errorf("sendmmsg is only available on Linux")
}

// WritePackets returns an error on non-Linux platforms.
func (si *SendMmsgInjector) WritePackets(packets [][]byte) error {
	return fmt.Errorf("sendmmsg is only available on Linux")
}

// Close is a no-op on non-Linux platforms.
func (si *SendMmsgInjector) Close() {
}

// MultiSendMmsgInjector is a stub for non-Linux platforms.
type MultiSendMmsgInjector struct{}

// NewMultiSendMmsgInjector returns an error on non-Linux platforms.
func NewMultiSendMmsgInjector(dstIP string, dstPort int, numSockets int) (*MultiSendMmsgInjector, error) {
	return nil, fmt.Errorf("sendmmsg is only available on Linux")
}

// WritePacket returns an error on non-Linux platforms.
func (mi *MultiSendMmsgInjector) WritePacket(data []byte) error {
	return fmt.Errorf("sendmmsg is only available on Linux")
}

// WritePackets returns an error on non-Linux platforms.
func (mi *MultiSendMmsgInjector) WritePackets(packets [][]byte) error {
	return fmt.Errorf("sendmmsg is only available on Linux")
}

// Close is a no-op on non-Linux platforms.
func (mi *MultiSendMmsgInjector) Close() {
}

// Ensure stubs implement PacketInjector
var _ PacketInjector = (*SendMmsgInjector)(nil)
var _ PacketInjector = (*MultiSendMmsgInjector)(nil)

// AFpacketInjector is a stub for non-Linux platforms.
type AFpacketInjector struct{}

// NewAFpacketInjector returns an error on non-Linux platforms.
func NewAFpacketInjector(config AFpacketConfig) (*AFpacketInjector, error) {
	return nil, fmt.Errorf("afpacket is only available on Linux")
}

// WritePacket returns an error on non-Linux platforms.
func (ai *AFpacketInjector) WritePacket(data []byte) error {
	return fmt.Errorf("afpacket is only available on Linux")
}

// WritePackets returns an error on non-Linux platforms.
func (ai *AFpacketInjector) WritePackets(packets [][]byte) error {
	return fmt.Errorf("afpacket is only available on Linux")
}

// Close is a no-op on non-Linux platforms.
func (ai *AFpacketInjector) Close() {}

// AFpacketConfig is defined in afpacket_linux.go
type AFpacketConfig struct {
	Interface   string
	BlockSize   int
	FrameSize   int
	BlockCount  int
	PacketCount int
}

// DefaultAFpacketConfig returns defaults on non-Linux.
func DefaultAFpacketConfig(iface string) AFpacketConfig {
	return AFpacketConfig{Interface: iface}
}

// MultiAFpacketInjector is a stub for non-Linux platforms.
type MultiAFpacketInjector struct{}

// NewMultiAFpacketInjector returns an error on non-Linux platforms.
func NewMultiAFpacketInjector(config AFpacketConfig, numSockets int) (*MultiAFpacketInjector, error) {
	return nil, fmt.Errorf("afpacket is only available on Linux")
}

// WritePacket returns an error on non-Linux platforms.
func (mi *MultiAFpacketInjector) WritePacket(data []byte) error {
	return fmt.Errorf("afpacket is only available on Linux")
}

// WritePackets returns an error on non-Linux platforms.
func (mi *MultiAFpacketInjector) WritePackets(packets [][]byte) error {
	return fmt.Errorf("afpacket is only available on Linux")
}

// Close is a no-op on non-Linux platforms.
func (mi *MultiAFpacketInjector) Close() {}

// Ensure stubs implement PacketInjector
var _ PacketInjector = (*AFpacketInjector)(nil)
var _ PacketInjector = (*MultiAFpacketInjector)(nil)

// AFpacketTXRing is a stub for non-Linux platforms.
type AFpacketTXRing struct{}

// NewAFpacketTXRing returns an error on non-Linux platforms.
func NewAFpacketTXRing(iface string, frameSize, blockSize, blockNr int) (*AFpacketTXRing, error) {
	return nil, fmt.Errorf("afpacket TX ring is only available on Linux")
}

// WritePacket returns an error on non-Linux platforms.
func (tx *AFpacketTXRing) WritePacket(data []byte) error {
	return fmt.Errorf("afpacket TX ring is only available on Linux")
}

// WritePackets returns an error on non-Linux platforms.
func (tx *AFpacketTXRing) WritePackets(packets [][]byte) error {
	return fmt.Errorf("afpacket TX ring is only available on Linux")
}

// Close is a no-op on non-Linux platforms.
func (tx *AFpacketTXRing) Close() {}

// Ensure stub implements PacketInjector
var _ PacketInjector = (*AFpacketTXRing)(nil)
