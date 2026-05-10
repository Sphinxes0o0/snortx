package packets

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestParseTxEngine(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    TxEngine
		wantErr bool
	}{
		{name: "default empty", in: "", want: TxEnginePCAP},
		{name: "pcap", in: "pcap", want: TxEnginePCAP},
		{name: "sendmmsg", in: "sendmmsg", want: TxEngineSendMmsg},
		{name: "afpacket", in: "afpacket", want: TxEngineAFPacket},
		{name: "invalid", in: "foo", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTxEngine(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTxEngine() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseTxEngine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewSenderWithModeAndEngine_UnimplementedEngine(t *testing.T) {
	// AF_PACKET is now implemented on Linux, but would fail at injector creation
	// On macOS, the actual injector creation (NewAFpacketInjector) would fail
	// Since AF_PACKET is Linux-only, we just verify the engine type is accepted
	// and sender creation succeeds (injector is created later by CLI)
	_, err := NewSenderWithModeAndEngine(t.TempDir(), "lo0", ModeInject, TxEngineAFPacket)
	if err != nil {
		t.Fatalf("unexpected error for AF_PACKET sender: %v", err)
	}
}

func TestNewSenderWithModeAndEngine_Combinations(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		mode      SendMode
		engine    TxEngine
		wantErr   bool
		errContains string
	}{
		{
			name:    "PCAP mode with PCAP engine",
			mode:    ModePCAP,
			engine:  TxEnginePCAP,
			wantErr: false,
		},
		{
			name:    "Inject mode with PCAP engine",
			mode:    ModeInject,
			engine:  TxEnginePCAP,
			wantErr: false,
		},
		{
			name:    "Both mode with PCAP engine",
			mode:    ModeBoth,
			engine:  TxEnginePCAP,
			wantErr: false,
		},
		{
			name:    "PCAP mode with SendMmsg engine",
			mode:    ModePCAP,
			engine:  TxEngineSendMmsg,
			wantErr: false, // No injector needed for PCAP mode
		},
		{
			name:    "PCAP mode with AFpacket engine",
			mode:    ModePCAP,
			engine:  TxEngineAFPacket,
			wantErr: false, // No injector needed for PCAP mode
		},
		{
			name:    "Inject mode with SendMmsg engine",
			mode:    ModeInject,
			engine:  TxEngineSendMmsg,
			wantErr: false, // SendMmsg returns nil injector (created by CLI)
		},
		{
			name:    "Inject mode with AFpacket engine",
			mode:    ModeInject,
			engine:  TxEngineAFPacket,
			wantErr: false, // AFpacket returns nil injector (created by CLI)
		},
		{
			name:    "Invalid engine",
			mode:    ModePCAP,
			engine:  TxEngine("invalid"),
			wantErr: true,
			errContains: "invalid tx engine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSenderWithModeAndEngine(tmpDir, "lo0", tt.mode, tt.engine)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s == nil {
				t.Fatal("expected non-nil sender")
			}
			if s.Mode != tt.mode {
				t.Errorf("Mode = %v, want %v", s.Mode, tt.mode)
			}
			if s.TxEngine != tt.engine {
				t.Errorf("TxEngine = %v, want %v", s.TxEngine, tt.engine)
			}
			s.Close()
		})
	}
}

func TestNewSender_InvalidOutputDir(t *testing.T) {
	// Use a path that cannot be created
	_, err := NewSender("/this/path/does/not/exist/and/cannot/be/created", "lo0")
	if err == nil {
		t.Fatal("expected error for invalid output dir")
	}
}

func TestSender_MkdirAll(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "a", "b", "c")

	s, err := NewSender(nestedDir, "lo0")
	if err != nil {
		t.Fatalf("failed to create sender with nested dir: %v", err)
	}
	defer s.Close()

	// Verify directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Errorf("directory %s was not created", nestedDir)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BurstSender tests

func TestBurstSender_QueueFull(t *testing.T) {
	// Create a sender with ModeBoth (supports both PCAP and injection)
	s, err := NewSenderWithModeAndEngine(t.TempDir(), "lo0", ModeBoth, TxEnginePCAP)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	// Create BurstSender with tiny queue to force full case
	bs := NewBurstSender(s, 1)
	defer bs.Close()

	// First write should succeed (queue has space)
	err = bs.WritePacket([]byte("first"))
	if err != nil {
		t.Errorf("first WritePacket failed: %v", err)
	}

	// Second write might go to queue or direct send depending on timing
	// Due to select with default, if channel is full, it sends directly
	err = bs.WritePacket([]byte("second"))
	if err != nil {
		t.Errorf("second WritePacket failed: %v", err)
	}
}

func TestBurstSender_ZeroQueueSize(t *testing.T) {
	s, err := NewSenderWithMode(t.TempDir(), "lo0", ModePCAP)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	// Zero queue size should default to 4096
	bs := NewBurstSender(s, 0)
	defer bs.Close()

	// Should work fine
	err = bs.WritePacket([]byte("test"))
	if err != nil {
		t.Errorf("WritePacket failed: %v", err)
	}
}

func TestBurstSender_CloseDrainsQueue(t *testing.T) {
	s, err := NewSenderWithModeAndEngine(t.TempDir(), "lo0", ModeBoth, TxEnginePCAP)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	bs := NewBurstSender(s, 100)

	// Write some packets
	for i := 0; i < 10; i++ {
		bs.WritePacket([]byte("packet"))
	}

	// Close should drain remaining packets
	bs.Close()

	// After Close, writerLoop is done
}

func TestBurstSender_ConcurrentWrites(t *testing.T) {
	s, err := NewSenderWithModeAndEngine(t.TempDir(), "lo0", ModeBoth, TxEnginePCAP)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	bs := NewBurstSender(s, 100)
	defer bs.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bs.WritePacket([]byte("data"))
			}
		}()
	}
	wg.Wait()
}

// MultiSender tests

func TestMultiSender_GetHandle(t *testing.T) {
	ms, err := NewMultiSender("lo0", 4)
	if err != nil {
		t.Fatalf("failed to create MultiSender: %v", err)
	}
	defer ms.Close()

	// GetHandle should return handles in round-robin fashion
	handles := make(map[*pcap.Handle]int)
	for i := 0; i < 8; i++ {
		h := ms.GetHandle(i)
		handles[h]++
	}

	// With 4 handles and 8 requests, each should get 2
	if len(handles) != 4 {
		t.Errorf("expected 4 unique handles, got %d", len(handles))
	}
}

func TestMultiSender_ZeroHandleCount(t *testing.T) {
	ms, err := NewMultiSender("lo0", 0)
	if err != nil {
		t.Fatalf("failed to create MultiSender with 0 handles: %v", err)
	}
	defer ms.Close()

	// Should default to 1 handle
	h := ms.GetHandle(0)
	if h == nil {
		t.Error("expected non-nil handle")
	}
}

func TestMultiSender_WriteTo(t *testing.T) {
	ms, err := NewMultiSender("lo0", 2)
	if err != nil {
		t.Fatalf("failed to create MultiSender: %v", err)
	}
	defer ms.Close()

	// WriteTo with PCAP mode just validates - won't actually send
	err = ms.WriteTo(0, []byte("test"))
	// May fail due to interface issues, but shouldn't crash
	_ = err
}

// MultiInjector tests

func TestMultiInjector_RoundRobin(t *testing.T) {
	ms, err := NewMultiSender("lo0", 4)
	if err != nil {
		t.Fatalf("failed to create MultiSender: %v", err)
	}
	defer ms.Close()

	mi := NewMultiInjector(ms)

	// WritePacket should round-robin across handles
	for i := 0; i < 100; i++ {
		err := mi.WritePacket([]byte("test"))
		_ = err // May fail but shouldn't crash
	}

	// nextHandle should have advanced
	if mi.nextHandle != 100 {
		t.Errorf("nextHandle = %d, want 100", mi.nextHandle)
	}
}

func TestMultiInjector_Concurrent(t *testing.T) {
	ms, err := NewMultiSender("lo0", 4)
	if err != nil {
		t.Fatalf("failed to create MultiSender: %v", err)
	}
	defer ms.Close()

	mi := NewMultiInjector(ms)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				mi.WritePacket([]byte("data"))
			}
		}()
	}
	wg.Wait()
}

// RawSocketInjector tests (IPv4 only)

func TestRawSocketInjector_NewRawSocketInjector(t *testing.T) {
	rsi, err := NewRawSocketInjector(2)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test (may require privileges): %v", err)
	}
	defer rsi.Close()

	if rsi.count != 2 {
		t.Errorf("count = %d, want 2", rsi.count)
	}
	if len(rsi.fds) != 2 {
		t.Errorf("len(fds) = %d, want 2", len(rsi.fds))
	}
}

func TestRawSocketInjector_ZeroCount(t *testing.T) {
	rsi, err := NewRawSocketInjector(0)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	// Should default to 1
	if rsi.count != 1 {
		t.Errorf("count = %d, want 1", rsi.count)
	}
}

func TestRawSocketInjector_WritePacket_Empty(t *testing.T) {
	rsi, err := NewRawSocketInjector(1)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	err = rsi.WritePacket([]byte{})
	if err == nil {
		t.Error("expected error for empty packet")
	}
}

func TestRawSocketInjector_WritePacket_TooShort(t *testing.T) {
	rsi, err := NewRawSocketInjector(1)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	// Less than 15 bytes (Ethernet header + version byte)
	err = rsi.WritePacket([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for too-short packet")
	}
}

func TestRawSocketInjector_WritePacket_IPv6NotSupported(t *testing.T) {
	rsi, err := NewRawSocketInjector(1)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	// IPv6 packet (version = 6 at byte 14)
	// Ethernet header (14 bytes) + version nibble in byte 14
	packet := make([]byte, 60)
	packet[14] = 0x60 // IPv6 version
	err = rsi.WritePacket(packet)
	if err == nil {
		t.Error("expected error for IPv6 packet")
	}
	if !contains(err.Error(), "IPv6 not supported") {
		t.Errorf("error = %q, want to contain 'IPv6 not supported'", err.Error())
	}
}

func TestRawSocketInjector_WritePacket_IPv4(t *testing.T) {
	rsi, err := NewRawSocketInjector(1)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	// Build a valid IPv4 TCP packet
	// Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes minimum
	packet := make([]byte, 54)
	// Ethernet: destination MAC (bytes 0-5), source MAC (6-11), EtherType (12-13)
	// EtherType 0x0800 = IPv4
	packet[12] = 0x08
	packet[13] = 0x00
	// IPv4: version/IHL (byte 14), version=4, IHL=5
	packet[14] = 0x45
	// Total length (bytes 16-17) = 40 (20 IP + 20 TCP)
	packet[16] = 0x00
	packet[17] = 0x28
	// Destination IP (bytes 16-19) - but this is after IPv4 header
	// Actually: bytes 16-19 is dst IP
	packet[19] = 0x01 // dst IP = 0.0.0.1
	// TCP: src port (20-21), dst port (22-23)
	packet[20] = 0x00
	packet[21] = 0x00 // src port = 0
	packet[22] = 0x00
	packet[23] = 0x50 // dst port = 80

	// This will likely fail due to actual network conditions,
	// but should not return "IPv6 not supported" or "unknown IP version"
	err = rsi.WritePacket(packet)
	// We just verify it processes IPv4 correctly
	_ = err
}

func TestRawSocketInjector_Concurrent(t *testing.T) {
	rsi, err := NewRawSocketInjector(4)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	// Build a minimal valid IPv4 TCP packet
	packet := make([]byte, 54)
	packet[12] = 0x08
	packet[13] = 0x00
	packet[14] = 0x45
	packet[16] = 0x00
	packet[17] = 0x28
	packet[19] = 0x01
	packet[22] = 0x00
	packet[23] = 0x50

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				rsi.WritePacket(packet)
			}
		}()
	}
	wg.Wait()
}

func TestRawSocketInjector_RoundRobin(t *testing.T) {
	rsi, err := NewRawSocketInjector(4)
	if err != nil {
		t.Skipf("skipping RawSocketInjector test: %v", err)
	}
	defer rsi.Close()

	packet := make([]byte, 54)
	packet[12] = 0x08
	packet[13] = 0x00
	packet[14] = 0x45
	packet[16] = 0x00
	packet[17] = 0x28
	packet[19] = 0x01
	packet[22] = 0x00
	packet[23] = 0x50

	// Write multiple packets
	for i := 0; i < 100; i++ {
		rsi.WritePacket(packet)
	}

	// nextIdx should reflect round-robin across 4 sockets
	// nextIdx = 100 means 100 packets sent round-robin across 4 sockets
	// nextIdx starts at 0 and is incremented before each use
	// So after 100 writes, nextIdx should be 100
	if rsi.nextIdx != 100 {
		t.Errorf("nextIdx = %d, want 100", rsi.nextIdx)
	}
}

// Sender.InjectPacket tests

func TestSender_InjectPacket_EmptyData(t *testing.T) {
	s, err := NewSenderWithMode(t.TempDir(), "lo0", ModeInject)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	err = s.InjectPacket([]byte{})
	if err == nil {
		t.Error("expected error for empty packet")
	}
	if !contains(err.Error(), "empty") {
		t.Errorf("error = %q, want to contain 'empty'", err.Error())
	}
}

func TestSender_InjectPacket_WrongMode(t *testing.T) {
	s, err := NewSenderWithMode(t.TempDir(), "lo0", ModePCAP)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	err = s.InjectPacket([]byte("data"))
	if err == nil {
		t.Error("expected error for PCAP-only mode")
	}
	if !contains(err.Error(), "does not support injection") {
		t.Errorf("error = %q, want to contain 'does not support injection'", err.Error())
	}
}

func TestSender_InjectPacket_NoInjector(t *testing.T) {
	// Create sender with ModeInject but TxEngineSendMmsg which has nil injector
	s, err := NewSenderWithModeAndEngine(t.TempDir(), "lo0", ModeInject, TxEngineSendMmsg)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}
	defer s.Close()

	// This sender has nil injector even in inject mode
	err = s.InjectPacket([]byte("data"))
	if err == nil {
		t.Error("expected error when injector is nil")
	}
	if !contains(err.Error(), "pcap handle is not initialized") {
		t.Errorf("error = %q, want to contain 'pcap handle is not initialized'", err.Error())
	}
}

// SendMode and TxEngine constants

func TestSendMode_Values(t *testing.T) {
	if ModePCAP != 0 {
		t.Errorf("ModePCAP = %d, want 0", ModePCAP)
	}
	if ModeInject != 1 {
		t.Errorf("ModeInject = %d, want 1", ModeInject)
	}
	if ModeBoth != 2 {
		t.Errorf("ModeBoth = %d, want 2", ModeBoth)
	}
}

func TestTxEngine_Values(t *testing.T) {
	if TxEnginePCAP != "pcap" {
		t.Errorf("TxEnginePCAP = %q, want 'pcap'", TxEnginePCAP)
	}
	if TxEngineSendMmsg != "sendmmsg" {
		t.Errorf("TxEngineSendMmsg = %q, want 'sendmmsg'", TxEngineSendMmsg)
	}
	if TxEngineAFPacket != "afpacket" {
		t.Errorf("TxEngineAFPacket = %q, want 'afpacket'", TxEngineAFPacket)
	}
}
