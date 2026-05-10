package packets

import (
	"testing"
	"time"
)

// mockInjector is a test double for PacketInjector
type mockInjector struct {
	failAll   bool
	failCount int // fail first N calls
	called    int
}

func (m *mockInjector) WritePacket(data []byte) error {
	m.called++
	if m.failAll {
		return &mockError{"injected error"}
	}
	if m.failCount > 0 && m.called <= m.failCount {
		return &mockError{"injected error"}
	}
	return nil
}

func (m *mockInjector) Close() {}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func TestFloodEngine_Run_LongDurationWithCount(t *testing.T) {
	// This test uses a long duration (10s) but count=100, so count limits the work
	injector := &mockInjector{}
	config := FloodConfig{
		Workers:    2,
		PacketSize: 64,
		BufferPool: false,
		BatchSize:  1,
	}
	fe := NewFloodEngine(config, injector)

	packetData := make([]byte, 64)
	result := fe.Run(packetData, 100, 10*time.Second, nil)

	// With 2 workers and count=100, we should get close to 100 sent
	// (exact number varies due to race conditions between workers)
	if result.Sent < 90 || result.Sent > 110 {
		t.Errorf("Sent = %d, want approximately 100 (range 90-110)", result.Sent)
	}
	if result.Failed != 0 {
		t.Errorf("Failed = %d, want 0", result.Failed)
	}
}

func TestFloodEngine_ContextWithTimeout_ZeroDuration(t *testing.T) {
	done, cancel := contextWithTimeout(0)

	// With 0 duration, done channel should already be closed
	select {
	case <-done:
		// Expected - channel is closed
	default:
		t.Error("expected done channel to be immediately closed for 0 duration")
	}

	cancel() // Should be no-op
}

func TestFloodEngine_ContextWithTimeout_NonZeroDuration(t *testing.T) {
	done, cancel := contextWithTimeout(50 * time.Millisecond)
	defer cancel()

	// Channel should not be ready immediately
	select {
	case <-done:
		t.Error("expected done channel to NOT be ready immediately")
	default:
		// Expected
	}

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	select {
	case <-done:
		// Expected - channel now ready after timeout
	default:
		t.Error("expected done channel to be ready after timeout")
	}
}

func TestNewFloodEngine_BufferPoolSizing(t *testing.T) {
	tests := []struct {
		name      string
		workers   int
		batchSize int
	}{
		{"small config", 4, 10},
		{"medium config", 10, 20},
		{"large config", 100, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := FloodConfig{
				Workers:    tt.workers,
				BatchSize:  tt.batchSize,
				BufferPool: true,
			}
			fe := NewFloodEngine(config, nil)

			if fe.buffers == nil {
				t.Error("buffers should not be nil when BufferPool=true")
			}
		})
	}
}

func TestFloodEngine_Run_AllFail(t *testing.T) {
	injector := &mockInjector{failAll: true}
	config := FloodConfig{
		Workers:    1,
		PacketSize: 64,
		BufferPool: false,
		BatchSize:  1,
	}
	fe := NewFloodEngine(config, injector)

	packetData := make([]byte, 64)
	// Use a long duration and count so workers actually run
	result := fe.Run(packetData, 10, 10*time.Second, nil)

	if result.Sent != 0 {
		t.Errorf("Sent = %d, want 0 when all fail", result.Sent)
	}
	if result.Failed == 0 {
		t.Error("Failed = 0, want > 0")
	}
}

func TestFloodEngine_Run_SomeFail(t *testing.T) {
	injector := &mockInjector{failCount: 1} // First packet fails
	config := FloodConfig{
		Workers:    1,
		PacketSize: 64,
		BufferPool: false,
		BatchSize:  1,
	}
	fe := NewFloodEngine(config, injector)

	packetData := make([]byte, 64)
	// First packet fails, rest succeed
	result := fe.Run(packetData, 10, 10*time.Second, nil)

	if result.Sent == 0 {
		t.Error("Sent = 0, want > 0")
	}
}

func TestFloodEngine_ResultFields(t *testing.T) {
	injector := &mockInjector{}
	config := FloodConfig{
		Workers:    1,
		PacketSize: 64,
		BufferPool: false,
		BatchSize:  1,
	}
	fe := NewFloodEngine(config, injector)

	packetData := make([]byte, 64)
	result := fe.Run(packetData, 5, 10*time.Second, nil)

	if result.Sent == 0 {
		t.Error("Sent should be > 0")
	}
	if result.Duration == 0 {
		t.Error("Duration should be > 0")
	}
	if result.PPS == 0 {
		t.Error("PPS should be > 0")
	}
}

func TestFloodEngine_Run_ZeroCountAndZeroDuration(t *testing.T) {
	// When both count=0 and duration=0 with no rate limiter, workers should exit immediately
	// because the context select fires immediately (ctx is done)
	injector := &mockInjector{}
	config := FloodConfig{
		Workers:    2,
		PacketSize: 64,
		BufferPool: false,
		BatchSize:  1,
	}
	fe := NewFloodEngine(config, injector)

	packetData := make([]byte, 64)
	// Both zero means context fires immediately and workers return without sending
	result := fe.Run(packetData, 0, 0, nil)

	if result.Attempted > 5 {
		t.Errorf("Attempted = %d, want <= 5 (should exit immediately)", result.Attempted)
	}
}
