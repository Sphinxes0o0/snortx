package packets

import (
	"sync"
	"sync/atomic"
	"time"
)

// FloodResult holds the result of a flood operation.
type FloodResult struct {
	Sent      int64
	Failed    int64
	Attempted int64
	Duration  time.Duration
	PPS       float64
}

// FloodConfig holds configuration for flood operations.
type FloodConfig struct {
	Workers    int
	PacketSize int
	BufferPool bool
	BatchSize  int // Number of packets to batch before sending
}

// FloodEngine implements a high-performance flood engine.
type FloodEngine struct {
	config  FloodConfig
	sender  PacketInjector
	buffers *BufferPool
}

// NewFloodEngine creates a new flood engine.
func NewFloodEngine(config FloodConfig, sender PacketInjector) *FloodEngine {
	var buffers *BufferPool
	if config.BufferPool {
		// Pre-allocate pool size = workers * batch size * 2
		poolSize := config.Workers * config.BatchSize * 2
		if poolSize < 256 {
			poolSize = 256
		}
		buffers = NewBufferPool(2048, poolSize) // Standard MTU
	}
	return &FloodEngine{
		config:  config,
		sender:  sender,
		buffers: buffers,
	}
}

// Run executes the flood.
// Returns the flood result.
func (fe *FloodEngine) Run(packetData []byte, count int64, duration time.Duration, rateLimiter <-chan struct{}) FloodResult {
	var sent, failed, attempted int64
	start := time.Now()

	ctx, cancel := contextWithTimeout(duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < fe.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// Check ctx (timeout) first
				select {
				case <-ctx:
					return
				default:
					// ctx not ready, continue
				}

				// Wait for rate limiter if provided
				if rateLimiter != nil {
					select {
					case <-ctx:
						return
					case <-rateLimiter:
						// proceed with work
					}
				}

				nextAttempt := atomic.AddInt64(&attempted, 1)
				if count > 0 && nextAttempt > count {
					return
				}

				if err := fe.sender.WritePacket(packetData); err != nil {
					atomic.AddInt64(&failed, 1)
				} else {
					atomic.AddInt64(&sent, 1)
				}
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(start)
	totalSent := atomic.LoadInt64(&sent)
	return FloodResult{
		Sent:      totalSent,
		Failed:    atomic.LoadInt64(&failed),
		Attempted: atomic.LoadInt64(&attempted),
		Duration:  elapsed,
		PPS:      float64(totalSent) / elapsed.Seconds(),
	}
}

// contextWithTimeout creates a done channel that fires after duration.
func contextWithTimeout(duration time.Duration) (<-chan time.Time, func()) {
	if duration == 0 {
		done := make(chan time.Time)
		close(done)
		return done, func() {}
	}

	timer := time.NewTimer(duration)
	return timer.C, func() {
		timer.Stop()
	}
}
