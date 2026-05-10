package packets

import (
	"sync"
)

// BufferPool manages pre-allocated byte slices for packet data.
// This reduces allocations in high-performance flooding scenarios.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with pre-allocated buffers.
// Each buffer has the specified size.
func NewBufferPool(bufferSize int, poolSize int) *BufferPool {
	bp := &BufferPool{
		size: bufferSize,
	}
	// Pre-populate the pool
	bp.pool.New = func() interface{} {
		return make([]byte, bufferSize)
	}
	// Pre-allocate poolSize buffers
	for i := 0; i < poolSize; i++ {
		bp.Put(make([]byte, bufferSize))
	}
	return bp
}

// Get retrieves a buffer from the pool.
// The returned buffer has length 0 but full capacity.
func (bp *BufferPool) Get() []byte {
	buf := bp.pool.Get().([]byte)
	return buf[:0] // Reset length to 0
}

// Put returns a buffer to the pool.
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) != bp.size {
		// Don't return incorrectly-sized buffers
		return
	}
	bp.pool.Put(buf)
}

// Size returns the buffer size.
func (bp *BufferPool) Size() int {
	return bp.size
}

// PacketBuffer is a pre-allocated packet buffer with associated metadata.
type PacketBuffer struct {
	Data   []byte
	Length int
}

// PacketBufferPool manages pre-allocated packet buffers.
type PacketBufferPool struct {
	pool sync.Pool
}

// NewPacketBufferPool creates a new pool for PacketBuffer objects.
func NewPacketBufferPool(size int) *PacketBufferPool {
	pbp := &PacketBufferPool{}
	pbp.pool.New = func() interface{} {
		return &PacketBuffer{
			Data: make([]byte, size),
		}
	}
	return pbp
}

// Get retrieves a PacketBuffer from the pool.
func (pbp *PacketBufferPool) Get() *PacketBuffer {
	pb := pbp.pool.Get().(*PacketBuffer)
	pb.Length = 0
	return pb
}

// Put returns a PacketBuffer to the pool.
func (pbp *PacketBufferPool) Put(pb *PacketBuffer) {
	pbp.pool.Put(pb)
}
