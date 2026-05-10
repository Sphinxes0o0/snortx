package packets

import (
	"sync"
	"testing"
)

func TestBufferPool_GetPut(t *testing.T) {
	bp := NewBufferPool(1024, 10)

	// Test Get returns buffer with correct capacity
	buf := bp.Get()
	if cap(buf) != 1024 {
		t.Errorf("Get() cap = %d, want 1024", cap(buf))
	}
	if len(buf) != 0 {
		t.Errorf("Get() len = %d, want 0", len(buf))
	}

	// Test Put returns buffer to pool
	bp.Put(buf)

	// Test Size returns correct size
	if bp.Size() != 1024 {
		t.Errorf("Size() = %d, want 1024", bp.Size())
	}
}

func TestBufferPool_GetPutCycle(t *testing.T) {
	// Test multiple cycles of Get/Put
	bp := NewBufferPool(512, 5)

	for i := 0; i < 10; i++ {
		buf := bp.Get()
		if cap(buf) != 512 {
			t.Errorf("cycle %d: Get() cap = %d, want 512", i, cap(buf))
		}

		// Write some data
		buf = append(buf, make([]byte, 100)...)
		if len(buf) != 100 {
			t.Errorf("cycle %d: appended buf len = %d, want 100", i, len(buf))
		}

		// Put resets length but keeps capacity
		bp.Put(buf)
	}
}

func TestBufferPool_WrongSizePut(t *testing.T) {
	bp := NewBufferPool(1024, 5)

	// Put buffer with wrong capacity should be ignored
	wrongBuf := make([]byte, 2048)
	bp.Put(wrongBuf) // Should not panic, just ignored

	// Correct buffer should work
	correctBuf := make([]byte, 1024)
	bp.Put(correctBuf) // Should be accepted

	// Getting should return a buffer of correct size
	got := bp.Get()
	if cap(got) != 1024 {
		t.Errorf("Get() after wrong put cap = %d, want 1024", cap(got))
	}
}

func TestBufferPool_Concurrent(t *testing.T) {
	bp := NewBufferPool(256, 20)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := bp.Get()
			// Simulate some work
			_ = append(buf, make([]byte, 50)...)
			bp.Put(buf)
		}()
	}
	wg.Wait()
}

func TestPacketBufferPool_GetPut(t *testing.T) {
	pbp := NewPacketBufferPool(2048)

	// Test Get returns PacketBuffer with correct data capacity
	pb := pbp.Get()
	if cap(pb.Data) != 2048 {
		t.Errorf("Get() Data cap = %d, want 2048", cap(pb.Data))
	}
	if pb.Length != 0 {
		t.Errorf("Get() Length = %d, want 0", pb.Length)
	}

	// Test Put returns PacketBuffer to pool
	pb.Length = 100
	pbp.Put(pb)

	// Test another Get returns buffer (possibly same one from pool)
	pb2 := pbp.Get()
	if pb2.Length != 0 {
		t.Errorf("second Get() Length = %d, want 0 (should be reset)", pb2.Length)
	}
}

func TestPacketBufferPool_Concurrent(t *testing.T) {
	pbp := NewPacketBufferPool(1024)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pb := pbp.Get()
			pb.Length = 50
			pbp.Put(pb)
		}()
	}
	wg.Wait()
}

func TestBufferPool_PreAllocation(t *testing.T) {
	// Test that pool pre-allocates the correct number of buffers
	poolSize := 100
	bp := NewBufferPool(512, poolSize)

	// Get all pre-allocated buffers
	bufs := make([][]byte, poolSize)
	for i := 0; i < poolSize; i++ {
		bufs[i] = bp.Get()
		if cap(bufs[i]) != 512 {
			t.Errorf("pre-allocated buffer %d cap = %d, want 512", i, cap(bufs[i]))
		}
	}

	// Return all buffers
	for _, buf := range bufs {
		bp.Put(buf)
	}

	// Get again should still work
	buf := bp.Get()
	if cap(buf) != 512 {
		t.Errorf("Get after return cap = %d, want 512", cap(buf))
	}
}

func TestBufferPool_ZeroPoolSize(t *testing.T) {
	// Zero pool size should still work, just no pre-allocation
	bp := NewBufferPool(256, 0)

	buf := bp.Get()
	if cap(buf) != 256 {
		t.Errorf("Get() cap = %d, want 256", cap(buf))
	}

	bp.Put(buf)
}

func TestPacketBufferPool_ZeroSize(t *testing.T) {
	// Zero size pool should still work
	pbp := NewPacketBufferPool(0)

	pb := pbp.Get()
	if cap(pb.Data) != 0 {
		t.Errorf("Get() Data cap = %d, want 0", cap(pb.Data))
	}
	if pb.Length != 0 {
		t.Errorf("Get() Length = %d, want 0", pb.Length)
	}
}
