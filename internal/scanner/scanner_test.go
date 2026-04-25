package scanner

import (
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("80,443,1000-1002,443")
	if err != nil {
		t.Fatalf("ParsePorts() error = %v", err)
	}
	want := []int{80, 443, 1000, 1001, 1002}
	if len(ports) != len(want) {
		t.Fatalf("len = %d, want %d", len(ports), len(want))
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d] = %d, want %d", i, ports[i], want[i])
		}
	}
}

func TestScanHostTCP(t *testing.T) {
	s := New(ScanConfig{
		Workers:       4,
		Timeout:       300 * time.Millisecond,
		ServiceDetect: true,
	})
	result, err := s.ScanHostTCP("127.0.0.1", []int{1})
	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Ports))
	}
	status := result.Ports[0].Status
	if status != StatusOpen && status != StatusClosed && status != StatusFiltered && status != StatusError {
		t.Fatalf("unexpected status %q", status)
	}
}
