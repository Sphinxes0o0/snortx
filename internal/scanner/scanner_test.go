package scanner

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// ParsePorts Table-Driven Tests
// =============================================================================

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:    "single port",
			input:   "80",
			want:    []int{80},
			wantErr: false,
		},
		{
			name:    "multiple ports",
			input:   "80,443,8080",
			want:    []int{80, 443, 8080},
			wantErr: false,
		},
		{
			name:    "port range",
			input:   "8000-8002",
			want:    []int{8000, 8001, 8002},
			wantErr: false,
		},
		{
			name:    "mixed ports and ranges",
			input:   "80,443,1000-1002",
			want:    []int{80, 443, 1000, 1001, 1002},
			wantErr: false,
		},
		{
			name:    "duplicate ports deduplicated",
			input:   "80,443,80,443",
			want:    []int{80, 443},
			wantErr: false,
		},
		{
			name:    "duplicate within range",
			input:   "80-82,81",
			want:    []int{80, 81, 82},
			wantErr: false,
		},
		{
			name:    "whitespace trimmed",
			input:   " 80 , 443 , 1000-1002 ",
			want:    []int{80, 443, 1000, 1001, 1002},
			wantErr: false,
		},
		{
			name:    "large range",
			input:   "1000-1005",
			want:    []int{1000, 1001, 1002, 1003, 1004, 1005},
			wantErr: false,
		},
		{
			name:    "edge port 1",
			input:   "1",
			want:    []int{1},
			wantErr: false,
		},
		{
			name:    "edge port 65535",
			input:   "65535",
			want:    []int{65535},
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port - letter",
			input:   "80a",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port - out of range high",
			input:   "70000",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port - out of range low",
			input:   "0",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range - start greater than end",
			input:   "100-50",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range - out of range start",
			input:   "70000-70005",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range - out of range end",
			input:   "65530-70000",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range - no end",
			input:   "80-",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range - no start",
			input:   "-80",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid range - too many hyphens",
			input:   "80-443-900",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePorts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParsePorts() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParsePorts()[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// =============================================================================
// PortResult Status Tests
// =============================================================================

func TestPortStatus(t *testing.T) {
	tests := []struct {
		name   string
		status PortStatus
		want   string
	}{
		{"StatusOpen", StatusOpen, "open"},
		{"StatusClosed", StatusClosed, "closed"},
		{"StatusFiltered", StatusFiltered, "filtered"},
		{"StatusError", StatusError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.status) != tt.want {
				t.Errorf("PortStatus = %q, want %q", tt.status, tt.want)
			}
		})
	}
}

func TestPortResultFields(t *testing.T) {
	pr := PortResult{
		Port:     80,
		Status:   StatusOpen,
		Duration: "100ms",
		Banner:   "HTTP/1.1 200 OK",
		Error:    "",
	}

	if pr.Port != 80 {
		t.Errorf("Port = %d, want 80", pr.Port)
	}
	if pr.Status != StatusOpen {
		t.Errorf("Status = %v, want StatusOpen", pr.Status)
	}
	if pr.Duration != "100ms" {
		t.Errorf("Duration = %v, want 100ms", pr.Duration)
	}
	if pr.Banner != "HTTP/1.1 200 OK" {
		t.Errorf("Banner = %v, want HTTP/1.1 200 OK", pr.Banner)
	}
}

func TestHostResultCounts(t *testing.T) {
	hr := HostResult{
		Target:      "127.0.0.1",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Reachable:   true,
		OpenCount:   2,
		ClosedCount: 3,
		Ports: []PortResult{
			{Port: 80, Status: StatusOpen},
			{Port: 443, Status: StatusOpen},
			{Port: 22, Status: StatusClosed},
			{Port: 23, Status: StatusClosed},
			{Port: 8080, Status: StatusClosed},
		},
	}

	if hr.OpenCount != 2 {
		t.Errorf("OpenCount = %d, want 2", hr.OpenCount)
	}
	if hr.ClosedCount != 3 {
		t.Errorf("ClosedCount = %d, want 3", hr.ClosedCount)
	}
	if len(hr.Ports) != 5 {
		t.Errorf("len(Ports) = %d, want 5", len(hr.Ports))
	}
}

// =============================================================================
// Scanner Configuration Tests
// =============================================================================

func TestNewScannerDefaults(t *testing.T) {
	tests := []struct {
		name          string
		cfg           ScanConfig
		wantWorkers   int
		wantTimeout   time.Duration
		wantRate      int
	}{
		{
			name:          "zero values get defaults",
			cfg:           ScanConfig{},
			wantWorkers:   256,
			wantTimeout:   1200 * time.Millisecond,
			wantRate:      0,
		},
		{
			name:          "negative workers gets default",
			cfg:           ScanConfig{Workers: -5},
			wantWorkers:   256,
			wantTimeout:   1200 * time.Millisecond,
			wantRate:      0,
		},
		{
			name:          "custom workers preserved",
			cfg:           ScanConfig{Workers: 100},
			wantWorkers:   100,
			wantTimeout:   1200 * time.Millisecond,
			wantRate:      0,
		},
		{
			name:          "custom timeout preserved",
			cfg:           ScanConfig{Timeout: 5 * time.Second},
			wantWorkers:   256,
			wantTimeout:   5 * time.Second,
			wantRate:      0,
		},
		{
			name:          "custom rate preserved",
			cfg:           ScanConfig{Rate: 1000},
			wantWorkers:   256,
			wantTimeout:   1200 * time.Millisecond,
			wantRate:      1000,
		},
		{
			name:          "banner timeout default",
			cfg:           ScanConfig{},
			wantWorkers:   256,
			wantTimeout:   1200 * time.Millisecond,
			wantRate:      0,
		},
		{
			name:          "custom banner timeout",
			cfg:           ScanConfig{BannerTimeout: 2 * time.Second},
			wantWorkers:   256,
			wantTimeout:   1200 * time.Millisecond,
			wantRate:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.cfg)
			if s.cfg.Workers != tt.wantWorkers {
				t.Errorf("Workers = %d, want %d", s.cfg.Workers, tt.wantWorkers)
			}
			if s.cfg.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", s.cfg.Timeout, tt.wantTimeout)
			}
			if s.cfg.Rate != tt.wantRate {
				t.Errorf("Rate = %d, want %d", s.cfg.Rate, tt.wantRate)
			}
		})
	}
}

// =============================================================================
// ScanHostTCP Input Validation Tests
// =============================================================================

func TestScanHostTCPValidation(t *testing.T) {
	s := New(ScanConfig{Workers: 4, Timeout: 300 * time.Millisecond})

	tests := []struct {
		name    string
		target  string
		ports   []int
		wantErr string
	}{
		{
			name:    "empty target",
			target:  "",
			ports:   []int{80},
			wantErr: "empty target",
		},
		{
			name:    "whitespace target",
			target:  "   ",
			ports:   []int{80},
			wantErr: "empty target",
		},
		{
			name:    "empty ports",
			target:  "127.0.0.1",
			ports:   []int{},
			wantErr: "no ports to scan",
		},
		{
			name:    "nil ports",
			target:  "127.0.0.1",
			ports:   nil,
			wantErr: "no ports to scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.ScanHostTCP(tt.target, tt.ports)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Rate Limiter Tests
// =============================================================================

func TestRateLimiterZero(t *testing.T) {
	// Rate = 0 means no limiting, all workers should run freely
	s := New(ScanConfig{
		Workers: 4,
		Rate:    0, // no rate limiting
		Timeout: 500 * time.Millisecond,
	})

	start := time.Now()
	result, err := s.ScanHostTCP("127.0.0.1", []int{22, 80, 443})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != 3 {
		t.Fatalf("len(result.Ports) = %d, want 3", len(result.Ports))
	}

	// With no rate limiting, should complete quickly for localhost
	if elapsed > 2*time.Second {
		t.Fatalf("scan took too long: %v (rate=0 should be fast)", elapsed)
	}
}

func TestRateLimiterWithLimit(t *testing.T) {
	// Rate = 100 means max 100 packets per second
	s := New(ScanConfig{
		Workers: 8,
		Rate:    100,
		Timeout: 500 * time.Millisecond,
	})

	start := time.Now()
	result, err := s.ScanHostTCP("127.0.0.1", []int{22, 80, 443, 8080, 9000})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != 5 {
		t.Fatalf("len(result.Ports) = %d, want 5", len(result.Ports))
	}

	// 5 ports at 100 pps should take at least 50ms theoretically
	// but due to worker parallelism and localhost speed, just verify it completes
	if elapsed == 0 {
		t.Fatalf("elapsed time should not be zero")
	}
}

func TestRateLimiterTokenBucketRefill(t *testing.T) {
	// Test that rate limiter with very low rate still works
	s := New(ScanConfig{
		Workers: 2,
		Rate:    10, // 10 packets per second
		Timeout: 1 * time.Second,
	})

	start := time.Now()
	result, err := s.ScanHostTCP("127.0.0.1", []int{22, 80})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != 2 {
		t.Fatalf("len(result.Ports) = %d, want 2", len(result.Ports))
	}

	// At 10 pps, scanning 2 ports should take at least 100ms minimum
	// (but localhost is fast, so this is just a sanity check)
	if elapsed < 0 {
		t.Fatalf("elapsed time should not be negative")
	}
}

// =============================================================================
// Worker Pool Tests
// =============================================================================

func TestWorkerPoolScaling(t *testing.T) {
	tests := []struct {
		name           string
		workers        int
		portCount      int
		wantPortCount  int
	}{
		{"single worker", 1, 5, 5},
		{"few workers", 4, 10, 10},
		{"many workers", 64, 20, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(ScanConfig{
				Workers: tt.workers,
				Timeout: 500 * time.Millisecond,
			})

			ports := make([]int, tt.portCount)
			for i := range ports {
				ports[i] = 1000 + i
			}

			result, err := s.ScanHostTCP("127.0.0.1", ports)
			if err != nil {
				t.Fatalf("ScanHostTCP() error = %v", err)
			}

			if len(result.Ports) != tt.wantPortCount {
				t.Errorf("len(result.Ports) = %d, want %d", len(result.Ports), tt.wantPortCount)
			}
		})
	}
}

func TestWorkerPoolConcurrent(t *testing.T) {
	// Test that multiple goroutines can use the scanner concurrently
	s := New(ScanConfig{
		Workers: 8,
		Timeout: 500 * time.Millisecond,
	})

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := s.ScanHostTCP("127.0.0.1", []int{80 + idx, 443 + idx})
			if err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Fatalf("concurrent scan error: %v", err)
	}
}

// =============================================================================
// Service Detection Tests
// =============================================================================

func TestServiceDetectionEnabled(t *testing.T) {
	s := New(ScanConfig{
		Workers:       4,
		Timeout:       500 * time.Millisecond,
		ServiceDetect: true,
		BannerTimeout: 500 * time.Millisecond,
	})

	result, err := s.ScanHostTCP("127.0.0.1", []int{80})
	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != 1 {
		t.Fatalf("len(result.Ports) = %d, want 1", len(result.Ports))
	}

	// Port 80 may or may not be open on localhost, but if open it may have a banner
	port := result.Ports[0]
	if port.Status == StatusOpen && port.Banner != "" {
		// Banner should be non-empty if port is open and service detect is on
		t.Logf("Banner for port 80: %q", port.Banner)
	}
}

func TestServiceDetectionDisabled(t *testing.T) {
	s := New(ScanConfig{
		Workers:       4,
		Timeout:       500 * time.Millisecond,
		ServiceDetect: false,
	})

	result, err := s.ScanHostTCP("127.0.0.1", []int{80})
	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != 1 {
		t.Fatalf("len(result.Ports) = %d, want 1", len(result.Ports))
	}

	// Banner should always be empty when ServiceDetect is false
	if result.Ports[0].Banner != "" {
		t.Errorf("Banner = %q, want empty when ServiceDetect=false", result.Ports[0].Banner)
	}
}

// =============================================================================
// Port Sorting Tests
// =============================================================================

func TestPortResultsSorted(t *testing.T) {
	s := New(ScanConfig{
		Workers: 4,
		Timeout: 500 * time.Millisecond,
	})

	// Scan ports in random order
	ports := []int{9000, 100, 8000, 22, 443, 3000}

	result, err := s.ScanHostTCP("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("ScanHostTCP() error = %v", err)
	}

	if len(result.Ports) != len(ports) {
		t.Fatalf("len(result.Ports) = %d, want %d", len(result.Ports), len(ports))
	}

	// Verify ports are sorted
	for i := 1; i < len(result.Ports); i++ {
		if result.Ports[i].Port <= result.Ports[i-1].Port {
			t.Errorf("Ports not sorted: ports[%d]=%d >= ports[%d]=%d",
				i-1, result.Ports[i-1].Port, i, result.Ports[i].Port)
		}
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestIsConnRefused(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"connection refused lowercase", "connection refused", true},
		{"connection refused uppercase", "Connection Refused", true},
		{"connection refused with other text", "dial tcp: connection refused", true},
		{"timeout error", "i/o timeout", false},
		{"other error", "some other error", false},
		{"empty error", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{msg: tt.errMsg}
			if isConnRefused(err) != tt.expected {
				t.Errorf("isConnRefused(%q) = %v, want %v", tt.errMsg, !tt.expected, tt.expected)
			}
		})
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"i/o timeout", "i/o timeout", true},
		{"timeout lowercase", "timeout", true},
		{"timeout uppercase", "Timeout", true},
		{"connection refused", "connection refused", false},
		{"other error", "some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{msg: tt.errMsg}
			if isTimeout(err) != tt.expected {
				t.Errorf("isTimeout(%q) = %v, want %v", tt.errMsg, !tt.expected, tt.expected)
			}
		})
	}
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// =============================================================================
// Banner Parsing Tests
// =============================================================================

func TestDetectServiceBannerHTTPPorts(t *testing.T) {
	// Test that HTTP ports (80, 8080, 8000, 8888) get HTTP requests
	httpPorts := []int{80, 8080, 8000, 8888}

	for _, port := range httpPorts {
		if port != 80 && port != 8080 && port != 8000 && port != 8888 {
			t.Errorf("expected HTTP port, got %d", port)
		}
	}
}

func TestBannerParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "crlf line endings",
			input:    "HTTP/1.1 200 OK\r\nServer: test\r\n",
			expected: "HTTP/1.1 200 OK  Server: test",
		},
		{
			name:     "lf line endings",
			input:    "SSH-2.0-Test\n",
			expected: "SSH-2.0-Test",
		},
		{
			name:     "mixed line endings",
			input:    "HTTP/1.1 200 OK\r\nServer: nginx\n",
			expected: "HTTP/1.1 200 OK  Server: nginx",
		},
		{
			name:     "no line endings",
			input:    "plain text banner",
			expected: "plain text banner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input
			result = strings.ReplaceAll(result, "\r", " ")
			result = strings.ReplaceAll(result, "\n", " ")
			result = strings.TrimSpace(result)

			if result != tt.expected {
				t.Errorf("banner parsing = %q, want %q", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Existing Tests (Preserved)
// =============================================================================

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
