package scanner

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortStatus string

const (
	StatusOpen     PortStatus = "open"
	StatusClosed   PortStatus = "closed"
	StatusFiltered PortStatus = "filtered"
	StatusError    PortStatus = "error"
)

type PortResult struct {
	Port     int        `json:"port"`
	Status   PortStatus `json:"status"`
	Duration string     `json:"duration"`
	Banner   string     `json:"banner,omitempty"`
	Error    string     `json:"error,omitempty"`
}

type HostResult struct {
	Target      string       `json:"target"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
	Reachable   bool         `json:"reachable"`
	OpenCount   int          `json:"open_count"`
	ClosedCount int          `json:"closed_count"`
	Ports       []PortResult `json:"ports"`
}

type ScanConfig struct {
	Workers       int
	Rate          int
	Timeout       time.Duration
	ServiceDetect bool
	BannerTimeout time.Duration
}

type Scanner struct {
	cfg ScanConfig
}

func New(cfg ScanConfig) *Scanner {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 256
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	bannerTimeout := cfg.BannerTimeout
	if bannerTimeout <= 0 {
		bannerTimeout = 500 * time.Millisecond
	}

	return &Scanner{
		cfg: ScanConfig{
			Workers:       workers,
			Rate:          cfg.Rate,
			Timeout:       timeout,
			ServiceDetect: cfg.ServiceDetect,
			BannerTimeout: bannerTimeout,
		},
	}
}

func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	seen := make(map[int]struct{})
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := start; p <= end; p++ {
				seen[p] = struct{}{}
			}
			continue
		}

		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}
		seen[port] = struct{}{}
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports parsed")
	}
	return ports, nil
}

func (s *Scanner) ScanHostTCP(target string, ports []int) (*HostResult, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("empty target")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}

	res := &HostResult{
		Target:    target,
		StartedAt: time.Now(),
	}

	jobs := make(chan int, s.cfg.Workers*2)
	results := make(chan PortResult, s.cfg.Workers*2)

	var limiter <-chan time.Time
	var limiterTicker *time.Ticker
	if s.cfg.Rate > 0 {
		interval := time.Second / time.Duration(s.cfg.Rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		limiterTicker = time.NewTicker(interval)
		limiter = limiterTicker.C
	}

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if limiter != nil {
					<-limiter
				}
				results <- s.scanTCPPort(target, port)
			}
		}()
	}

	go func() {
		for _, port := range ports {
			jobs <- port
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	all := make([]PortResult, 0, len(ports))
	for item := range results {
		all = append(all, item)
	}

	if limiterTicker != nil {
		limiterTicker.Stop()
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Port < all[j].Port
	})

	for _, p := range all {
		switch p.Status {
		case StatusOpen:
			res.OpenCount++
			res.Reachable = true
		case StatusClosed:
			res.ClosedCount++
			res.Reachable = true
		}
	}
	res.CompletedAt = time.Now()
	res.Ports = all

	return res, nil
}

func (s *Scanner) scanTCPPort(target string, port int) PortResult {
	start := time.Now()
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, s.cfg.Timeout)
	if err == nil {
		defer conn.Close()
		item := PortResult{
			Port:     port,
			Status:   StatusOpen,
			Duration: time.Since(start).String(),
		}
		if s.cfg.ServiceDetect {
			item.Banner = detectServiceBanner(conn, port, s.cfg.BannerTimeout)
		}
		return item
	}

	status := StatusError
	switch {
	case isConnRefused(err):
		status = StatusClosed
	case isTimeout(err):
		status = StatusFiltered
	}

	return PortResult{
		Port:     port,
		Status:   status,
		Duration: time.Since(start).String(),
		Error:    err.Error(),
	}
}

func detectServiceBanner(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	switch port {
	case 80, 8080, 8000, 8888:
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.ReplaceAll(banner, "\r", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	return strings.TrimSpace(banner)
}

func isConnRefused(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused")
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timeout")
}
