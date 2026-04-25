package main

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/snortx/internal/scanner"
)

var (
	scanPortsSpec      string
	scanTopPorts       int
	scanWorkers        int
	scanRate           int
	scanTimeout        time.Duration
	scanServiceDetect  bool
	scanJSON           bool
	scanMaxCIDRTargets int
)

var scanCmd = &cobra.Command{
	Use:   "scan <target|cidr|host1,host2>",
	Short: "Scan TCP ports (nmap/masscan style)",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanPortsSpec, "ports", "p", "22,80,443", "Ports/ranges, e.g. 80,443,1-1024")
	scanCmd.Flags().IntVar(&scanTopPorts, "top-ports", 0, "Use built-in common top ports (overrides --ports)")
	scanCmd.Flags().IntVarP(&scanWorkers, "workers", "w", 512, "Parallel worker count")
	scanCmd.Flags().IntVar(&scanRate, "rate", 0, "Probe rate (packets per second, 0=unlimited)")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 1200*time.Millisecond, "Per-port timeout")
	scanCmd.Flags().BoolVar(&scanServiceDetect, "service-detect", false, "Try to read service banner on open ports")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Output scan result as JSON")
	scanCmd.Flags().IntVar(&scanMaxCIDRTargets, "max-hosts", 4096, "Maximum hosts expanded from CIDR target")
}

func runScan(cmd *cobra.Command, args []string) error {
	targetSpec := strings.TrimSpace(args[0])
	targets, err := expandTargets(targetSpec, scanMaxCIDRTargets)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets to scan")
	}

	var ports []int
	if scanTopPorts > 0 {
		ports = topPorts(scanTopPorts)
	} else {
		ports, err = scanner.ParsePorts(scanPortsSpec)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 {
		return fmt.Errorf("no ports to scan")
	}

	s := scanner.New(scanner.ScanConfig{
		Workers:       scanWorkers,
		Rate:          scanRate,
		Timeout:       scanTimeout,
		ServiceDetect: scanServiceDetect,
	})

	results := make([]*scanner.HostResult, 0, len(targets))
	for _, target := range targets {
		res, err := s.ScanHostTCP(target, ports)
		if err != nil {
			return err
		}
		results = append(results, res)
	}

	if scanJSON {
		out, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("Scanned %d target(s), %d port(s) each\n", len(targets), len(ports))
	for _, host := range results {
		fmt.Printf("\nTarget: %s (reachable=%v)\n", host.Target, host.Reachable)
		fmt.Printf("Open: %d, Closed: %d, Duration: %s\n", host.OpenCount, host.ClosedCount, host.CompletedAt.Sub(host.StartedAt))
		for _, p := range host.Ports {
			if p.Status != scanner.StatusOpen {
				continue
			}
			if p.Banner != "" {
				fmt.Printf("  %-5d %-8s %s\n", p.Port, p.Status, p.Banner)
			} else {
				fmt.Printf("  %-5d %-8s\n", p.Port, p.Status)
			}
		}
	}
	return nil
}

func expandTargets(spec string, maxCIDRHosts int) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("empty target")
	}

	targets := make([]string, 0)
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if strings.Contains(item, "/") {
			cidrTargets, err := expandCIDR(item, maxCIDRHosts)
			if err != nil {
				return nil, err
			}
			targets = append(targets, cidrTargets...)
			continue
		}
		targets = append(targets, item)
	}

	targets = uniqueStrings(targets)
	return targets, nil
}

func expandCIDR(cidr string, maxHosts int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %s: %w", cidr, err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only ipv4 cidr is supported: %s", cidr)
	}

	maskSize, bits := ipnet.Mask.Size()
	total := 1 << (bits - maskSize)
	if total > maxHosts {
		return nil, fmt.Errorf("cidr %s expands to %d hosts, exceeds max %d", cidr, total, maxHosts)
	}

	base := ipToUint32(ip)
	targets := make([]string, 0, total)
	for i := 0; i < total; i++ {
		cur := uint32ToIP(base + uint32(i))
		if shouldSkipBoundaryHost(maskSize, total, i) {
			continue
		}
		targets = append(targets, cur.String())
	}
	return targets, nil
}

func shouldSkipBoundaryHost(maskSize, total, idx int) bool {
	if maskSize >= 31 {
		return false
	}
	return idx == 0 || idx == total-1
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	slices.Sort(in)
	out := make([]string, 0, len(in))
	last := ""
	for i, item := range in {
		if i == 0 || item != last {
			out = append(out, item)
			last = item
		}
	}
	return out
}

func topPorts(n int) []int {
	common := []int{
		80, 443, 22, 53, 25, 110, 143, 445, 139, 21,
		3306, 3389, 5900, 8080, 8443, 993, 995, 1723, 111, 135,
		587, 465, 1025, 1521, 5432, 6379, 27017, 9200, 11211, 5000,
	}
	if n <= 0 {
		return nil
	}
	if n > len(common) {
		n = len(common)
	}
	ports := make([]int, n)
	copy(ports, common[:n])
	return ports
}
