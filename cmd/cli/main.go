package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/snortx/internal/api"
	"github.com/user/snortx/internal/engine"
	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/reports"
	"github.com/user/snortx/internal/rules"
	"github.com/user/snortx/pkg/config"
)

var (
	outputDir    string
	interface_   string
	workers      int
	batchWorkers int
	reportFmt    string
	listenAddr   string
	sendMode     string
	authToken    string
	corsOrigins  string
	rateLimit    int
	configFile   string
	parseJSON    bool
)

const version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "snortx",
	Short: "Snort rule testing tool",
	Long:  `snortx parses Snort rules, generates matching network packets,
records them to PCAP files, and generates HTML/JSON test reports.`,
}

var parseCmd = &cobra.Command{
	Use:   "parse <rule-file>",
	Short: "Parse Snort rules from file",
	Args:  cobra.ExactArgs(1),
	RunE:  parseRules,
}

var testCmd = &cobra.Command{
	Use:   "test <rule-file>",
	Short: "Run full test pipeline",
	Args:  cobra.ExactArgs(1),
	RunE:  runTests,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the REST API server",
	RunE:  startServer,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	RunE:  showVersion,
}

var genCmd = &cobra.Command{
	Use:   "generate <rule-file>",
	Short: "Generate packets from rules (without sending)",
	Args:  cobra.ExactArgs(1),
	RunE:  generatePackets,
}

var lintCmd = &cobra.Command{
	Use:   "lint <rule-file>",
	Short: "Validate Snort rules without generating packets",
	Args:  cobra.ExactArgs(1),
	RunE:  lintRules,
}

var batchCmd = &cobra.Command{
	Use:   "batch <rule-files...>",
	Short: "Run tests on multiple rule files",
	Args:  cobra.MinimumNArgs(1),
	RunE:  batchTest,
}

var benchCmd = &cobra.Command{
	Use:   "benchmark <rule-file>",
	Short: "Run performance benchmark on rule file",
	Args:  cobra.ExactArgs(1),
	RunE:  runBenchmark,
}

var diffCmd = &cobra.Command{
	Use:   "diff <rule-file-1> <rule-file-2>",
	Short: "Compare two rule files and show differences",
	Args:  cobra.ExactArgs(2),
	RunE:  diffRules,
}

var replCmd = &cobra.Command{
	Use:   "repl",
	Short: "Start interactive REPL mode for rule testing",
	RunE:  runRepl,
}

func init() {
	rootCmd.AddCommand(parseCmd, testCmd, serveCmd, versionCmd, genCmd, lintCmd, batchCmd, benchCmd, diffCmd, replCmd)

	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./output", "Output directory")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Config file path")

	testCmd.Flags().StringVarP(&interface_, "interface", "i", "lo0", "Network interface")
	testCmd.Flags().IntVarP(&workers, "workers", "w", 0, "Number of parallel workers (0=auto)")
	testCmd.Flags().StringVarP(&reportFmt, "report", "r", "both", "Report format: json, html, both")
	testCmd.Flags().StringVar(&sendMode, "mode", "pcap", "Send mode: pcap, inject, both")

	serveCmd.Flags().StringVar(&listenAddr, "addr", ":8080", "Listen address")
	serveCmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token for API authentication")
	serveCmd.Flags().StringVar(&corsOrigins, "cors", "", "Comma-separated list of allowed CORS origins")
	serveCmd.Flags().IntVar(&rateLimit, "rate-limit", 100, "Rate limit (requests per second)")

	batchCmd.Flags().IntVarP(&batchWorkers, "workers", "w", 4, "Number of parallel workers for batch processing (default 4)")

	parseCmd.Flags().BoolVar(&parseJSON, "json", false, "Output rules as JSON")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseRules(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]

	parser := rules.NewParser()
	result, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	if parseJSON {
		// Output as JSON
		jsonData, err := json.MarshalIndent(result.Rules, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal rules to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	fmt.Printf("Parsed %d rules from %s\n\n", len(result.Rules), ruleFile)
	for _, rule := range result.Rules {
		fmt.Printf("SID %d: %s\n", rule.RuleID.SID, rule.Msg)
		fmt.Printf("  Protocol: %s\n", rule.Protocol)
		fmt.Printf("  Source: %s:%s -> %s:%s\n", rule.SrcNet, rule.SrcPorts, rule.DstNet, rule.DstPorts)
		if rule.IsBidirectional {
			fmt.Printf("  Direction: <> (bidirectional)\n")
		}
		fmt.Printf("  Contents: %d\n", len(rule.Contents))
		for i, c := range rule.Contents {
			if len(c.Raw) > 20 {
				fmt.Printf("    [%d] %x...\n", i, c.Raw[:20])
			} else {
				fmt.Printf("    [%d] %x\n", i, c.Raw)
			}
		}
		if len(rule.PCREMatches) > 0 {
			fmt.Printf("  PCRE patterns: %d\n", len(rule.PCREMatches))
			for i, p := range rule.PCREMatches {
				fmt.Printf("    [%d] /%s/%s\n", i, p.Pattern, p.Modifiers)
			}
		}
		fmt.Println()
	}

	return nil
}

func runTests(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]
	cfg := loadConfig()

	fmt.Printf("Loading rules from: %s\n", ruleFile)

	parser := rules.NewParser()
	result, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	fmt.Printf("Parsed %d rules\n", len(result.Rules))

	mode := packets.ModePCAP
	switch sendMode {
	case "inject":
		mode = packets.ModeInject
	case "both":
		mode = packets.ModeBoth
	}

	sender, err := packets.NewSenderWithMode(outputDir, interface_, mode)
	if err != nil {
		return fmt.Errorf("failed to create sender: %w", err)
	}
	defer sender.Close()

	generator := packets.NewGeneratorWithVars(cfg.Engine.Generator.Vars)

	eng, err := engine.New(engine.EngineConfig{
		Generator:   generator,
		Sender:      sender,
		WorkerCount: workers,
		OutputDir:   outputDir,
	})
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	fmt.Printf("Running tests with %d workers...\n", eng.WorkerCount)
	start := time.Now()

	testResult, err := eng.Run(result.Rules)
	if err != nil {
		return fmt.Errorf("failed to run tests: %w", err)
	}

	fmt.Printf("\nTest completed in %v\n", time.Since(start))
	fmt.Printf("Total: %d, Success: %d, Failed: %d\n\n", testResult.TotalRules, testResult.SuccessCount, testResult.FailureCount)

	switch reportFmt {
	case "json":
		path, err := reports.NewJSONGenerator(outputDir).Generate(testResult)
		if err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
		fmt.Printf("JSON report: %s\n", path)
	case "html":
		path, err := reports.NewHTMLGenerator(outputDir).Generate(testResult)
		if err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
		fmt.Printf("HTML report: %s\n", path)
	default:
		jsonPath, _ := reports.NewJSONGenerator(outputDir).Generate(testResult)
		htmlPath, _ := reports.NewHTMLGenerator(outputDir).Generate(testResult)
		fmt.Printf("JSON report: %s\n", jsonPath)
		fmt.Printf("HTML report: %s\n", htmlPath)
	}

	return nil
}

func startServer(cmd *cobra.Command, args []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	authToken, _ := cmd.Flags().GetString("auth-token")
	corsStr, _ := cmd.Flags().GetString("cors")
	rate, _ := cmd.Flags().GetInt("rate-limit")

	corsOrigins := []string{}
	if corsStr != "" {
		for _, origin := range splitAndTrim(corsStr, ",") {
			corsOrigins = append(corsOrigins, origin)
		}
	}

	srv := api.NewServer(api.ServerConfig{
		Address:   addr,
		OutputDir: outputDir,
		Auth: api.AuthConfig{
			Enabled: authToken != "",
			Token:   authToken,
		},
		CORS:      corsOrigins,
		RateLimit: rate,
	})

	fmt.Printf("Starting API server on %s\n", addr)
	fmt.Printf("Output directory: %s\n", outputDir)
	if authToken != "" {
		fmt.Printf("Auth: enabled (Bearer token)\n")
	}
	if len(corsOrigins) > 0 {
		fmt.Printf("CORS: %v\n", corsOrigins)
	}
	fmt.Printf("Rate limit: %d req/s\n", rate)

	return srv.Start()
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func loadConfig() *config.Config {
	if configFile == "" {
		return config.LoadDefault()
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Printf("Warning: failed to load config from %s: %v, using defaults\n", configFile, err)
		return config.LoadDefault()
	}
	return cfg
}

func showVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("snortx version %s\n", version)
	fmt.Printf("Go version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return nil
}

func generatePackets(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]
	cfg := loadConfig()

	parser := rules.NewParser()
	result, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	generator := packets.NewGeneratorWithVars(cfg.Engine.Generator.Vars)

	fmt.Printf("Generating packets for %d rules...\n", len(result.Rules))
	generated := 0
	for _, rule := range result.Rules {
		pkts, err := generator.Generate(rule)
		if err != nil {
			fmt.Printf("  SID %d: ERROR - %v\n", rule.RuleID.SID, err)
			continue
		}
		fmt.Printf("  SID %d: Generated %d packet(s)\n", rule.RuleID.SID, len(pkts))
		generated++
	}

	fmt.Printf("\nGenerated packets for %d/%d rules\n", generated, len(result.Rules))
	return nil
}

func lintRules(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]
	cfg := loadConfig()

	parser := rules.NewParser()
	result, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	generator := packets.NewGeneratorWithVars(cfg.Engine.Generator.Vars)

	fmt.Printf("Validating %d rules from %s...\n\n", len(result.Rules), ruleFile)

	warnings := 0
	errors := 0
	for _, rule := range result.Rules {
		issues := validateRule(rule, generator)
		if len(issues) > 0 {
			for _, issue := range issues {
				if issue.isError {
					fmt.Printf("  SID %d [ERROR]: %s\n", rule.RuleID.SID, issue.msg)
					errors++
				} else {
					fmt.Printf("  SID %d [WARN]: %s\n", rule.RuleID.SID, issue.msg)
					warnings++
				}
			}
		}
	}

	fmt.Printf("\nValidation complete: %d errors, %d warnings\n", errors, warnings)
	if errors > 0 {
		fmt.Println("Rule validation failed due to errors")
	}
	return nil
}

type lintIssue struct {
	isError bool
	msg     string
}

func validateRule(rule *rules.ParsedRule, generator *packets.Generator) []lintIssue {
	var issues []lintIssue

	// Check for empty content and no PCRE
	if len(rule.Contents) == 0 && len(rule.PCREMatches) == 0 {
		issues = append(issues, lintIssue{isError: false, msg: "no content match or PCRE - will use generic payload"})
	}

	// Try to generate a packet
	_, err := generator.Generate(rule)
	if err != nil {
		issues = append(issues, lintIssue{isError: true, msg: err.Error()})
	}

	// Check for potentially problematic patterns
	if len(rule.Contents) > 0 {
		for i, c := range rule.Contents {
			if c.IsNegated {
				issues = append(issues, lintIssue{isError: false, msg: fmt.Sprintf("content[%d] is negated - may not match correctly", i)})
			}
			if c.Nocase && len(rule.Contents) > 1 {
				issues = append(issues, lintIssue{isError: false, msg: fmt.Sprintf("content[%d] has nocase with multiple contents - may cause issues", i)})
			}
		}
	}

	// Check PCRE patterns using static analysis
	for i, pcre := range rule.PCREMatches {
		pcreIssues := rules.AnalyzePCRE(pcre.Pattern, pcre.Modifiers)
		for _, pi := range pcreIssues {
			issues = append(issues, lintIssue{
				isError: pi.Severity == "error",
				msg:     fmt.Sprintf("pcre[%d]: %s", i, pi.Message),
			})
		}

		// Legacy check for unsupported modifiers
		if len(pcre.Modifiers) > 0 {
			if contains(pcre.Modifiers, 'R') || contains(pcre.Modifiers, 'U') {
				issues = append(issues, lintIssue{isError: false, msg: fmt.Sprintf("pcre[%d] has PCRE_MATCH_END or PCRE_UNGREEDY modifier", i)})
			}
		}
	}

	return issues
}

func contains(s string, c rune) bool {
	for _, r := range s {
		if r == c {
			return true
		}
	}
	return false
}

func batchTest(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	parser := rules.NewParser()
	generator := packets.NewGeneratorWithVars(cfg.Engine.Generator.Vars)

	totalRules := 0
	totalSuccess := 0
	totalFailed := 0

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to limit concurrent file processing
	sem := make(chan struct{}, batchWorkers)

	for _, ruleFile := range args {
		parseResult, err := parser.ParseFile(ruleFile)
		if err != nil {
			fmt.Printf("Error parsing %s: %v\n", ruleFile, err)
			continue
		}

		fmt.Printf("Processing %s: %d rules\n", ruleFile, len(parseResult.Rules))

		wg.Add(1)
		go func(ruleFile string, rules []*rules.ParsedRule) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			sender, err := packets.NewSenderWithMode(outputDir, interface_, packets.ModePCAP)
			if err != nil {
				fmt.Printf("Error creating sender for %s: %v\n", ruleFile, err)
				return
			}
			defer sender.Close()

			eng, err := engine.New(engine.EngineConfig{
				Generator: generator,
				Sender:    sender,
				OutputDir: outputDir,
			})
			if err != nil {
				fmt.Printf("Error creating engine for %s: %v\n", ruleFile, err)
				return
			}

			result, err := eng.Run(rules)
			if err != nil {
				fmt.Printf("Error running tests for %s: %v\n", ruleFile, err)
				return
			}

			mu.Lock()
			totalRules += len(rules)
			totalSuccess += result.SuccessCount
			totalFailed += result.FailureCount
			mu.Unlock()

			// Generate reports
			reports.NewJSONGenerator(outputDir).Generate(result)
			reports.NewHTMLGenerator(outputDir).Generate(result)
		}(ruleFile, parseResult.Rules)
	}

	wg.Wait()

	fmt.Printf("\n=== Batch Summary ===\n")
	fmt.Printf("Total rules: %d\n", totalRules)
	fmt.Printf("Success: %d\n", totalSuccess)
	fmt.Printf("Failed: %d\n", totalFailed)
	if totalRules > 0 {
		fmt.Printf("Success rate: %.1f%%\n", float64(totalSuccess)/float64(totalRules)*100)
	}

	return nil
}

var benchIterations int
var benchWarmup bool

func init() {
	benchCmd.Flags().IntVarP(&benchIterations, "iterations", "n", 1000, "Number of iterations for benchmark")
	benchCmd.Flags().BoolVar(&benchWarmup, "warmup", false, "Run warmup iteration before benchmark")
}

func runBenchmark(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]
	cfg := loadConfig()

	parser := rules.NewParser()
	result, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	generator := packets.NewGeneratorWithVars(cfg.Engine.Generator.Vars)

	fmt.Printf("Benchmarking: %s\n", ruleFile)
	fmt.Printf("Rules: %d\n", len(result.Rules))
	fmt.Printf("Iterations: %d\n", benchIterations)
	if benchWarmup {
		fmt.Printf("Warmup: enabled\n")
	}
	fmt.Println()

	// Warmup iteration
	if benchWarmup {
		for _, rule := range result.Rules {
			_, _ = generator.Generate(rule)
		}
	}

	// Benchmark parsing
	parseStart := time.Now()
	for i := 0; i < benchIterations; i++ {
		_, _ = parser.ParseFile(ruleFile)
	}
	parseElapsed := time.Since(parseStart)
	parsePerRule := parseElapsed / time.Duration(benchIterations)

	// Benchmark packet generation
	genStart := time.Now()
	genCount := 0
	for i := 0; i < benchIterations; i++ {
		for _, rule := range result.Rules {
			pkts, _ := generator.Generate(rule)
			genCount += len(pkts)
		}
	}
	genElapsed := time.Since(genStart)
	genPerRule := genElapsed / time.Duration(benchIterations)
	genPerPacket := genElapsed / time.Duration(genCount)

	fmt.Printf("=== Parsing Benchmark ===\n")
	fmt.Printf("Total time: %v\n", parseElapsed)
	fmt.Printf("Per iteration: %v\n", parsePerRule)
	fmt.Printf("Iterations/sec: %.2f\n", float64(benchIterations)/parseElapsed.Seconds())
	fmt.Println()

	fmt.Printf("=== Packet Generation Benchmark ===\n")
	fmt.Printf("Total time: %v\n", genElapsed)
	fmt.Printf("Per iteration (all rules): %v\n", genPerRule)
	fmt.Printf("Per rule (avg): %v\n", genElapsed/time.Duration(benchIterations*len(result.Rules)))
	fmt.Printf("Per packet (avg): %v\n", genPerPacket)
	fmt.Printf("Packets/sec: %.2f\n", float64(genCount)/genElapsed.Seconds())
	fmt.Printf("Total packets generated: %d\n", genCount)
	fmt.Println()

	// Memory stats
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	for i := 0; i < benchIterations; i++ {
		for _, rule := range result.Rules {
			_, _ = generator.Generate(rule)
		}
	}
	runtime.ReadMemStats(&m2)
	fmt.Printf("=== Memory Stats ===\n")
	fmt.Printf("Alloc delta: %d KB\n", (m2.Alloc-m1.Alloc)/1024)
	fmt.Printf("TotalAlloc delta: %d KB\n", (m2.TotalAlloc-m1.TotalAlloc)/1024)
	fmt.Printf("Mallocs delta: %d\n", m2.Mallocs-m1.Mallocs)

	return nil
}

func diffRules(cmd *cobra.Command, args []string) error {
	file1, file2 := args[0], args[1]

	parser := rules.NewParser()

	result1, err := parser.ParseFile(file1)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", file1, err)
	}

	result2, err := parser.ParseFile(file2)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", file2, err)
	}

	// Build maps by SID for easy comparison
	rules1 := make(map[int]*rules.ParsedRule)
	rules2 := make(map[int]*rules.ParsedRule)

	for _, r := range result1.Rules {
		rules1[r.RuleID.SID] = r
	}
	for _, r := range result2.Rules {
		rules2[r.RuleID.SID] = r
	}

	added := 0
	removed := 0
	modified := 0

	fmt.Printf("=== Rule Diff: %s vs %s ===\n\n", file1, file2)

	// Find added rules (in file2 but not in file1)
	fmt.Printf("--- Added rules (in %s but not in %s) ---\n", file2, file1)
	for sid := range rules2 {
		if _, ok := rules1[sid]; !ok {
			r := rules2[sid]
			fmt.Printf("  [+%d] %s %s %s:%s -> %s:%s (%s)\n",
				sid, r.Action, r.Protocol, r.SrcNet, r.SrcPorts, r.DstNet, r.DstPorts, r.Msg)
			added++
		}
	}
	if added == 0 {
		fmt.Println("  (none)")
	}

	// Find removed rules (in file1 but not in file2)
	fmt.Printf("\n--- Removed rules (in %s but not in %s) ---\n", file1, file2)
	for sid := range rules1 {
		if _, ok := rules2[sid]; !ok {
			r := rules1[sid]
			fmt.Printf("  [-%d] %s %s %s:%s -> %s:%s (%s)\n",
				sid, r.Action, r.Protocol, r.SrcNet, r.SrcPorts, r.DstNet, r.DstPorts, r.Msg)
			removed++
		}
	}
	if removed == 0 {
		fmt.Println("  (none)")
	}

	// Find modified rules (same SID but different content)
	fmt.Printf("\n--- Modified rules (same SID, different content) ---\n")
	for sid, r1 := range rules1 {
		if r2, ok := rules2[sid]; ok {
			diffs := compareRules(r1, r2)
			if len(diffs) > 0 {
				fmt.Printf("  [~%d] %s\n", sid, r1.Msg)
				for _, d := range diffs {
					fmt.Printf("      %s\n", d)
				}
				modified++
			}
		}
	}
	if modified == 0 {
		fmt.Println("  (none)")
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Added: %d\n", added)
	fmt.Printf("Removed: %d\n", removed)
	fmt.Printf("Modified: %d\n", modified)

	return nil
}

func compareRules(r1, r2 *rules.ParsedRule) []string {
	var diffs []string

	if r1.Action != r2.Action {
		diffs = append(diffs, fmt.Sprintf("action: %s -> %s", r1.Action, r2.Action))
	}
	if r1.Protocol != r2.Protocol {
		diffs = append(diffs, fmt.Sprintf("protocol: %s -> %s", r1.Protocol, r2.Protocol))
	}
	if r1.SrcNet != r2.SrcNet {
		diffs = append(diffs, fmt.Sprintf("src_net: %s -> %s", r1.SrcNet, r2.SrcNet))
	}
	if r1.SrcPorts != r2.SrcPorts {
		diffs = append(diffs, fmt.Sprintf("src_ports: %s -> %s", r1.SrcPorts, r2.SrcPorts))
	}
	if r1.DstNet != r2.DstNet {
		diffs = append(diffs, fmt.Sprintf("dst_net: %s -> %s", r1.DstNet, r2.DstNet))
	}
	if r1.DstPorts != r2.DstPorts {
		diffs = append(diffs, fmt.Sprintf("dst_ports: %s -> %s", r1.DstPorts, r2.DstPorts))
	}
	if r1.Direction != r2.Direction {
		diffs = append(diffs, fmt.Sprintf("direction: %s -> %s", r1.Direction, r2.Direction))
	}
	if r1.Msg != r2.Msg {
		diffs = append(diffs, fmt.Sprintf("msg: %q -> %q", r1.Msg, r2.Msg))
	}
	if len(r1.Contents) != len(r2.Contents) {
		diffs = append(diffs, fmt.Sprintf("content count: %d -> %d", len(r1.Contents), len(r2.Contents)))
	} else {
		for i := range r1.Contents {
			if string(r1.Contents[i].Raw) != string(r2.Contents[i].Raw) {
				diffs = append(diffs, fmt.Sprintf("content[%d]: %x -> %x", i, r1.Contents[i].Raw, r2.Contents[i].Raw))
			}
		}
	}
	if len(r1.PCREMatches) != len(r2.PCREMatches) {
		diffs = append(diffs, fmt.Sprintf("pcre count: %d -> %d", len(r1.PCREMatches), len(r2.PCREMatches)))
	}

	return diffs
}

func runRepl(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	parser := rules.NewParser()
	generator := packets.NewGeneratorWithVars(cfg.Engine.Generator.Vars)

	fmt.Println("snortx REPL - Interactive Rule Testing")
	fmt.Println("=====================================")
	fmt.Println("Commands:")
	fmt.Println("  parse <rule>   - Parse a rule and show details")
	fmt.Println("  generate <rule> - Generate packets for a rule")
	fmt.Println("  help           - Show this help message")
	fmt.Println("  exit, quit     - Exit REPL")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("snortx> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Handle commands
		if input == "exit" || input == "quit" {
			fmt.Println("Goodbye!")
			break
		}
		if input == "help" {
			fmt.Println("Commands:")
			fmt.Println("  parse <rule>   - Parse a rule and show details")
			fmt.Println("  generate <rule> - Generate packets for a rule")
			fmt.Println("  help           - Show this help message")
			fmt.Println("  exit, quit     - Exit REPL")
			continue
		}

		// Parse command
		parts := strings.SplitN(input, " ", 2)
		command := parts[0]
		ruleText := ""
		if len(parts) > 1 {
			ruleText = parts[1]
		}

		if command == "parse" && ruleText != "" {
			r, err := parser.ParseRule(ruleText)
			if err != nil {
				fmt.Printf("Parse error: %v\n", err)
				continue
			}
			fmt.Printf("  SID: %d\n", r.RuleID.SID)
			fmt.Printf("  Protocol: %s\n", r.Protocol)
			fmt.Printf("  Msg: %s\n", r.Msg)
			fmt.Printf("  Contents: %d\n", len(r.Contents))
			for i, c := range r.Contents {
				fmt.Printf("    [%d] %x\n", i, c.Raw)
			}
			fmt.Printf("  PCRE matches: %d\n", len(r.PCREMatches))
			if len(r.Flowbits) > 0 {
				fmt.Printf("  Flowbits: %v\n", r.Flowbits)
			}
		} else if command == "generate" && ruleText != "" {
			r, err := parser.ParseRule(ruleText)
			if err != nil {
				fmt.Printf("Parse error: %v\n", err)
				continue
			}
			pkts, err := generator.Generate(r)
			if err != nil {
				fmt.Printf("Generate error: %v\n", err)
				continue
			}
			fmt.Printf("  Generated %d packet(s)\n", len(pkts))
			for i, pkt := range pkts {
				fmt.Printf("    [%d] Layers: ", i)
				for _, layer := range pkt.Layers() {
					fmt.Printf("%s ", layer.LayerType().String())
				}
				fmt.Println()
			}
		} else {
			// Try to parse as a rule directly
			r, err := parser.ParseRule(input)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				fmt.Println("Use 'parse <rule>' or 'generate <rule>' commands, or enter a rule directly")
				continue
			}
			fmt.Printf("  SID: %d, Protocol: %s, Msg: %s\n", r.RuleID.SID, r.Protocol, r.Msg)
			fmt.Printf("  Contents: %d, PCRE: %d\n", len(r.Contents), len(r.PCREMatches))
		}
	}

	return nil
}
