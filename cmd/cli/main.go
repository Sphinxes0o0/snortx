package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/snortx/internal/api"
	"github.com/user/snortx/internal/engine"
	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/reports"
	"github.com/user/snortx/internal/rules"
)

var (
	outputDir   string
	interface_  string
	workers     int
	reportFmt   string
	listenAddr  string
	sendMode    string
	authToken   string
	corsOrigins string
	rateLimit   int
	configFile  string
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

func init() {
	rootCmd.AddCommand(parseCmd, testCmd, serveCmd, versionCmd, genCmd, lintCmd, batchCmd)

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
	rulesList, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	fmt.Printf("Parsed %d rules from %s\n\n", len(rulesList), ruleFile)
	for _, rule := range rulesList {
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

	fmt.Printf("Loading rules from: %s\n", ruleFile)

	parser := rules.NewParser()
	rulesList, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	fmt.Printf("Parsed %d rules\n", len(rulesList))

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

	generator := packets.NewGenerator()

	eng, err := engine.New(engine.EngineConfig{
		Parser:      parser,
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

	result, err := eng.Run(rulesList)
	if err != nil {
		return fmt.Errorf("failed to run tests: %w", err)
	}

	fmt.Printf("\nTest completed in %v\n", time.Since(start))
	fmt.Printf("Total: %d, Success: %d, Failed: %d\n\n", result.TotalRules, result.SuccessCount, result.FailureCount)

	switch reportFmt {
	case "json":
		path, err := reports.NewJSONGenerator(outputDir).Generate(result)
		if err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
		fmt.Printf("JSON report: %s\n", path)
	case "html":
		path, err := reports.NewHTMLGenerator(outputDir).Generate(result)
		if err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
		fmt.Printf("HTML report: %s\n", path)
	default:
		jsonPath, _ := reports.NewJSONGenerator(outputDir).Generate(result)
		htmlPath, _ := reports.NewHTMLGenerator(outputDir).Generate(result)
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
	for _, part := range split(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func split(s, sep string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i = start - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func showVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("snortx version %s\n", version)
	fmt.Printf("Go version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return nil
}

func generatePackets(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]

	parser := rules.NewParser()
	rulesList, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	generator := packets.NewGenerator()

	fmt.Printf("Generating packets for %d rules...\n", len(rulesList))
	generated := 0
	for _, rule := range rulesList {
		pkts, err := generator.Generate(rule)
		if err != nil {
			fmt.Printf("  SID %d: ERROR - %v\n", rule.RuleID.SID, err)
			continue
		}
		fmt.Printf("  SID %d: Generated %d packet(s)\n", rule.RuleID.SID, len(pkts))
		generated++
	}

	fmt.Printf("\nGenerated packets for %d/%d rules\n", generated, len(rulesList))
	return nil
}

func lintRules(cmd *cobra.Command, args []string) error {
	ruleFile := args[0]

	parser := rules.NewParser()
	rulesList, err := parser.ParseFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	generator := packets.NewGenerator()

	fmt.Printf("Validating %d rules from %s...\n\n", len(rulesList), ruleFile)

	warnings := 0
	errors := 0
	for _, rule := range rulesList {
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

	// Check PCRE patterns for complex constructs
	for i, pcre := range rule.PCREMatches {
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
	parser := rules.NewParser()
	generator := packets.NewGenerator()

	totalRules := 0
	totalSuccess := 0
	totalFailed := 0

	for _, ruleFile := range args {
		rulesList, err := parser.ParseFile(ruleFile)
		if err != nil {
			fmt.Printf("Error parsing %s: %v\n", ruleFile, err)
			continue
		}

		fmt.Printf("Processing %s: %d rules\n", ruleFile, len(rulesList))
		totalRules += len(rulesList)

		sender, err := packets.NewSenderWithMode(outputDir, interface_, packets.ModePCAP)
		if err != nil {
			fmt.Printf("Error creating sender: %v\n", err)
			continue
		}
		defer sender.Close()

		eng, err := engine.New(engine.EngineConfig{
			Parser:    parser,
			Generator: generator,
			Sender:    sender,
			OutputDir: outputDir,
		})
		if err != nil {
			fmt.Printf("Error creating engine: %v\n", err)
			continue
		}

		result, err := eng.Run(rulesList)
		if err != nil {
			fmt.Printf("Error running tests: %v\n", err)
			continue
		}

		totalSuccess += result.SuccessCount
		totalFailed += result.FailureCount

		// Generate reports
		reports.NewJSONGenerator(outputDir).Generate(result)
		reports.NewHTMLGenerator(outputDir).Generate(result)
	}

	fmt.Printf("\n=== Batch Summary ===\n")
	fmt.Printf("Total rules: %d\n", totalRules)
	fmt.Printf("Success: %d\n", totalSuccess)
	fmt.Printf("Failed: %d\n", totalFailed)
	if totalRules > 0 {
		fmt.Printf("Success rate: %.1f%%\n", float64(totalSuccess)/float64(totalRules)*100)
	}

	return nil
}
