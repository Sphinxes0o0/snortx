package reports

import "time"

type TestRunResult struct {
	TestRunID    string        `json:"test_run_id"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  time.Time     `json:"completed_at"`
	TotalRules   int           `json:"total_rules"`
	SuccessCount int           `json:"success_count"`
	FailureCount int           `json:"failure_count"`
	Results      []*TestResult `json:"results"`
	PCAPFiles    []string      `json:"pcap_files"`
}

type TestResult struct {
	RuleSID      int       `json:"rule_sid"`
	RuleMsg     string    `json:"rule_msg"`
	Protocol    string    `json:"protocol"`
	PacketsGen  int       `json:"packets_generated"`
	PacketsSent int       `json:"packets_sent"`
	PCAPPath    string    `json:"pcap_path"`
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
}

func NewTestRunResult() *TestRunResult {
	return &TestRunResult{
		StartedAt: time.Now(),
		Results:   make([]*TestResult, 0),
		PCAPFiles: make([]string, 0),
	}
}

func (r *TestRunResult) AddResult(result *TestResult) {
	r.Results = append(r.Results, result)
	if result.PCAPPath != "" {
		r.PCAPFiles = append(r.PCAPFiles, result.PCAPPath)
	}
	r.TotalRules++
	if result.Status == "success" {
		r.SuccessCount++
	} else {
		r.FailureCount++
	}
}
