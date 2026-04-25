package api

import "github.com/user/snortx/internal/rules"

type ParseRequest struct {
	Rules  string `json:"rules"`
	Format string `json:"format"`
}

type ParseResponse struct {
	Rules  []*rules.ParsedRule `json:"rules"`
	Count  int                 `json:"count"`
	Errors []ParseError        `json:"errors,omitempty"`
}

type ParseError struct {
	Line  int    `json:"line"`
	Error string `json:"error"`
	Rule  string `json:"rule,omitempty"`
}

type TestRunRequest struct {
	Rules     string `json:"rules"`
	RuleIDs   []int  `json:"rule_ids,omitempty"`
	AllRules  bool   `json:"all_rules"`
	Format    string `json:"format"`
	Interface string `json:"interface"`
}

type TestRunResponse struct {
	TestRunID    string       `json:"test_run_id"`
	Status       string       `json:"status"`
	Total        int          `json:"total"`
	Success      int          `json:"success"`
	Failed       int          `json:"failed"`
	Message      string       `json:"message"`
	JSONPath     string       `json:"json_path,omitempty"`
	HTMLPath     string       `json:"html_path,omitempty"`
	ParseErrors  []ParseError `json:"parse_errors,omitempty"`
	ReportErrors []string     `json:"report_errors,omitempty"`
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type TestResultsResponse struct {
	TestRunID    string            `json:"test_run_id"`
	TotalResults int               `json:"total_results"`
	Page         int               `json:"page"`
	PageSize     int               `json:"page_size"`
	TotalPages   int               `json:"total_pages"`
	Results      []*TestResultItem `json:"results"`
}

type TestResultItem struct {
	RuleSID     int    `json:"rule_sid"`
	RuleMsg     string `json:"rule_msg"`
	Protocol    string `json:"protocol"`
	PacketsGen  int    `json:"packets_gen"`
	PacketsSent int    `json:"packets_sent"`
	PCAPPath    string `json:"pcap_path"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	Duration    string `json:"duration"`
}

type BatchDeleteRequest struct {
	IDs []string `json:"ids"`
}

type BatchDeleteResponse struct {
	Deleted []string `json:"deleted"`
	Failed  []string `json:"failed,omitempty"`
	Count   int      `json:"count"`
}
