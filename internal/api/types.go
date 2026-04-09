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
	Rules    string   `json:"rules"`
	RuleIDs  []int    `json:"rule_ids,omitempty"`
	AllRules bool     `json:"all_rules"`
	Format   string   `json:"format"`
}

type TestRunResponse struct {
	TestRunID string `json:"test_run_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}
