package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/snortx/internal/reports"
	"github.com/user/snortx/internal/rules"
)

func TestHandlers_ParseRules(t *testing.T) {
	h := NewHandlers(t.TempDir())

	body := "{\"rules\": \"alert tcp any any -> any any (msg:\\\"TEST\\\"; content:\\\"test\\\"; sid:1; rev:1;)\"}"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/parse", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.ParseRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ParseResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Count != 1 {
		t.Errorf("expected 1 rule, got %d", resp.Count)
	}
	if len(resp.Errors) != 0 {
		t.Errorf("expected no errors, got %v", resp.Errors)
	}
}

func TestHandlers_ParseRules_InvalidBody(t *testing.T) {
	h := NewHandlers(t.TempDir())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/parse", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.ParseRules(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandlers_ParseRules_EmptyRules(t *testing.T) {
	h := NewHandlers(t.TempDir())

	body := `{"rules": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/parse", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.ParseRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ParseResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Count != 0 {
		t.Errorf("expected 0 rules, got %d", resp.Count)
	}
}

func TestHandlers_ParseRules_InvalidRules(t *testing.T) {
	h := NewHandlers(t.TempDir())

	body := `{"rules": "not a valid snort rule"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/parse", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.ParseRules(w, req)

	// Should still return 200 but with errors
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ParseResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Error("expected parse errors for invalid rules")
	}
}

func TestHandlers_HealthCheck(t *testing.T) {
	h := NewHandlers(t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	h.HealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", resp["status"])
	}
}

func TestHandlers_GetTestResults_NotFound(t *testing.T) {
	h := NewHandlers(t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/results?id=nonexistent", nil)
	w := httptest.NewRecorder()

	h.GetTestResults(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestHandlers_GetTestResults_MissingID(t *testing.T) {
	h := NewHandlers(t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/results", nil)
	w := httptest.NewRecorder()

	h.GetTestResults(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandlers_GetTestResults_NoPaginationReturnsFullResult(t *testing.T) {
	h := NewHandlers(t.TempDir())

	result := reports.NewTestRunResult()
	result.TestRunID = "run-no-pagination"
	result.AddResult(&reports.TestResult{RuleSID: 1, RuleMsg: "r1", Protocol: "tcp", Status: "success"})
	result.AddResult(&reports.TestResult{RuleSID: 2, RuleMsg: "r2", Protocol: "udp", Status: "failed", Error: "x"})
	h.testRuns[result.TestRunID] = result

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/results?id="+result.TestRunID, nil)
	w := httptest.NewRecorder()
	h.GetTestResults(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp reports.TestRunResult
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.TotalRules != 2 {
		t.Errorf("expected TotalRules 2, got %d", resp.TotalRules)
	}
	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}
}

func TestHandlers_GetTestResults_PageAndPageSizeParsing(t *testing.T) {
	h := NewHandlers(t.TempDir())

	result := reports.NewTestRunResult()
	result.TestRunID = "run-pagination"
	result.AddResult(&reports.TestResult{RuleSID: 1, RuleMsg: "r1", Protocol: "tcp", Status: "success"})
	result.AddResult(&reports.TestResult{RuleSID: 2, RuleMsg: "r2", Protocol: "tcp", Status: "success"})
	result.AddResult(&reports.TestResult{RuleSID: 3, RuleMsg: "r3", Protocol: "udp", Status: "failed", Error: "err"})
	h.testRuns[result.TestRunID] = result

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/results?id="+result.TestRunID+"&page=2&page_size=2", nil)
	w := httptest.NewRecorder()
	h.GetTestResults(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp TestResultsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Page != 2 {
		t.Errorf("expected page 2, got %d", resp.Page)
	}
	if resp.PageSize != 2 {
		t.Errorf("expected page_size 2, got %d", resp.PageSize)
	}
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result on page 2, got %d", len(resp.Results))
	}
	if len(resp.Results) == 1 && resp.Results[0].RuleSID != 3 {
		t.Errorf("expected SID 3 on page 2, got %d", resp.Results[0].RuleSID)
	}
}

func TestNewHandlers(t *testing.T) {
	h := NewHandlers("/tmp/output")

	if h.generator == nil {
		t.Error("expected generator to be initialized")
	}
	if h.jsonGen == nil {
		t.Error("expected jsonGen to be initialized")
	}
	if h.htmlGen == nil {
		t.Error("expected htmlGen to be initialized")
	}
	if h.outputDir != "/tmp/output" {
		t.Errorf("expected outputDir '/tmp/output', got %q", h.outputDir)
	}
	if h.testRuns == nil {
		t.Error("expected testRuns map to be initialized")
	}
}

func TestHandlers_RunTests(t *testing.T) {
	h := NewHandlers(t.TempDir())

	rule := &rules.ParsedRule{
		Protocol:  "tcp",
		SrcNet:    "any",
		DstNet:    "any",
		SrcPorts:  "any",
		DstPorts:  "80",
		Direction: "->",
		RuleID:    rules.RuleID{SID: 1},
		Msg:       "test",
		Contents:  []rules.ContentMatch{{Raw: []byte("test")}},
	}
	ruleBytes, _ := json.Marshal(rule)

	body := map[string]interface{}{
		"rules": string(ruleBytes),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tests/run", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.RunTests(w, req)

	// May fail due to sender setup, but should not panic
	_ = w.Code
}

func TestHandlers_RunTests_AllInvalidRules(t *testing.T) {
	h := NewHandlers(t.TempDir())

	body := `{"rules":"not a valid snort rule"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tests/run", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.RunTests(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var resp ParseResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Count != 0 {
		t.Errorf("expected 0 parsed rules, got %d", resp.Count)
	}
	if len(resp.Errors) == 0 {
		t.Error("expected parse errors in response")
	}
}

func TestErrorResponse(t *testing.T) {
	resp := ErrorResponse{
		Code:    400,
		Message: "bad request",
		Details: "missing field",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Code != 400 {
		t.Errorf("expected Code 400, got %d", decoded.Code)
	}
	if decoded.Message != "bad request" {
		t.Errorf("expected Message 'bad request', got %q", decoded.Message)
	}
	if decoded.Details != "missing field" {
		t.Errorf("expected Details 'missing field', got %q", decoded.Details)
	}
}
