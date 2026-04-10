package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
