package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/user/snortx/internal/engine"
	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/reports"
	"github.com/user/snortx/internal/rules"
)

type Handlers struct {
	generator *packets.Generator
	jsonGen   *reports.JSONGenerator
	htmlGen   *reports.HTMLGenerator
	outputDir string
	mu        sync.RWMutex
	testRuns  map[string]*reports.TestRunResult
}

func NewHandlers(outputDir string) *Handlers {
	h := &Handlers{
		generator: packets.NewGenerator(),
		jsonGen:   reports.NewJSONGenerator(outputDir),
		htmlGen:   reports.NewHTMLGenerator(outputDir),
		outputDir: outputDir,
		testRuns:  make(map[string]*reports.TestRunResult),
	}
	// Load existing results from disk
	h.loadResults()
	return h
}

// persistPath returns the path to persist a test result
func (h *Handlers) persistPath(testRunID string) string {
	return filepath.Join(h.outputDir, "test_runs", testRunID+".json")
}

// saveResult persists a test result to disk
func (h *Handlers) saveResult(result *reports.TestRunResult) error {
	path := h.persistPath(result.TestRunID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// loadResults loads all persisted test results from disk
func (h *Handlers) loadResults() {
	dir := filepath.Join(h.outputDir, "test_runs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		testRunID := entry.Name()[:len(entry.Name())-5]
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var result reports.TestRunResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}
		h.testRuns[testRunID] = &result
	}
}

func (h *Handlers) UploadRules(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("rules")
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read file", err.Error())
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read file content", err.Error())
		return
	}

	parser := rules.NewParser()
	result, err := parser.ParseMulti(string(content))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to parse rules", err.Error())
		return
	}

	resp := ParseResponse{
		Rules:  result.Rules,
		Count:  len(result.Rules),
		Errors: convertParseErrors(result.Errors),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) ParseRules(w http.ResponseWriter, r *http.Request) {
	var req ParseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	parser := rules.NewParser()
	result, err := parser.ParseMulti(req.Rules)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to parse rules", err.Error())
		return
	}

	resp := ParseResponse{
		Rules:  result.Rules,
		Count:  len(result.Rules),
		Errors: convertParseErrors(result.Errors),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) RunTests(w http.ResponseWriter, r *http.Request) {
	var req TestRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	// Parse rules from request body
	parser := rules.NewParser()
	parseResult, err := parser.ParseMulti(req.Rules)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to parse rules", err.Error())
		return
	}
	parseErrors := convertParseErrors(parseResult.Errors)
	if len(parseResult.Rules) == 0 {
		h.writeJSON(w, http.StatusBadRequest, ParseResponse{
			Rules:  []*rules.ParsedRule{},
			Count:  0,
			Errors: parseErrors,
		})
		return
	}

	// Create sender for this run
	iface := req.Interface
	if iface == "" {
		iface = "lo0"
	}
	sender, err := packets.NewSender(h.outputDir, iface)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create sender", err.Error())
		return
	}
	defer sender.Close()

	// Create engine
	eng, err := engine.New(engine.EngineConfig{
		Generator: h.generator,
		Sender:    sender,
		OutputDir: h.outputDir,
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create engine", err.Error())
		return
	}

	// Run tests
	result, err := eng.Run(parseResult.Rules)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to run tests", err.Error())
		return
	}

	// Store result in memory and persist to disk
	h.mu.Lock()
	h.testRuns[result.TestRunID] = result
	h.mu.Unlock()

	// Persist to disk
	if err := h.saveResult(result); err != nil {
		// Log but don't fail - the result is already in memory
		fmt.Printf("Warning: failed to persist result: %v\n", err)
	}

	// Generate reports
	var jsonPath, htmlPath string
	var reportErrs []string
	switch req.Format {
	case "json":
		jsonPath, err = h.jsonGen.Generate(result)
		if err != nil {
			reportErrs = append(reportErrs, fmt.Sprintf("json report: %v", err))
		}
	case "html":
		htmlPath, err = h.htmlGen.Generate(result)
		if err != nil {
			reportErrs = append(reportErrs, fmt.Sprintf("html report: %v", err))
		}
	default:
		jsonPath, err = h.jsonGen.Generate(result)
		if err != nil {
			reportErrs = append(reportErrs, fmt.Sprintf("json report: %v", err))
		}
		htmlPath, err = h.htmlGen.Generate(result)
		if err != nil {
			reportErrs = append(reportErrs, fmt.Sprintf("html report: %v", err))
		}
	}

	// Determine status based on errors
	status := "completed"
	if len(reportErrs) > 0 || len(parseErrors) > 0 {
		status = "completed_with_errors"
	}

	var msg string
	if len(reportErrs) > 0 {
		msg = fmt.Sprintf("JSON: %s, HTML: %s, Errors: %v", jsonPath, htmlPath, reportErrs)
	} else {
		msg = fmt.Sprintf("JSON: %s, HTML: %s", jsonPath, htmlPath)
	}
	resp := TestRunResponse{
		TestRunID:    result.TestRunID,
		Status:       status,
		Total:        result.TotalRules,
		Success:      result.SuccessCount,
		Failed:       result.FailureCount,
		Message:      msg,
		JSONPath:     jsonPath,
		HTMLPath:     htmlPath,
		ParseErrors:  parseErrors,
		ReportErrors: reportErrs,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func convertParseErrors(errs []*rules.ParseError) []ParseError {
	if len(errs) == 0 {
		return []ParseError{}
	}
	out := make([]ParseError, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		out = append(out, ParseError{
			Line:  err.Line,
			Error: err.Error(),
			Rule:  err.RuleText,
		})
	}
	return out
}

func (h *Handlers) GetTestResults(w http.ResponseWriter, r *http.Request) {
	testRunID := r.URL.Query().Get("id")
	if testRunID == "" {
		h.writeError(w, http.StatusBadRequest, "missing test_run_id", "")
		return
	}

	// Parse pagination params
	page := 1
	pageSize := 50
	hasPage := false
	hasPageSize := false
	if p := r.URL.Query().Get("page"); p != "" {
		hasPage = true
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		hasPageSize = true
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 {
			pageSize = parsed
			if pageSize > 100 {
				pageSize = 100 // cap at 100
			}
		}
	}

	h.mu.RLock()
	result, exists := h.testRuns[testRunID]
	h.mu.RUnlock()

	if !exists {
		h.writeError(w, http.StatusNotFound, "test run not found", "")
		return
	}

	// If no pagination requested, return full result (backward compatible)
	if !hasPage && !hasPageSize {
		h.writeJSON(w, http.StatusOK, result)
		return
	}

	// Apply pagination
	totalResults := len(result.Results)
	totalPages := (totalResults + pageSize - 1) / pageSize
	if page < 1 {
		page = 1
	}
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > totalResults {
		end = totalResults
	}

	items := make([]*TestResultItem, 0, end-start)
	for i := start; i < end; i++ {
		r := result.Results[i]
		items = append(items, &TestResultItem{
			RuleSID:     r.RuleSID,
			RuleMsg:     r.RuleMsg,
			Protocol:    r.Protocol,
			PacketsGen:  r.PacketsGen,
			PacketsSent: r.PacketsSent,
			PCAPPath:    r.PCAPPath,
			Status:      r.Status,
			Error:       r.Error,
			Duration:    r.Duration.String(),
		})
	}

	resp := TestResultsResponse{
		TestRunID:    result.TestRunID,
		TotalResults: totalResults,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
		Results:      items,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handlers) DeleteTestResult(w http.ResponseWriter, r *http.Request) {
	testRunID := r.URL.Query().Get("id")
	if testRunID == "" {
		h.writeError(w, http.StatusBadRequest, "missing test_run_id", "")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.testRuns[testRunID]; !exists {
		h.writeError(w, http.StatusNotFound, "test run not found", "")
		return
	}

	// Delete from memory
	delete(h.testRuns, testRunID)

	// Delete persisted file
	path := h.persistPath(testRunID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		h.writeError(w, http.StatusInternalServerError, "failed to delete persisted result", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "test_run_id": testRunID})
}

func (h *Handlers) BatchDeleteTestResults(w http.ResponseWriter, r *http.Request) {
	var req BatchDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	if len(req.IDs) == 0 {
		h.writeError(w, http.StatusBadRequest, "no IDs provided", "")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var deleted []string
	var failed []string

	for _, id := range req.IDs {
		if _, exists := h.testRuns[id]; exists {
			delete(h.testRuns, id)
		}

		path := h.persistPath(id)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			failed = append(failed, id)
		} else {
			deleted = append(deleted, id)
		}
	}

	h.writeJSON(w, http.StatusOK, BatchDeleteResponse{
		Deleted: deleted,
		Failed:  failed,
		Count:   len(deleted),
	})
}

func (h *Handlers) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handlers) writeError(w http.ResponseWriter, code int, msg, details string) {
	h.writeJSON(w, code, ErrorResponse{
		Code:    code,
		Message: msg,
		Details: details,
	})
}
