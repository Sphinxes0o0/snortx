package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/user/snortx/internal/engine"
	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/reports"
	"github.com/user/snortx/internal/rules"
)

type Handlers struct {
	engine    *engine.Engine
	generator *packets.Generator
	sender    *packets.Sender
	jsonGen   *reports.JSONGenerator
	htmlGen   *reports.HTMLGenerator
	outputDir string
}

func NewHandlers(outputDir string) *Handlers {
	return &Handlers{
		generator: packets.NewGenerator(),
		sender:    nil,
		jsonGen:   reports.NewJSONGenerator(outputDir),
		htmlGen:   reports.NewHTMLGenerator(outputDir),
		outputDir: outputDir,
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
	rulesList, err := parser.ParseMulti(string(content))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to parse rules", err.Error())
		return
	}

	resp := ParseResponse{
		Rules:  rulesList,
		Count:  len(rulesList),
		Errors: []ParseError{},
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
	rulesList, err := parser.ParseMulti(req.Rules)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to parse rules", err.Error())
		return
	}

	resp := ParseResponse{
		Rules:  rulesList,
		Count:  len(rulesList),
		Errors: []ParseError{},
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
	rulesList, err := parser.ParseMulti(req.Rules)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to parse rules", err.Error())
		return
	}

	// Create sender for this run
	sender, err := packets.NewSender(h.outputDir, "lo0")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create sender", err.Error())
		return
	}
	defer sender.Close()

	// Create engine
	eng, err := engine.New(engine.EngineConfig{
		Parser:    parser,
		Generator: h.generator,
		Sender:    sender,
		OutputDir: h.outputDir,
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create engine", err.Error())
		return
	}

	// Run tests
	result, err := eng.Run(rulesList)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to run tests", err.Error())
		return
	}

	// Generate reports
	var jsonPath, htmlPath string
	switch req.Format {
	case "json":
		jsonPath, _ = h.jsonGen.Generate(result)
	case "html":
		htmlPath, _ = h.htmlGen.Generate(result)
	default:
		jsonPath, _ = h.jsonGen.Generate(result)
		htmlPath, _ = h.htmlGen.Generate(result)
	}

	resp := TestRunResponse{
		TestRunID: result.TestRunID,
		Status:    "completed",
		Message:   fmt.Sprintf("JSON: %s, HTML: %s", jsonPath, htmlPath),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) GetTestResults(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
