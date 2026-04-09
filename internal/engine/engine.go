package engine

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/user/snortx/internal/packets"
	"github.com/user/snortx/internal/reports"
	"github.com/user/snortx/internal/rules"
)

type Engine struct {
	parser    *rules.Parser
	generator *packets.Generator
	sender    *packets.Sender

	WorkerCount int
	ruleChan    chan *rules.ParsedRule
	resultChan  chan *packets.SendResult

	wg sync.WaitGroup
	mu sync.Mutex

	testRunResult *reports.TestRunResult
}

type EngineConfig struct {
	Parser      *rules.Parser
	Generator   *packets.Generator
	Sender      *packets.Sender
	WorkerCount int
	OutputDir   string
}

func New(cfg EngineConfig) (*Engine, error) {
	workerCount := cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	e := &Engine{
		parser:        cfg.Parser,
		generator:     cfg.Generator,
		sender:        cfg.Sender,
		WorkerCount:   workerCount,
		ruleChan:      make(chan *rules.ParsedRule, workerCount*2),
		resultChan:    make(chan *packets.SendResult, workerCount*2),
		testRunResult: reports.NewTestRunResult(),
	}

	e.testRunResult.TestRunID = fmt.Sprintf("run_%d", time.Now().Unix())

	return e, nil
}

func (e *Engine) Run(parsedRules []*rules.ParsedRule) (*reports.TestRunResult, error) {
	e.testRunResult.StartedAt = time.Now()

	for i := 0; i < e.WorkerCount; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	go func() {
		for _, rule := range parsedRules {
			e.ruleChan <- rule
		}
		close(e.ruleChan)
	}()

	go func() {
		e.wg.Wait()
		close(e.resultChan)
	}()

	for result := range e.resultChan {
		tr := &reports.TestResult{
			RuleSID:     result.RuleSID,
			RuleMsg:     result.RuleMsg,
			Protocol:    result.Protocol,
			PacketsGen:  result.PacketsGen,
			PacketsSent: result.PacketsSent,
			PCAPPath:    result.PCAPPath,
			Status:      result.Status,
			Error:       result.Error,
			Duration:    result.Duration,
		}
		e.mu.Lock()
		e.testRunResult.AddResult(tr)
		e.mu.Unlock()
	}

	e.testRunResult.CompletedAt = time.Now()

	return e.testRunResult, nil
}

func (e *Engine) worker(id int) {
	defer e.wg.Done()

	for rule := range e.ruleChan {
		e.processRule(rule)
	}
}

func (e *Engine) processRule(rule *rules.ParsedRule) {
	start := time.Now()

	pkts, err := e.generator.Generate(rule)
	if err != nil {
		e.resultChan <- &packets.SendResult{
			RuleSID:  rule.RuleID.SID,
			RuleMsg:  rule.Msg,
			Protocol: rule.Protocol,
			Status:   "failed",
			Error:    fmt.Sprintf("generation failed: %v", err),
		}
		return
	}

	if len(rule.PCREMatches) > 0 {
		payload := pkts[0].Data()
		if err := e.validatePCRE(rule.PCREMatches, payload); err != nil {
			e.resultChan <- &packets.SendResult{
				RuleSID:  rule.RuleID.SID,
				RuleMsg:  rule.Msg,
				Protocol: rule.Protocol,
				Status:   "failed",
				Error:    fmt.Sprintf("PCRE mismatch: %v", err),
			}
			return
		}
	}

	result := e.sender.SendAndRecord(rule, pkts)
	result.RuleSID = rule.RuleID.SID
	result.RuleMsg = rule.Msg
	result.Protocol = rule.Protocol
	result.PacketsGen = len(pkts)
	result.Duration = time.Since(start)

	e.resultChan <- &result
}

func (e *Engine) validatePCRE(pcreMatches []rules.PCREMatch, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty payload")
	}

	for _, pcre := range pcreMatches {
		pattern := pcre.Pattern
		modifiers := pcre.Modifiers

		if strings.Contains(modifiers, "i") {
			pattern = "(?i)" + pattern
		}
		if strings.Contains(modifiers, "m") {
			pattern = "(?m)" + pattern
		}
		if strings.Contains(modifiers, "s") {
			pattern = "(?s)" + pattern
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid PCRE pattern: %v", err)
		}

		if !re.Match(payload) {
			return fmt.Errorf("payload does not match PCRE /%s/%s", pcre.Pattern, pcre.Modifiers)
		}
	}

	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	close(e.ruleChan)
	e.wg.Wait()
}
