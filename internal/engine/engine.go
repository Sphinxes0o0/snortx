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

const (
	// maxPCRECacheSize is the maximum number of PCRE patterns to cache
	maxPCRECacheSize = 1000
	// pcreCacheCleanupThreshold is when to trigger cleanup (number of entries)
	pcreCacheCleanupThreshold = 1200
)

type cachedRegex struct {
	regex      *regexp.Regexp
	lastAccess time.Time
}

type Engine struct {
	generator *packets.Generator
	sender    *packets.Sender

	WorkerCount int
	ruleChan    chan *rules.ParsedRule
	resultChan  chan *packets.SendResult

	wg sync.WaitGroup
	mu sync.Mutex

	testRunResult *reports.TestRunResult
	pcreCache     map[string]*cachedRegex

	// flowbitState tracks flowbit states for stateful rule processing
	flowbitState map[string]bool
	flowbitMu    sync.RWMutex
}

type EngineConfig struct {
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
		generator:     cfg.Generator,
		sender:        cfg.Sender,
		WorkerCount:   workerCount,
		ruleChan:      make(chan *rules.ParsedRule, workerCount*2),
		resultChan:    make(chan *packets.SendResult, workerCount*2),
		testRunResult: reports.NewTestRunResult(),
		pcreCache:     make(map[string]*cachedRegex),
	}

	e.testRunResult.TestRunID = fmt.Sprintf("run_%d", time.Now().Unix())

	return e, nil
}

func (e *Engine) Run(parsedRules []*rules.ParsedRule) (*reports.TestRunResult, error) {
	// Reset channels and result for each run
	e.ruleChan = make(chan *rules.ParsedRule, e.WorkerCount*2)
	e.resultChan = make(chan *packets.SendResult, e.WorkerCount*2)
	e.testRunResult = reports.NewTestRunResult()
	e.testRunResult.TestRunID = fmt.Sprintf("run_%d", time.Now().Unix())
	e.testRunResult.StartedAt = time.Now()

	// Reset flowbit state for this run
	e.flowbitMu.Lock()
	e.flowbitState = make(map[string]bool)
	e.flowbitMu.Unlock()

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

	// Check flowbit conditions before processing
	if !e.checkFlowbits(rule) {
		e.resultChan <- &packets.SendResult{
			RuleSID:  rule.RuleID.SID,
			RuleMsg:  rule.Msg,
			Protocol: rule.Protocol,
			Status:   "failed",
			Error:    "flowbit condition not met",
		}
		return
	}

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

	// Set flowbits after successful match
	e.setFlowbits(rule)

	e.resultChan <- &result
}

// checkFlowbits checks if flowbit conditions are met for a rule
func (e *Engine) checkFlowbits(rule *rules.ParsedRule) bool {
	if len(rule.Flowbits) == 0 {
		return true
	}

	e.flowbitMu.RLock()
	defer e.flowbitMu.RUnlock()

	for _, fb := range rule.Flowbits {
		switch fb.Op {
		case rules.FlowbitIsSet:
			if !e.flowbitState[fb.Name] {
				return false
			}
		case rules.FlowbitNotSet:
			if e.flowbitState[fb.Name] {
				return false
			}
		}
	}
	return true
}

// setFlowbits sets flowbit states after a successful rule match
func (e *Engine) setFlowbits(rule *rules.ParsedRule) {
	e.flowbitMu.Lock()
	defer e.flowbitMu.Unlock()

	for _, fb := range rule.Flowbits {
		switch fb.Op {
		case rules.FlowbitSet:
			e.flowbitState[fb.Name] = true
		case rules.FlowbitToggle:
			e.flowbitState[fb.Name] = !e.flowbitState[fb.Name]
		case rules.FlowbitUnset:
			e.flowbitState[fb.Name] = false
		}
	}
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

		// Check cache first
		cacheKey := pattern
		e.mu.Lock()
		cached, found := e.pcreCache[cacheKey]
		if found {
			cached.lastAccess = time.Now()
			e.mu.Unlock()
			if !cached.regex.Match(payload) {
				return fmt.Errorf("payload does not match PCRE /%s/%s", pcre.Pattern, pcre.Modifiers)
			}
			continue
		}

		// Compile and cache
		re, err := regexp.Compile(pattern)
		if err != nil {
			e.mu.Unlock()
			return fmt.Errorf("invalid PCRE pattern: %v", err)
		}

		e.pcreCache[cacheKey] = &cachedRegex{
			regex:      re,
			lastAccess: time.Now(),
		}

		// Evict if cache is too large
		if len(e.pcreCache) >= pcreCacheCleanupThreshold {
			e.evictPCRECache()
		}
		e.mu.Unlock()

		if !re.Match(payload) {
			return fmt.Errorf("payload does not match PCRE /%s/%s", pcre.Pattern, pcre.Modifiers)
		}
	}

	return nil
}

// evictPCRECache removes oldest entries when cache exceeds maxPCRECacheSize
func (e *Engine) evictPCRECache() {
	// If cache is under limit, nothing to do
	if len(e.pcreCache) <= maxPCRECacheSize {
		return
	}

	// Find and remove oldest entries to get back to maxPCRECacheSize
	targetSize := maxPCRECacheSize / 2 // Remove half to avoid frequent eviction
	toRemove := len(e.pcreCache) - targetSize

	if toRemove <= 0 {
		return
	}

	// Find oldest entries
	type entry struct {
		key  string
		time time.Time
	}
	var entries []entry
	for k, v := range e.pcreCache {
		entries = append(entries, entry{key: k, time: v.lastAccess})
	}

	// Sort by access time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].time.Before(entries[i].time) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove oldest entries
	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(e.pcreCache, entries[i].key)
	}
}

func (e *Engine) Stop() {
	// Note: ruleChan is closed by the sender goroutine in Run(),
	// so we only wait for workers to finish. This is safe to call
	// even after Run() completes.
	e.wg.Wait()
}
