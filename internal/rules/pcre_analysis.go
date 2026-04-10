package rules

import (
	"regexp"
	"strings"
)

// PCREIssue represents an issue found in PCRE pattern analysis
type PCREIssue struct {
	Pattern   string
	Severity string // "error", "warning"
	Message   string
}

// AnalyzePCRE performs static analysis on a PCRE pattern to detect potential issues
func AnalyzePCRE(pattern string, modifiers string) []PCREIssue {
	var issues []PCREIssue

	// Check for empty pattern
	if pattern == "" {
		issues = append(issues, PCREIssue{
			Pattern:   pattern,
			Severity: "error",
			Message:   "empty pattern",
		})
		return issues
	}

	// Check for nested quantifiers (ReDoS risk)
	if hasNestedQuantifiers(pattern) {
		issues = append(issues, PCREIssue{
			Pattern:   pattern,
			Severity:  "warning",
			Message:   "nested quantifiers detected - potential for catastrophic backtracking",
		})
	}

	// Check for overlapping alternation
	if hasOverlappingAlternation(pattern) {
		issues = append(issues, PCREIssue{
			Pattern:   pattern,
			Severity:  "warning",
			Message:   "alternation with overlapping patterns may cause backtracking",
		})
	}

	// Check for unanchored patterns with quantifiers at end
	if hasUnanchoredQuantifiers(pattern) {
		issues = append(issues, PCREIssue{
			Pattern:   pattern,
			Severity:  "warning",
			Message:   "unanchored pattern with trailing quantifier may cause excessive backtracking",
		})
	}

	// Check for extremely long character classes
	if hasLargeCharClass(pattern) {
		issues = append(issues, PCREIssue{
			Pattern:   pattern,
			Severity:  "warning",
			Message:   "large character class may cause performance issues",
		})
	}

	// Check if Go regex can compile it (syntax validity)
	_, goErr := regexp.Compile(pattern)
	if goErr != nil {
		issues = append(issues, PCREIssue{
			Pattern:   pattern,
			Severity:  "error",
			Message:   "invalid regex pattern: " + goErr.Error(),
		})
	}

	return issues
}

// hasNestedQuantifiers detects nested quantifiers like (a+)+, (a*)*, (a+)* etc.
func hasNestedQuantifiers(pattern string) bool {
	// Pattern to find quantifier inside a group
	nestedQuantifier := regexp.MustCompile(`\([^)]*[*+][^)]*\)[*+]`)
	if nestedQuantifier.MatchString(pattern) {
		return true
	}

	// Check for patterns like .*.* which can cause issues
	if matched, _ := regexp.MatchString(`\(\.\*[^*]*\)\+\|\+\|\*\+`, pattern); matched {
		return true
	}

	return false
}

// hasOverlappingAlternation checks for patterns like (a|ab)+ which can cause backtracking
func hasOverlappingAlternation(pattern string) bool {
	// Find alternations
	altRe := regexp.MustCompile(`\(\?[^)]+\|[^)]+\)|\[^[^\]]+\|[^\]]+\]|[^|]\|[^|]`)
	matches := altRe.FindAllStringSubmatch(pattern, -1)
	if len(matches) == 0 {
		return false
	}

	// Simple heuristic: if we have alternation with common prefixes, flag it
	// e.g., (ab|abc) has overlapping "ab" prefix
	overlapRe := regexp.MustCompile(`\(\w+|\w+\w+\)|\[[\w]+\|[\w]+\]`)
	return overlapRe.MatchString(pattern)
}

// hasUnanchoredQuantifiers checks for patterns ending with unanchored quantifiers
func hasUnanchoredQuantifiers(pattern string) bool {
	trimmed := strings.TrimSpace(pattern)
	if len(trimmed) == 0 {
		return false
	}

	// Check if pattern ends with a quantifier without anchor
	if strings.HasSuffix(trimmed, "+") ||
		strings.HasSuffix(trimmed, "*") ||
		strings.HasSuffix(trimmed, "?") {
		// Check it's not anchored at start
		if !strings.HasPrefix(trimmed, "^") && !strings.HasPrefix(trimmed, "\\A") {
			return true
		}
	}

	// Check for .* at end without being anchored
	if matched, _ := regexp.MatchString(`[^\\]\.\*+$`, trimmed); matched {
		return true
	}

	return false
}

// hasLargeCharClass detects very large character classes like [a-zA-Z0-9]
func hasLargeCharClass(pattern string) bool {
	// Find character classes
	charClassRe := regexp.MustCompile(`\[([^\]]+)\]`)
	matches := charClassRe.FindAllStringSubmatch(pattern, -1)

	for _, match := range matches {
		if len(match) > 1 {
			class := match[1]
			// Skip negated classes and simple ranges
			if strings.HasPrefix(class, "^") {
				continue
			}
			// Count unique characters
			// Simple heuristic: if it has multiple ranges, flag it
			rangeRe := regexp.MustCompile(`[a-z]-[a-z]|[A-Z]-[A-Z]|[0-9]-[0-9]`)
			ranges := rangeRe.FindAllString(class, -1)
			if len(ranges) >= 3 {
				return true
			}
		}
	}

	return false
}
