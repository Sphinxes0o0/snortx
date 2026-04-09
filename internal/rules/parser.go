package rules

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrEmptyRule     = errors.New("empty or comment line")
	ErrInvalidFormat = errors.New("invalid rule format")
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) ParseMulti(text string) ([]*ParsedRule, error) {
	var rules []*ParsedRule
	lines := strings.Split(text, "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := p.ParseRule(line)
		if err != nil {
			fmt.Printf("Warning: Line %d: %v\n", lineNum+1, err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (p *Parser) ParseFile(path string) ([]*ParsedRule, error) {
	var rules []*ParsedRule

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := p.ParseRule(line)
		if err != nil {
			fmt.Printf("Warning: Line %d: %v\n", lineNum, err)
			continue
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func (p *Parser) ParseRule(text string) (*ParsedRule, error) {
	text = strings.TrimSpace(text)
	if text == "" || strings.HasPrefix(text, "#") {
		return nil, ErrEmptyRule
	}

	if !strings.HasSuffix(text, ";)") {
		if strings.HasSuffix(text, ";") {
			text += ")"
		} else if strings.HasSuffix(text, ")") {
			text = text[:len(text)-1] + ";"
		}
	}

	parts := strings.SplitN(text, "(", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidFormat
	}

	header := strings.TrimSpace(parts[0])
	optionsStr := parts[1]

	action, protocol, srcNet, srcPorts, direction, dstNet, dstPorts, err := p.parseHeader(header)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	ruleID, msg, contents, pcreMatches, flow, options, err := p.parseOptions(optionsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	return &ParsedRule{
		RawText:         text,
		Action:          action,
		Protocol:        protocol,
		SrcNet:          srcNet,
		SrcPorts:        srcPorts,
		DstNet:          dstNet,
		DstPorts:        dstPorts,
		Direction:       direction,
		IsBidirectional: direction == "<>",
		RuleID:          ruleID,
		Msg:             msg,
		Contents:        contents,
		PCREMatches:     pcreMatches,
		Flow:            flow,
		Options:         options,
	}, nil
}

func (p *Parser) parseHeader(header string) (action, protocol, srcNet, srcPorts, direction, dstNet, dstPorts string, err error) {
	fields := strings.Fields(header)
	if len(fields) < 6 {
		return "", "", "", "", "", "", "", ErrInvalidFormat
	}

	action = fields[0]
	protocol = fields[1]

	// Handle protocol modifiers like "http", "https", "ftp", "ssh", etc.
	// These are application-layer protocol specifiers, actual transport protocol is TCP
	if isAppProtocol(protocol) {
		protocol = "tcp"
	}

	srcNet = fields[2]
	srcPorts = fields[3]
	direction = fields[4]
	dstNet = fields[5]
	dstPorts = fields[6]

	return action, protocol, srcNet, srcPorts, direction, dstNet, dstPorts, nil
}

func isAppProtocol(proto string) bool {
	appProtocols := map[string]bool{
		"http":   true,
		"https":  true,
		"http2":  true,
		"ftp":    true,
		"ssh":    true,
		"telnet": true,
		"smtp":   true,
		"pop3":   true,
		"imap":   true,
		"dns":    true,
		"rdp":    true,
		"sip":    true,
		"smb":    true,
		"dcerpc": true,
	}
	return appProtocols[strings.ToLower(proto)]
}

func (p *Parser) parseOptions(opts string) (RuleID, string, []ContentMatch, []PCREMatch, string, map[string]string, error) {
	ruleID := RuleID{GID: 1, SID: 0, REV: 1}
	var msg string
	var contents []ContentMatch
	var pcreMatches []PCREMatch
	var flow string
	options := make(map[string]string)

	parts := strings.Split(opts, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.HasPrefix(part, "content:") {
			cm := p.parseContentMatch(part)
			contents = append(contents, cm)
		} else if strings.Contains(part, "msg:") {
			re := regexp.MustCompile(`msg:\s*"([^"]*)"`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				msg = m[1]
			}
		} else if strings.Contains(part, "sid:") {
			re := regexp.MustCompile(`sid:\s*(\d+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				if sid, err := strconv.Atoi(m[1]); err == nil {
					ruleID.SID = sid
				}
			}
		} else if strings.Contains(part, "rev:") {
			re := regexp.MustCompile(`rev:\s*(\d+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				if rev, err := strconv.Atoi(m[1]); err == nil {
					ruleID.REV = rev
				}
			}
		} else if strings.Contains(part, "gid:") {
			re := regexp.MustCompile(`gid:\s*(\d+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				if gid, err := strconv.Atoi(m[1]); err == nil {
					ruleID.GID = gid
				}
			}
		} else if strings.Contains(part, "flow:") {
			re := regexp.MustCompile(`flow:\s*([\w_,]+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				flow = m[1]
			}
		} else if part == "nocase" && len(contents) > 0 {
			contents[len(contents)-1].Nocase = true
		} else if strings.HasPrefix(part, "offset:") && len(contents) > 0 {
			re := regexp.MustCompile(`offset:\s*(\d+)`)
			if m := re.FindStringSubmatch(part); len(m) > 1 {
				if n, err := strconv.Atoi(m[1]); err == nil {
					contents[len(contents)-1].Offset = &n
				}
			}
		} else if strings.HasPrefix(part, "depth:") && len(contents) > 0 {
			re := regexp.MustCompile(`depth:\s*(\d+)`)
			if m := re.FindStringSubmatch(part); len(m) > 1 {
				if n, err := strconv.Atoi(m[1]); err == nil {
					contents[len(contents)-1].Depth = &n
				}
			}
		} else if strings.HasPrefix(part, "distance:") && len(contents) > 0 {
			re := regexp.MustCompile(`distance:\s*(\d+)`)
			if m := re.FindStringSubmatch(part); len(m) > 1 {
				if n, err := strconv.Atoi(m[1]); err == nil {
					contents[len(contents)-1].Distance = &n
				}
			}
		} else if strings.HasPrefix(part, "within:") && len(contents) > 0 {
			re := regexp.MustCompile(`within:\s*(\d+)`)
			if m := re.FindStringSubmatch(part); len(m) > 1 {
				if n, err := strconv.Atoi(m[1]); err == nil {
					contents[len(contents)-1].Within = &n
				}
			}
		} else if strings.HasPrefix(part, "pcre:") {
			pcre := p.parsePCRE(part)
			if pcre.Pattern != "" {
				pcreMatches = append(pcreMatches, pcre)
			}
		} else {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	return ruleID, msg, contents, pcreMatches, flow, options, nil
}

func (p *Parser) parsePCRE(part string) PCREMatch {
	pcre := PCREMatch{}

	re := regexp.MustCompile(`pcre:\s*"/(.+)"/?([imsxAEGRUBPHDMCS]*)"?`)
	m := re.FindStringSubmatch(part)
	if len(m) > 1 {
		full := m[1]
		modifiers := m[2]

		slashIdx := strings.LastIndex(full, "/")
		if slashIdx > 0 {
			pcre.Pattern = full[:slashIdx]
			pcre.Modifiers = full[slashIdx+1:] + modifiers
		} else {
			pcre.Pattern = full
		}
	}

	return pcre
}

func (p *Parser) parseContentMatch(part string) ContentMatch {
	cm := ContentMatch{}

	negated := strings.Contains(part, "content:!") || strings.Contains(part, "content: !")
	cm.IsNegated = negated

	hexRe := regexp.MustCompile(`content:\s*"?\|([^"|]+)\|"?`)
	h := hexRe.FindStringSubmatch(part)
	if len(h) > 1 {
		cm.Raw = decodeContent("|" + h[1] + "|")
		cm.IsHex = true
	} else {
		strRe := regexp.MustCompile(`content:\s*"?([^";]+)"?`)
		m := strRe.FindStringSubmatch(part)
		if len(m) > 1 {
			content := m[1]
			if strings.HasPrefix(content, "!") {
				cm.IsNegated = true
				content = content[1:]
			}
			cm.Raw = decodeContent(content)
		}
	}

	return cm
}

func decodeContent(s string) []byte {
	if strings.HasPrefix(s, "|") && strings.HasSuffix(s, "|") {
		hexStr := strings.ReplaceAll(s[1:len(s)-1], " ", "")
		hexStr = strings.ReplaceAll(hexStr, "\n", "")
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		result := make([]byte, len(hexStr)/2)
		for i := 0; i < len(hexStr); i += 2 {
			b, _ := strconv.ParseUint(hexStr[i:i+2], 16, 8)
			result[i/2] = byte(b)
		}
		return result
	}
	return []byte(s)
}
