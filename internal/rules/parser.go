package rules

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// ParseResult holds parsing results with detailed errors
type ParseResult struct {
	Rules  []*ParsedRule
	Errors []*ParseError
}

func (p *Parser) ParseMulti(text string) (*ParseResult, error) {
	result := &ParseResult{}
	lines := strings.Split(text, "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := p.ParseRule(line)
		if err != nil {
			if parseErr, ok := err.(*ParseError); ok {
				parseErr.Line = lineNum + 1
				parseErr.RuleText = line
				result.Errors = append(result.Errors, parseErr)
			} else {
				result.Errors = append(result.Errors, &ParseError{
					Line:     lineNum + 1,
					Phase:    PhaseFormat,
					Message:  err.Error(),
					RuleText: line,
				})
			}
			continue
		}
		result.Rules = append(result.Rules, rule)
	}
	return result, nil
}

func (p *Parser) ParseFile(path string) (*ParseResult, error) {
	result := &ParseResult{}

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
			if parseErr, ok := err.(*ParseError); ok {
				parseErr.Line = lineNum
				parseErr.RuleText = line
				result.Errors = append(result.Errors, parseErr)
			} else {
				result.Errors = append(result.Errors, &ParseError{
					Line:     lineNum,
					Phase:    PhaseFormat,
					Message:  err.Error(),
					RuleText: line,
				})
			}
			continue
		}
		result.Rules = append(result.Rules, rule)
	}

	return result, nil
}

func (p *Parser) ParseRule(text string) (*ParsedRule, error) {
	text = strings.TrimSpace(text)
	if text == "" || strings.HasPrefix(text, "#") {
		return nil, &ParseError{
			CharOffset: 0,
			Phase:      PhaseFormat,
			Message:    "empty or comment line",
			RuleText:  text,
		}
	}

	origText := text

	if !strings.HasSuffix(text, ";)") {
		if strings.HasSuffix(text, ";") {
			text += ")"
		} else if strings.HasSuffix(text, ")") {
			text = text[:len(text)-1] + ";"
		}
	}

	parts := strings.SplitN(text, "(", 2)
	if len(parts) != 2 {
		return nil, &ParseError{
			CharOffset: strings.Index(text, "("),
			Phase:      PhaseFormat,
			Message:    "missing opening parenthesis for options",
			RuleText:  origText,
		}
	}

	header := strings.TrimSpace(parts[0])
	optionsStr := parts[1]

	headerErr := p.validateHeader(header)
	if headerErr != nil {
		headerErr.RuleText = origText
		return nil, headerErr
	}

	action, protocol, srcNet, srcPorts, direction, dstNet, dstPorts := p.parseHeader(header)

	ruleID, msg, contents, pcreMatches, byteTests, byteJumps, flow, flowbits, noAlert, options, vlanID, optErr := p.parseOptions(optionsStr, origText)
	if optErr != nil {
		return nil, optErr
	}

	// Validate GID/SID ranges
	if err := validateRuleID(ruleID); err != nil {
		return nil, &ParseError{
			CharOffset: 0,
			Phase:      PhaseRuleID,
			Message:    err.Error(),
			RuleText:   origText,
		}
	}

	// Extract IPv6 extension headers from options
	ipv6ExtHeaders := extractIPv6ExtHeaders(options)

	return &ParsedRule{
		RawText:         origText,
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
		ByteTests:       byteTests,
		ByteJumps:       byteJumps,
		Flow:            flow,
		Flowbits:        flowbits,
		NoAlert:         noAlert,
		Options:         options,
		VLANID:          vlanID,
		IPv6ExtHeaders:  ipv6ExtHeaders,
	}, nil
}

func (p *Parser) validateHeader(header string) *ParseError {
	fields := strings.Fields(header)
	if len(fields) < 6 {
		return &ParseError{
			CharOffset: 0,
			Phase:      PhaseHeader,
			Message:    fmt.Sprintf("header has %d fields, expected at least 6 (action protocol src_net src_ports direction dst_net dst_ports)", len(fields)),
			Context:    header,
		}
	}

	// Validate action
	validActions := map[string]bool{"alert": true, "log": true, "pass": true, "drop": true, "reject": true, "sdrop": true, "activate": true, "dynamic": true}
	if !validActions[fields[0]] {
		return &ParseError{
			CharOffset: 0,
			Phase:      PhaseHeader,
			Message:    fmt.Sprintf("invalid action '%s', expected one of: alert, log, pass, drop, reject, sdrop, activate, dynamic", fields[0]),
			Context:    header,
		}
	}

	// Validate direction
	validDirections := map[string]bool{"->": true, "<>": true, "<-": true}
	if !validDirections[fields[4]] {
		return &ParseError{
			CharOffset: strings.Index(header, fields[4]),
			Phase:      PhaseHeader,
			Message:    fmt.Sprintf("invalid direction '%s', expected '->' or '<>'", fields[4]),
			Context:    header,
		}
	}

	return nil
}

func (p *Parser) parseHeader(header string) (action, protocol, srcNet, srcPorts, direction, dstNet, dstPorts string) {
	fields := strings.Fields(header)

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

	return action, protocol, srcNet, srcPorts, direction, dstNet, dstPorts
}

func isAppProtocol(proto string) bool {
	appProtocols := map[string]bool{
		"http":    true,
		"https":   true,
		"http2":   true,
		"ftp":     true,
		"ssh":     true,
		"telnet":  true,
		"smtp":    true,
		"pop3":    true,
		"imap":    true,
		"dns":     true,
		"rdp":     true,
		"sip":     true,
		"smb":     true,
		"dcerpc":  true,
		"ntp":     true,
		"snmp":    true,
		"rtsp":    true,
		"tftp":    true,
		"ldap":    true,
		"irc":     true,
		"mysql":   true,
		"postgresql": true,
		"mssql":   true,
		"oracle":  true,
	}
	return appProtocols[strings.ToLower(proto)]
}

func (p *Parser) parseOptions(opts string, ruleText string) (RuleID, string, []ContentMatch, []PCREMatch, []ByteTest, []ByteJump, string, []Flowbit, bool, map[string]string, uint16, error) {
	ruleID := RuleID{GID: 1, SID: 0, REV: 1}
	var msg string
	var contents []ContentMatch
	var pcreMatches []PCREMatch
	var byteTests []ByteTest
	var byteJumps []ByteJump
	var flow string
	var flowbits []Flowbit
	noAlert := false
	options := make(map[string]string)
	var pendingNocase bool
	var vlanID uint16

	errRet := func(err *ParseError) (RuleID, string, []ContentMatch, []PCREMatch, []ByteTest, []ByteJump, string, []Flowbit, bool, map[string]string, uint16, error) {
		return ruleID, msg, contents, pcreMatches, byteTests, byteJumps, flow, flowbits, noAlert, options, vlanID, err
	}

	parts := strings.Split(opts, ";")
	for partIdx, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Calculate character offset in original rule
		offset := strings.Index(ruleText, part)
		if offset < 0 {
			offset = 0
		}

		if strings.HasPrefix(part, "content:") {
			cm, cmErr := p.parseContentMatch(part)
			if cmErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhaseContent,
					Message:    cmErr.Error(),
					RuleText:   ruleText,
				})
			}
			if pendingNocase {
				cm.Nocase = true
				pendingNocase = false
			}
			contents = append(contents, cm)
		} else if part == "nocase" {
			if len(contents) > 0 {
				contents[len(contents)-1].Nocase = true
			} else {
				pendingNocase = true
			}
		} else if strings.Contains(part, "msg:") {
			re := regexp.MustCompile(`msg:\s*"([^"]*)"`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				msg = m[1]
			} else {
				return errRet(&ParseError{
					CharOffset: offset + strings.Index(part, "msg:"),
					Phase:      PhaseOptions,
					Message:    "msg option missing closing quote",
					RuleText:   ruleText,
				})
			}
		} else if strings.Contains(part, "sid:") {
			re := regexp.MustCompile(`sid:\s*(\d+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				if sid, err := strconv.Atoi(m[1]); err == nil {
					ruleID.SID = sid
				}
			} else {
				return errRet(&ParseError{
					CharOffset: offset + strings.Index(part, "sid:"),
					Phase:      PhaseRuleID,
					Message:    "sid option has invalid numeric value",
					RuleText:   ruleText,
				})
			}
		} else if strings.Contains(part, "rev:") {
			re := regexp.MustCompile(`rev:\s*(\d+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				if rev, err := strconv.Atoi(m[1]); err == nil {
					ruleID.REV = rev
				}
			} else {
				return errRet(&ParseError{
					CharOffset: offset + strings.Index(part, "rev:"),
					Phase:      PhaseRuleID,
					Message:    "rev option has invalid numeric value",
					RuleText:   ruleText,
				})
			}
		} else if strings.Contains(part, "gid:") {
			re := regexp.MustCompile(`gid:\s*(\d+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				if gid, err := strconv.Atoi(m[1]); err == nil {
					ruleID.GID = gid
				}
			} else {
				return errRet(&ParseError{
					CharOffset: offset + strings.Index(part, "gid:"),
					Phase:      PhaseRuleID,
					Message:    "gid option has invalid numeric value",
					RuleText:   ruleText,
				})
			}
		} else if strings.Contains(part, "flow:") && !strings.Contains(part, "flowbits:") {
			re := regexp.MustCompile(`flow:\s*([\w_,]+)`)
			m := re.FindStringSubmatch(part)
			if len(m) > 1 {
				flow = m[1]
				if err := p.validateFlow(flow); err != nil {
					return errRet(&ParseError{
						CharOffset: offset + strings.Index(part, "flow:"),
						Phase:      PhaseFlow,
						Message:    err.Error(),
						RuleText:   ruleText,
					})
				}
			} else {
				return errRet(&ParseError{
					CharOffset: offset + strings.Index(part, "flow:"),
					Phase:      PhaseFlow,
					Message:    "flow option has invalid value",
					RuleText:   ruleText,
				})
			}
		} else if strings.HasPrefix(part, "flowbits:") {
			fb, fbErr := p.parseFlowbits(part)
			if fbErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhaseOptions,
					Message:    fbErr.Error(),
					RuleText:   ruleText,
				})
			}
			if fb.Op == FlowbitNoAlert {
				noAlert = true
			} else {
				flowbits = append(flowbits, fb)
			}
		} else if strings.HasPrefix(part, "threshold:") {
			options["threshold"] = part
		} else if strings.HasPrefix(part, "rate_filter:") {
			options["rate_filter"] = part
		} else if strings.HasPrefix(part, "detection_filter:") {
			// Validate detection_filter syntax
			_, dfErr := p.parseDetectionFilter(part)
			if dfErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhaseOptions,
					Message:    dfErr.Error(),
					RuleText:   ruleText,
				})
			}
			options["detection_filter"] = part
		} else if strings.HasPrefix(part, "dsize:") {
			// Validate dsize syntax
			_, dsErr := p.parseDSize(part)
			if dsErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhaseOptions,
					Message:    dsErr.Error(),
					RuleText:   ruleText,
				})
			}
			options["dsize"] = part
		} else if strings.HasPrefix(part, "sameip") {
			options["sameip"] = "true"
		} else if strings.HasPrefix(part, "uricontent:") {
			// Store uricontent - maps to content for URI matching
			options["uricontent"] = strings.TrimPrefix(part, "uricontent:")
		} else if part == "http_cookie" || part == "http_header" || part == "http_method" ||
			part == "http_stat_code" || part == "http_stat_msg" || part == "http_uri" ||
			part == "http_client_body" || part == "http_raw_cookie" || part == "http_raw_header" ||
			part == "http_raw_method" || part == "http_raw_stat_code" || part == "http_raw_stat_msg" ||
			part == "http_raw_uri" || part == "http_version" || part == "http_raw_body" ||
			part == "http_trailer" || part == "http_raw_trailer" {
			// HTTP modifiers without values
			options[part] = "true"
		} else if strings.HasPrefix(part, "http_cookie:") || strings.HasPrefix(part, "http_header:") ||
			strings.HasPrefix(part, "http_method:") || strings.HasPrefix(part, "http_stat_code:") ||
			strings.HasPrefix(part, "http_stat_msg:") || strings.HasPrefix(part, "http_uri:") ||
			strings.HasPrefix(part, "http_client_body:") || strings.HasPrefix(part, "http_raw_cookie:") ||
			strings.HasPrefix(part, "http_raw_header:") || strings.HasPrefix(part, "http_raw_method:") ||
			strings.HasPrefix(part, "http_raw_stat_code:") || strings.HasPrefix(part, "http_raw_stat_msg:") ||
			strings.HasPrefix(part, "http_raw_uri:") || strings.HasPrefix(part, "http_version:") ||
			strings.HasPrefix(part, "http_raw_body:") || strings.HasPrefix(part, "http_trailer:") ||
			strings.HasPrefix(part, "http_raw_trailer:") || strings.HasPrefix(part, "uricontent:") {
			// Store HTTP modifier options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "flags:") {
			// Store TCP flags option
			options["flags"] = strings.TrimPrefix(part, "flags:")
		} else if strings.HasPrefix(part, "stream_reassemble:") || strings.HasPrefix(part, "stream_size:") {
			// Store stream options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "ipv6-options:") {
			// Store IPv6 extension header options
			options["ipv6-options"] = strings.TrimPrefix(part, "ipv6-options:")
		} else if strings.HasPrefix(part, "hopopts:") {
			options["hopopts"] = strings.TrimPrefix(part, "hopopts:")
		} else if strings.HasPrefix(part, "dstopts:") {
			options["dstopts"] = strings.TrimPrefix(part, "dstopts:")
		} else if strings.HasPrefix(part, "routing:") {
			options["routing"] = strings.TrimPrefix(part, "routing:")
		} else if strings.HasPrefix(part, "fragment:") {
			options["fragment"] = strings.TrimPrefix(part, "fragment:")
		} else if strings.HasPrefix(part, "ah:") {
			options["ah"] = strings.TrimPrefix(part, "ah:")
		} else if strings.HasPrefix(part, "esp:") {
			options["esp"] = strings.TrimPrefix(part, "esp:")
		} else if strings.HasPrefix(part, "mip6:") {
			options["mip6"] = strings.TrimPrefix(part, "mip6:")
		} else if strings.HasPrefix(part, "ttl:") || strings.HasPrefix(part, "tos:") ||
			strings.HasPrefix(part, "id:") || strings.HasPrefix(part, "ipopts:") ||
			strings.HasPrefix(part, "seq:") || strings.HasPrefix(part, "ack:") ||
			strings.HasPrefix(part, "window:") || strings.HasPrefix(part, "itype:") ||
			strings.HasPrefix(part, "icode:") || strings.HasPrefix(part, "icmp_id:") ||
			strings.HasPrefix(part, "icmp_seq:") {
			// Store IP/ICMP layer options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "activates:") || strings.HasPrefix(part, "activated_by:") || strings.HasPrefix(part, "dynamic:") {
			// Store activate/dynamic rule chaining options
			options[strings.TrimSpace(strings.Split(part, ":")[0])] = strings.TrimSpace(strings.Join(strings.SplitN(part, ":", 2)[1:], ":"))
		} else if part == "rawbytes" || part == "fast_pattern" || part == "norm" {
			// Content modifiers without values
			options[part] = "true"
		} else if strings.HasPrefix(part, "replace:") {
			// Replace option (inline mode)
			options["replace"] = strings.TrimPrefix(part, "replace:")
		} else if strings.HasPrefix(part, "tag:") {
			// Session tagging option
			options["tag"] = strings.TrimPrefix(part, "tag:")
		} else if strings.HasPrefix(part, "logto:") {
			// Log to alternative file
			options["logto"] = strings.TrimPrefix(part, "logto:")
		} else if strings.HasPrefix(part, "session:") {
			// Session logging option
			options["session"] = strings.TrimPrefix(part, "session:")
		} else if strings.HasPrefix(part, "resp:") {
			// Reactive response option
			options["resp"] = strings.TrimPrefix(part, "resp:")
		} else if strings.HasPrefix(part, "react:") {
			// Reactive blocking option
			options["react"] = strings.TrimPrefix(part, "react:")
		} else if part == "pkt_data" || part == "raw_data" ||
			part == "file_data" || part == "base64_data" || part == "pkt_header" {
			// Data detection points without values
			options[part] = "true"
		} else if strings.HasPrefix(part, "pkt_data:") || strings.HasPrefix(part, "raw_data:") ||
			strings.HasPrefix(part, "file_data:") || strings.HasPrefix(part, "base64_data:") {
			// Data detection points with options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "file_type:") {
			options["file_type"] = strings.TrimPrefix(part, "file_type:")
		} else if strings.HasPrefix(part, "file_id:") {
			options["file_id"] = strings.TrimPrefix(part, "file_id:")
		} else if strings.HasPrefix(part, "file_signature:") {
			options["file_signature"] = strings.TrimPrefix(part, "file_signature:")
		} else if strings.HasPrefix(part, "base64_decode:") {
			options["base64_decode"] = strings.TrimPrefix(part, "base64_decode:")
		} else if strings.HasPrefix(part, "classtype:") {
			// Classification type
			options["classtype"] = strings.TrimPrefix(part, "classtype:")
		} else if strings.HasPrefix(part, "priority:") {
			// Rule priority
			options["priority"] = strings.TrimPrefix(part, "priority:")
		} else if strings.HasPrefix(part, "reference:") {
			// External reference
			options["reference"] = strings.TrimPrefix(part, "reference:")
		} else if strings.HasPrefix(part, "metadata:") {
			// Rule metadata
			options["metadata"] = strings.TrimPrefix(part, "metadata:")
		} else if strings.HasPrefix(part, "service:") {
			// Service identification
			options["service"] = strings.TrimPrefix(part, "service:")
		} else if strings.HasPrefix(part, "dce_smb:") || strings.HasPrefix(part, "dce_http_proxy:") ||
			strings.HasPrefix(part, "dce_http_inspect:") || strings.HasPrefix(part, "dce_asn1:") {
			// DCE/RPC preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "sip:") || strings.HasPrefix(part, "sip_method:") ||
			strings.HasPrefix(part, "sip_stat_code:") || strings.HasPrefix(part, "sip_header:") ||
			strings.HasPrefix(part, "sip_body:") {
			// SIP preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "gtp:") || strings.HasPrefix(part, "gtp_type:") ||
			strings.HasPrefix(part, "gtp_info:") || strings.HasPrefix(part, "gtp_version:") {
			// GTP preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "ssh:") || strings.HasPrefix(part, "ssh_proto:") ||
			strings.HasPrefix(part, "ssh_proVersion:") || strings.HasPrefix(part, "ssh_encryption:") ||
			strings.HasPrefix(part, "ssh_hassh:") || strings.HasPrefix(part, "ssh_hassh_string:") {
			// SSH preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "ssl:") || strings.HasPrefix(part, "ssl_state:") ||
			strings.HasPrefix(part, "ssl_version:") || strings.HasPrefix(part, "ssl_cert:") ||
			strings.HasPrefix(part, "ssn:") {
			// SSL/TLS preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "modbus:") || strings.HasPrefix(part, "dnp3:") ||
			strings.HasPrefix(part, "dnp3_func:") || strings.HasPrefix(part, "dnp3_ind:") ||
			strings.HasPrefix(part, "dnp3_obj:") || strings.HasPrefix(part, "iec104:") ||
			strings.HasPrefix(part, "iec104_type:") || strings.HasPrefix(part, "iec104_func:") {
			// Industrial control protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "enip:") || strings.HasPrefix(part, "enip_cmd:") ||
			strings.HasPrefix(part, "enip_plc:") || strings.HasPrefix(part, "bacnet:") ||
			strings.HasPrefix(part, "bacnet_obj:") || strings.HasPrefix(part, "bacnet_conf:") {
			// ENIP and BACnet options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "dns:") || strings.HasPrefix(part, "dns_query:") ||
			strings.HasPrefix(part, "dns_response:") || strings.HasPrefix(part, "dns_query_name:") {
			// DNS protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "smtp:") || strings.HasPrefix(part, "smtp_command:") ||
			strings.HasPrefix(part, "smtp_data:") || strings.HasPrefix(part, "smtp_header:") ||
			strings.HasPrefix(part, "smtp_body:") || strings.HasPrefix(part, "smtp_rav:") {
			// SMTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "ftp:") || strings.HasPrefix(part, "ftp_command:") ||
			strings.HasPrefix(part, "ftp_response:") || strings.HasPrefix(part, "ftp_stat:") {
			// FTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "telnet:") || strings.HasPrefix(part, "telnet_cmd:") ||
			strings.HasPrefix(part, "telnet_data:") {
			// Telnet protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "ssh:") || strings.HasPrefix(part, "ssh_proto:") ||
			strings.HasPrefix(part, "ssh_proVersion:") || strings.HasPrefix(part, "ssh_encryption:") ||
			strings.HasPrefix(part, "ssh_hassh:") || strings.HasPrefix(part, "ssh_hassh_string:") {
			// SSH protocol options (already partially handled above)
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "ssl:") || strings.HasPrefix(part, "ssl_version:") ||
			strings.HasPrefix(part, "ssl_state:") || strings.HasPrefix(part, "ssl_cert:") ||
			strings.HasPrefix(part, "ssn:") {
			// SSL/TLS options (already handled above)
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "irc:") || strings.HasPrefix(part, "irc_channel:") ||
			strings.HasPrefix(part, "irc_nick:") || strings.HasPrefix(part, "irc_command:") ||
			strings.HasPrefix(part, "irc_message:") {
			// IRC protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "mysql:") || strings.HasPrefix(part, "mysql_query:") ||
			strings.HasPrefix(part, "mysql_command:") || strings.HasPrefix(part, "pgsql:") ||
			strings.HasPrefix(part, "postgres:") || strings.HasPrefix(part, "oracle:") ||
			strings.HasPrefix(part, "mssql:") {
			// Database protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "msrpc:") || strings.HasPrefix(part, "msrpc_char:") ||
			strings.HasPrefix(part, "msrpc_string:") || strings.HasPrefix(part, "msrpc_conf:") {
			// MSRPC options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "netbios:") || strings.HasPrefix(part, "netbios_name:") ||
			strings.HasPrefix(part, "smb:") || strings.HasPrefix(part, "smb_tree:") ||
			strings.HasPrefix(part, "smb_share:") || strings.HasPrefix(part, "cifs:") {
			// NetBIOS/SMB/CIFS options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "rdp:") || strings.HasPrefix(part, "rdp_cookie:") ||
			strings.HasPrefix(part, "vnc:") || strings.HasPrefix(part, "vnc_rfb:") {
			// RDP/VNC options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, " reputation:") || strings.HasPrefix(part, "localid:") ||
			strings.HasPrefix(part, "skinny:") || strings.HasPrefix(part, "h323:") ||
			strings.HasPrefix(part, "rpc:") || strings.HasPrefix(part, "netflow:") {
			// Other preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "msg:") {
			// Already handled above, but catch any remaining
			// Skip - msg is already parsed
		} else if strings.HasPrefix(part, "sid:") {
			// Already handled above - Skip
		} else if strings.HasPrefix(part, "rev:") {
			// Already handled above - Skip
		} else if strings.HasPrefix(part, "gid:") {
			// Already handled above - Skip
		} else if strings.HasPrefix(part, "patters:") || strings.HasPrefix(part, "patters_file:") ||
			strings.HasPrefix(part, "patters_group:") {
			// Sensitive data detection options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if strings.HasPrefix(part, "byte_extract:") || strings.HasPrefix(part, "byte_math:") {
			// Byte extract and math options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "isdataat:") {
			// Isdataat option
			options["isdataat"] = strings.TrimPrefix(part, "isdataat:")
		} else if part == "isdataat" {
			// isdataat without value
			options["isdataat"] = "true"
		} else if strings.HasPrefix(part, "pctilealerts:") {
			// Percentile alerting option
			options["pctilealerts"] = strings.TrimPrefix(part, "pctilealerts:")
		} else if strings.HasPrefix(part, "base64_match:") || strings.HasPrefix(part, "base64_decode bytes:") {
			// Base64 matching options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			}
		} else if strings.HasPrefix(part, "byte_order:") || strings.HasPrefix(part, "endian:") ||
			strings.HasPrefix(part, "string:") {
			// Byte order and encoding options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[kv[0]] = kv[1]
			} else {
				options[part] = "true"
			}
		} else if part == "rawip" || part == "ip_proto" {
			// Protocol modifiers without values
			options[part] = "true"
		} else if strings.HasPrefix(part, "ip_proto:") {
			// IP protocol number check
			options["ip_proto"] = strings.TrimPrefix(part, "ip_proto:")
		} else if strings.HasPrefix(part, "tcp_flags:") {
			// TCP flags check (F,S,R,P,A,U,E,C)
			options["tcp_flags"] = strings.TrimPrefix(part, "tcp_flags:")
		} else if strings.HasPrefix(part, "seq:") {
			// TCP sequence number
			options["seq"] = strings.TrimPrefix(part, "seq:")
		} else if strings.HasPrefix(part, "ack:") {
			// TCP acknowledgment number
			options["ack"] = strings.TrimPrefix(part, "ack:")
		} else if strings.HasPrefix(part, "window:") {
			// TCP window size
			options["window"] = strings.TrimPrefix(part, "window:")
		} else if strings.HasPrefix(part, "itype:") {
			// ICMP type
			options["itype"] = strings.TrimPrefix(part, "itype:")
		} else if strings.HasPrefix(part, "icode:") {
			// ICMP code
			options["icode"] = strings.TrimPrefix(part, "icode:")
		} else if strings.HasPrefix(part, "icmp_id:") {
			// ICMP ID
			options["icmp_id"] = strings.TrimPrefix(part, "icmp_id:")
		} else if strings.HasPrefix(part, "icmp_seq:") {
			// ICMP sequence
			options["icmp_seq"] = strings.TrimPrefix(part, "icmp_seq:")
		} else if strings.HasPrefix(part, "ip_id:") {
			// IP ID
			options["ip_id"] = strings.TrimPrefix(part, "ip_id:")
		} else if strings.HasPrefix(part, "ip_len:") {
			// IP length
			options["ip_len"] = strings.TrimPrefix(part, "ip_len:")
		} else if strings.HasPrefix(part, "ip_tos:") {
			// IP TOS
			options["ip_tos"] = strings.TrimPrefix(part, "ip_tos:")
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
			pcre, pcreErr := p.parsePCRE(part)
			if pcreErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhasePCRE,
					Message:    pcreErr.Error(),
					RuleText:   ruleText,
				})
			}
			if pcre.Pattern != "" {
				pcreMatches = append(pcreMatches, pcre)
			}
		} else if strings.HasPrefix(part, "vlan:") {
			re := regexp.MustCompile(`vlan:\s*(\d+)`)
			if m := re.FindStringSubmatch(part); len(m) > 1 {
				if v, err := strconv.ParseUint(m[1], 10, 16); err == nil {
					vlanID = uint16(v)
				}
			} else {
				return errRet(&ParseError{
					CharOffset: offset + strings.Index(part, "vlan:"),
					Phase:      PhaseVLAN,
					Message:    "vlan option has invalid value (must be 0-65535)",
					RuleText:   ruleText,
				})
			}
		} else if strings.HasPrefix(part, "byte_test:") {
			bt, btErr := p.parseByteTest(part)
			if btErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhaseOptions,
					Message:    btErr.Error(),
					RuleText:   ruleText,
				})
			}
			byteTests = append(byteTests, bt)
		} else if strings.HasPrefix(part, "byte_jump:") {
			bj, bjErr := p.parseByteJump(part)
			if bjErr != nil {
				return errRet(&ParseError{
					CharOffset: offset,
					Phase:      PhaseOptions,
					Message:    bjErr.Error(),
					RuleText:   ruleText,
				})
			}
			byteJumps = append(byteJumps, bj)
		} else if strings.HasPrefix(part, "asn1:") {
			// ASN.1 detection options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["asn1"] = kv[1]
			} else {
				options["asn1"] = "true"
			}
		} else if strings.HasPrefix(part, "cvs:") {
			// CVS protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["cvs"] = kv[1]
			} else {
				options["cvs"] = "true"
			}
		} else if strings.HasPrefix(part, "kerberos:") || strings.HasPrefix(part, "krb5:") {
			// Kerberos protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["kerberos"] = kv[1]
			} else {
				options["kerberos"] = "true"
			}
		} else if strings.HasPrefix(part, "nfs:") || strings.HasPrefix(part, "nfs_procedure:") ||
			strings.HasPrefix(part, "nfs_version:") {
			// NFS protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["nfs"] = kv[1]
			} else {
				options["nfs"] = "true"
			}
		} else if strings.HasPrefix(part, "ntp:") || strings.HasPrefix(part, "ntp_command:") ||
			strings.HasPrefix(part, "ntp_mode:") || strings.HasPrefix(part, "ntp_version:") {
			// NTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ntp"] = kv[1]
			} else {
				options["ntp"] = "true"
			}
		} else if strings.HasPrefix(part, "snmp:") || strings.HasPrefix(part, "snmp_community:") ||
			strings.HasPrefix(part, "snmp_version:") || strings.HasPrefix(part, "snmp_pdu_type:") {
			// SNMP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["snmp"] = kv[1]
			} else {
				options["snmp"] = "true"
			}
		} else if strings.HasPrefix(part, "tftp:") || strings.HasPrefix(part, "tftp_mode:") ||
			strings.HasPrefix(part, "tftp_opcode:") {
			// TFTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["tftp"] = kv[1]
			} else {
				options["tftp"] = "true"
			}
		} else if strings.HasPrefix(part, "sip:") || strings.HasPrefix(part, "sip_header:") ||
			strings.HasPrefix(part, "sip_body:") || strings.HasPrefix(part, "sip_method:") ||
			strings.HasPrefix(part, "sip_stat_code:") || strings.HasPrefix(part, "sip_stat_msg:") ||
			strings.HasPrefix(part, "sip_uri:") || strings.HasPrefix(part, "sip_from:") ||
			strings.HasPrefix(part, "sip_to:") || strings.HasPrefix(part, "sip_via:") {
			// SIP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["sip"] = kv[1]
			} else {
				options["sip"] = "true"
			}
		} else if strings.HasPrefix(part, "gtp:") || strings.HasPrefix(part, "gtp_type:") ||
			strings.HasPrefix(part, "gtp_info:") || strings.HasPrefix(part, "gtp_version:") {
			// GTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["gtp"] = kv[1]
			} else {
				options["gtp"] = "true"
			}
		} else if strings.HasPrefix(part, "dce_smb:") || strings.HasPrefix(part, "dce_opnum:") ||
			strings.HasPrefix(part, "dce_stub_data:") {
			// DCE/RPC SMB options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["dce_smb"] = kv[1]
			} else {
				options["dce_smb"] = "true"
			}
		} else if strings.HasPrefix(part, "dnp3:") || strings.HasPrefix(part, "dnp3_func:") ||
			strings.HasPrefix(part, "dnp3_ind:") || strings.HasPrefix(part, "dnp3_obj:") {
			// DNP3 protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["dnp3"] = kv[1]
			} else {
				options["dnp3"] = "true"
			}
		} else if strings.HasPrefix(part, "iec104:") || strings.HasPrefix(part, "iec104_type:") ||
			strings.HasPrefix(part, "iec104_data:") {
			// IEC 60870-5-104 protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["iec104"] = kv[1]
			} else {
				options["iec104"] = "true"
			}
		} else if strings.HasPrefix(part, "enip:") || strings.HasPrefix(part, "enip_command:") ||
			strings.HasPrefix(part, "enip_plc:") || strings.HasPrefix(part, "enip_cip_ext:") {
			// EtherNet/IP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["enip"] = kv[1]
			} else {
				options["enip"] = "true"
			}
		} else if strings.HasPrefix(part, "bacnet:") || strings.HasPrefix(part, "bacnet_apdu_type:") ||
			strings.HasPrefix(part, "bacnet_conf:") || strings.HasPrefix(part, "bacnet_data:") ||
			strings.HasPrefix(part, "bacnet_dst:") || strings.HasPrefix(part, "bacnet_function:") ||
			strings.HasPrefix(part, "bacnet_src:") {
			// BACnet protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["bacnet"] = kv[1]
			} else {
				options["bacnet"] = "true"
			}
		} else if strings.HasPrefix(part, "modbus:") || strings.HasPrefix(part, "modbus_func:") ||
			strings.HasPrefix(part, "modbus_data:") {
			// Modbus protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["modbus"] = kv[1]
			} else {
				options["modbus"] = "true"
			}
		} else if strings.HasPrefix(part, "content_decode:") || strings.HasPrefix(part, "content_decode_ratio:") {
			// Content decoding options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["content_decode"] = kv[1]
			} else {
				options["content_decode"] = "true"
			}
		} else if part == "file_data" || strings.HasPrefix(part, "file_data:") {
			// File data option
			if strings.Contains(part, ":") {
				options["file_data"] = strings.TrimPrefix(part, "file_data:")
			} else {
				options["file_data"] = "true"
			}
		} else if part == "packet_data" || strings.HasPrefix(part, "packet_data:") {
			// Packet data option
			if strings.Contains(part, ":") {
				options["packet_data"] = strings.TrimPrefix(part, "packet_data:")
			} else {
				options["packet_data"] = "true"
			}
		} else if strings.HasPrefix(part, "http_raw_cookie:") || strings.HasPrefix(part, "http_raw_header:") ||
			strings.HasPrefix(part, "http_raw_request:") || strings.HasPrefix(part, "http_raw_response:") ||
			strings.HasPrefix(part, "http_raw_uri:") {
			// HTTP raw data options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["http_raw"] = kv[1]
			} else {
				options["http_raw"] = "true"
			}
		} else if strings.HasPrefix(part, "http_stat_code:") || strings.HasPrefix(part, "http_stat_msg:") {
			// HTTP status code/message options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["http_stat"] = kv[1]
			} else {
				options["http_stat"] = "true"
			}
		} else if strings.HasPrefix(part, "ssl_version:") || strings.HasPrefix(part, "ssl_state:") {
			// SSL/TLS options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ssl"] = kv[1]
			} else {
				options["ssl"] = "true"
			}
		} else if strings.HasPrefix(part, "urilen:") || strings.HasPrefix(part, "urilen_raw:") {
			// URI length options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["urilen"] = kv[1]
			} else {
				options["urilen"] = "true"
			}
		} else if strings.HasPrefix(part, "replace:") {
			// Content replacement (for dynamic rules)
			options["replace"] = strings.TrimPrefix(part, "replace:")
		} else if strings.HasPrefix(part, "activates:") {
			// Dynamic rule activation
			options["activates"] = strings.TrimPrefix(part, "activates:")
		} else if strings.HasPrefix(part, "activated_by:") {
			// Dynamic rule reference
			options["activated_by"] = strings.TrimPrefix(part, "activated_by:")
		} else if strings.HasPrefix(part, "count:") {
			// Dynamic rule count
			options["count"] = strings.TrimPrefix(part, "count:")
		} else if strings.HasPrefix(part, "tag:") {
			// Session tagging
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["tag"] = kv[1]
			} else {
				options["tag"] = "true"
			}
		} else if strings.HasPrefix(part, "metadata:") {
			// Rule metadata
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["metadata"] = kv[1]
			} else {
				options["metadata"] = "true"
			}
		} else if strings.HasPrefix(part, "config:") {
			// Preprocessor configuration
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["config"] = kv[1]
			} else {
				options["config"] = "true"
			}
		} else if strings.HasPrefix(part, "soid:") {
			// Source IP or destination
			options["soid"] = strings.TrimPrefix(part, "soid:")
		} else if part == "sameip" || strings.HasPrefix(part, "sameip:") {
			// Same IP option
			if strings.Contains(part, ":") {
				options["sameip"] = strings.TrimPrefix(part, "sameip:")
			} else {
				options["sameip"] = "true"
			}
		} else if strings.HasPrefix(part, "ttl:") {
			// TTL option
			options["ttl"] = strings.TrimPrefix(part, "ttl:")
		} else if strings.HasPrefix(part, "tos:") {
			// TOS option
			options["tos"] = strings.TrimPrefix(part, "tos:")
		} else if strings.HasPrefix(part, "fragbits:") {
			// Fragment bits
			options["fragbits"] = strings.TrimPrefix(part, "fragbits:")
		} else if strings.HasPrefix(part, "fragoffset:") {
			// Fragment offset
			options["fragoffset"] = strings.TrimPrefix(part, "fragoffset:")
		} else if strings.HasPrefix(part, "icmp_id:") {
			// ICMP ID (already added but catch all variations)
			options["icmp_id"] = strings.TrimPrefix(part, "icmp_id:")
		} else if strings.HasPrefix(part, "icmp_seq:") {
			// ICMP sequence (already added)
			options["icmp_seq"] = strings.TrimPrefix(part, "icmp_seq:")
		} else if strings.HasPrefix(part, "service:") {
			// Service matching
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["service"] = kv[1]
			} else {
				options["service"] = "true"
			}
		} else if strings.HasPrefix(part, "appids:") || strings.HasPrefix(part, "appid:") {
			// Application ID
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["appid"] = kv[1]
			} else {
				options["appid"] = "true"
			}
		} else if strings.HasPrefix(part, "vs:") {
			// Virtual server
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["vs"] = kv[1]
			} else {
				options["vs"] = "true"
			}
		} else if strings.HasPrefix(part, "dsize:") {
			// Payload size - already handled but catch any variations
			_, dsErr := p.parseDSize(part)
			if dsErr == nil {
				options["dsize"] = strings.TrimPrefix(part, "dsize:")
			}
		} else if strings.HasPrefix(part, "flowbits:") {
			// Flowbits - already handled above, but catch any remaining
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["flowbits"] = kv[1]
			}
		} else if strings.HasPrefix(part, "threshold:") {
			// Threshold - already handled
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["threshold"] = kv[1]
			}
		} else if strings.HasPrefix(part, "rate_filter:") {
			// Rate filter - already handled
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["rate_filter"] = kv[1]
			}
		} else if strings.HasPrefix(part, "stream_reassemble:") || strings.HasPrefix(part, "stream_size:") {
			// Stream options - already handled
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["stream"] = kv[1]
			} else {
				options["stream"] = "true"
			}
		} else if strings.HasPrefix(part, "detection_filter:") {
			// Detection filter - already handled
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["detection_filter"] = kv[1]
			}
		} else if part == "nopcre" || part == "no_pcre" {
			// No PCRE option
			options["nopcre"] = "true"
		} else if part == "noalert" {
			// No alert option - already handled but catch any remaining
			noAlert = true
		} else if strings.HasPrefix(part, "http_cookie:") || strings.HasPrefix(part, "http_header:") ||
			strings.HasPrefix(part, "http_method:") || strings.HasPrefix(part, "http_uri:") ||
			strings.HasPrefix(part, "http_user_agent:") || strings.HasPrefix(part, "http_host:") ||
			strings.HasPrefix(part, "http_referer:") {
			// HTTP modifiers - already handled but catch any remaining
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				key := strings.SplitN(kv[0], "_", 2)[1] // get "cookie", "header", etc.
				options["http_"+key] = kv[1]
			}
		} else if strings.HasPrefix(part, "base64_data:") || strings.HasPrefix(part, "base64_decode:") {
			// Base64 decoding options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["base64_data"] = kv[1]
			} else {
				options["base64_data"] = "true"
			}
		} else if strings.HasPrefix(part, "xbits:") {
			// Extended bits (flowbits extension)
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["xbits"] = kv[1]
			} else {
				options["xbits"] = "true"
			}
		} else if strings.HasPrefix(part, "file:") || strings.HasPrefix(part, "file_type:") ||
			strings.HasPrefix(part, "file_name:") {
			// File matching options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["file"] = kv[1]
			} else {
				options["file"] = "true"
			}
		} else if strings.HasPrefix(part, "lua:") || strings.HasPrefix(part, "lua_script:") {
			// Lua script options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["lua"] = kv[1]
			} else {
				options["lua"] = "true"
			}
		} else if part == "pkt_data" || strings.HasPrefix(part, "pkt_data:") {
			// Packet data option
			if strings.Contains(part, ":") {
				options["pkt_data"] = strings.TrimPrefix(part, "pkt_data:")
			} else {
				options["pkt_data"] = "true"
			}
		} else if strings.HasPrefix(part, "gid:") {
			// GID - already handled above
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["gid"] = kv[1]
			}
		} else if strings.HasPrefix(part, "ssh:") || strings.HasPrefix(part, "ssh_proto:") ||
			strings.HasPrefix(part, "ssh_version:") || strings.HasPrefix(part, "ssh_payload:") ||
			strings.HasPrefix(part, "ssh_software:") {
			// SSH protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ssh"] = kv[1]
			} else {
				options["ssh"] = "true"
			}
		} else if strings.HasPrefix(part, "ssl:") || strings.HasPrefix(part, "ssl_state:") ||
			strings.HasPrefix(part, "ssl_version:") || strings.HasPrefix(part, "ssl_cert:") ||
			strings.HasPrefix(part, "ssl_chain:") || strings.HasPrefix(part, "ssl_banner:") {
			// SSL/TLS options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ssl"] = kv[1]
			} else {
				options["ssl"] = "true"
			}
		} else if strings.HasPrefix(part, "radius:") || strings.HasPrefix(part, "radius_code:") ||
			strings.HasPrefix(part, "radius_type:") || strings.HasPrefix(part, "radius_attr:") {
			// RADIUS protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["radius"] = kv[1]
			} else {
				options["radius"] = "true"
			}
		} else if strings.HasPrefix(part, "wap:") || strings.HasPrefix(part, "wap_wsp:") ||
			strings.HasPrefix(part, "wap_wsp_method:") || strings.HasPrefix(part, "wap_wsp_header:") ||
			strings.HasPrefix(part, "wap_wsp_body:") || strings.HasPrefix(part, "wap_wsp_uri:") {
			// WAP/WSP options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["wap"] = kv[1]
			} else {
				options["wap"] = "true"
			}
		} else if strings.HasPrefix(part, "imap:") || strings.HasPrefix(part, "imap_command:") ||
			strings.HasPrefix(part, "imap_login:") || strings.HasPrefix(part, "imap_pass:") ||
			strings.HasPrefix(part, "imap_mailbox:") || strings.HasPrefix(part, "imap_filename:") {
			// IMAP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["imap"] = kv[1]
			} else {
				options["imap"] = "true"
			}
		} else if strings.HasPrefix(part, "pop:") || strings.HasPrefix(part, "pop_command:") ||
			strings.HasPrefix(part, "pop_login:") || strings.HasPrefix(part, "pop_pass:") ||
			strings.HasPrefix(part, "pop_mail_from:") || strings.HasPrefix(part, "pop_rcpt_to:") {
			// POP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["pop"] = kv[1]
			} else {
				options["pop"] = "true"
			}
		} else if strings.HasPrefix(part, "nntp:") || strings.HasPrefix(part, "nntp_command:") ||
			strings.HasPrefix(part, "nntp_newsgroups:") || strings.HasPrefix(part, "nntp_subject:") ||
			strings.HasPrefix(part, "nntp_from:") || strings.HasPrefix(part, "nntp_payload:") {
			// NNTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["nntp"] = kv[1]
			} else {
				options["nntp"] = "true"
			}
		} else if strings.HasPrefix(part, "mms:") || strings.HasPrefix(part, "mms_direction:") ||
			strings.HasPrefix(part, "mms_message_id:") {
			// MMS protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["mms"] = kv[1]
			} else {
				options["mms"] = "true"
			}
		} else if strings.HasPrefix(part, "smpp:") || strings.HasPrefix(part, "smpp_command:") ||
			strings.HasPrefix(part, "smpp_type:") || strings.HasPrefix(part, "smpp_src:") ||
			strings.HasPrefix(part, "smpp_dst:") || strings.HasPrefix(part, "smpp_service:") {
			// SMPP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["smpp"] = kv[1]
			} else {
				options["smpp"] = "true"
			}
		} else if strings.HasPrefix(part, "gtp:") || strings.HasPrefix(part, "gtp_type:") ||
			strings.HasPrefix(part, "gtp_info:") || strings.HasPrefix(part, "gtp_version:") ||
			strings.HasPrefix(part, "gtp_message:") {
			// GTP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["gtp"] = kv[1]
			} else {
				options["gtp"] = "true"
			}
		} else if strings.HasPrefix(part, "dns:") || strings.HasPrefix(part, "dns_query:") ||
			strings.HasPrefix(part, "dns_response:") || strings.HasPrefix(part, "dns_query_name:") ||
			strings.HasPrefix(part, "dns_query_type:") || strings.HasPrefix(part, "dns_flags:") {
			// DNS protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["dns"] = kv[1]
			} else {
				options["dns"] = "true"
			}
		} else if strings.HasPrefix(part, "sdp:") || strings.HasPrefix(part, "sdp_session:") ||
			strings.HasPrefix(part, "sdp_session_name:") || strings.HasPrefix(part, "sdp_session_info:") ||
			strings.HasPrefix(part, "sdp_uri:") || strings.HasPrefix(part, "sdp_email:") ||
			strings.HasPrefix(part, "sdp_phone:") || strings.HasPrefix(part, "sdp_version:") ||
			strings.HasPrefix(part, "sdp_origin:") || strings.HasPrefix(part, "sdp_connection:") ||
			strings.HasPrefix(part, "sdp_bandwidth:") || strings.HasPrefix(part, "sdp_time:") ||
			strings.HasPrefix(part, "sdp_repeat:") || strings.HasPrefix(part, "sdp_encryption:") ||
			strings.HasPrefix(part, "sdp_attribute:") || strings.HasPrefix(part, "sdp_media:") {
			// SDP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["sdp"] = kv[1]
			} else {
				options["sdp"] = "true"
			}
		} else if strings.HasPrefix(part, "h323:") || strings.HasPrefix(part, "h323_calling:") ||
			strings.HasPrefix(part, "h323_called:") || strings.HasPrefix(part, "h323_type:") ||
			strings.HasPrefix(part, "h323_reason:") || strings.HasPrefix(part, "h323_address:") {
			// H.323 protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["h323"] = kv[1]
			} else {
				options["h323"] = "true"
			}
		} else if strings.HasPrefix(part, "megaco:") || strings.HasPrefix(part, "megaco_command:") ||
			strings.HasPrefix(part, "megaco_digit:") || strings.HasPrefix(part, "megaco_mediatype:") {
			// Megaco/H.248 protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["megaco"] = kv[1]
			} else {
				options["megaco"] = "true"
			}
		} else if strings.HasPrefix(part, "mmp:") || strings.HasPrefix(part, "mmp_type:") ||
			strings.HasPrefix(part, "mmp_code:") || strings.HasPrefix(part, "mmp_seq:") {
			// MMP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["mmp"] = kv[1]
			} else {
				options["mmp"] = "true"
			}
		} else if strings.HasPrefix(part, "skinny:") || strings.HasPrefix(part, "skinny_msgtype:") ||
			strings.HasPrefix(part, "skinny_calling:") || strings.HasPrefix(part, "skinny_called:") ||
			strings.HasPrefix(part, "skinny_line:") || strings.HasPrefix(part, "skinny_calldel:") {
			// Skinny (SCCP) protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["skinny"] = kv[1]
			} else {
				options["skinny"] = "true"
			}
		} else if strings.HasPrefix(part, "selenium:") || strings.HasPrefix(part, "selenium_url:") ||
			strings.HasPrefix(part, "selenium_script:") || strings.HasPrefix(part, "selenium_token:") {
			// Selenium options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["selenium"] = kv[1]
			} else {
				options["selenium"] = "true"
			}
		} else if strings.HasPrefix(part, "reputation:") || strings.HasPrefix(part, "reputation_block:") ||
			strings.HasPrefix(part, "reputation_list:") || strings.HasPrefix(part, "reputation_priority:") {
			// Reputation preprocessor options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["reputation"] = kv[1]
			} else {
				options["reputation"] = "true"
			}
		} else if strings.HasPrefix(part, "localid:") || strings.HasPrefix(part, "localid_msg:") {
			// Local ID options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["localid"] = kv[1]
			} else {
				options["localid"] = "true"
			}
		} else if strings.HasPrefix(part, "rpc:") || strings.HasPrefix(part, "rpc_status:") ||
			strings.HasPrefix(part, "rpc_program:") || strings.HasPrefix(part, "rpc_program_version:") ||
			strings.HasPrefix(part, "rpc_procedure:") {
			// RPC options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["rpc"] = kv[1]
			} else {
				options["rpc"] = "true"
			}
		} else if strings.HasPrefix(part, "netflow:") || strings.HasPrefix(part, "netflow_version:") ||
			strings.HasPrefix(part, "netflow_role:") {
			// NetFlow options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["netflow"] = kv[1]
			} else {
				options["netflow"] = "true"
			}
		} else if strings.HasPrefix(part, "pt2fill:") || strings.HasPrefix(part, "pt2tree:") ||
			strings.HasPrefix(part, "pt2event:") || strings.HasPrefix(part, "pt2data:") {
			// PT (Protocol Test) options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["pt"] = kv[1]
			} else {
				options["pt"] = "true"
			}
		} else if strings.HasPrefix(part, "curesReset:") || strings.HasPrefix(part, "curesTracking:") {
			// CURES options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["cures"] = kv[1]
			} else {
				options["cures"] = "true"
			}
		} else if strings.HasPrefix(part, "s7comm:") || strings.HasPrefix(part, "s7comm_param:") ||
			strings.HasPrefix(part, "s7comm_func:") || strings.HasPrefix(part, "s7comm_subfunc:") ||
			strings.HasPrefix(part, "s7comm_data:") {
			// S7comm (SIMATIC) options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["s7comm"] = kv[1]
			} else {
				options["s7comm"] = "true"
			}
		} else if strings.HasPrefix(part, "mq:") || strings.HasPrefix(part, "mq_msg_type:") ||
			strings.HasPrefix(part, "mq_correl_id:") || strings.HasPrefix(part, "mq_msg_id:") ||
			strings.HasPrefix(part, "mq_put_appl_type:") || strings.HasPrefix(part, "mq_backout_count:") ||
			strings.HasPrefix(part, "mq_reply_to_q:") || strings.HasPrefix(part, "mq_expiry:") ||
			strings.HasPrefix(part, "mq_report:") || strings.HasPrefix(part, "mq_user:") {
			// MQ (IBM MQ) options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["mq"] = kv[1]
			} else {
				options["mq"] = "true"
			}
		} else if strings.HasPrefix(part, "classtype:") {
			// Classification type
			options["classtype"] = strings.TrimPrefix(part, "classtype:")
		} else if strings.HasPrefix(part, "reference:") {
			// Reference tracking
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["reference"] = kv[1]
			} else {
				options["reference"] = "true"
			}
		} else if strings.HasPrefix(part, "priority:") {
			// Rule priority
			options["priority"] = strings.TrimPrefix(part, "priority:")
		} else if strings.HasPrefix(part, "rev:") {
			// Revision - already handled but catch any remaining
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["rev"] = kv[1]
			}
		} else if strings.HasPrefix(part, "sid:") {
			// SID - already handled but catch any remaining
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["sid"] = kv[1]
			}
		} else if strings.HasPrefix(part, "msg:") {
			// Msg - already handled but catch any remaining
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["msg"] = kv[1]
			}
		} else if strings.HasPrefix(part, "content:") {
			// Content - already handled but catch remaining variations
			// Skip to avoid duplicate handling
		} else if strings.HasPrefix(part, "pcre:") {
			// PCRE - already handled above
		} else if strings.HasPrefix(part, "byte_test:") || strings.HasPrefix(part, "byte_jump:") {
			// Byte operations - already handled
		} else if strings.HasPrefix(part, "flow:") {
			// Flow - already handled
		} else if strings.HasPrefix(part, "flowbits:") {
			// Flowbits - already handled
		} else if strings.HasPrefix(part, "vlan:") {
			// VLAN - already handled
		} else if strings.HasPrefix(part, "threshold:") || strings.HasPrefix(part, "detection_filter:") {
			// Threshold - already handled
		} else if strings.HasPrefix(part, "rate_filter:") {
			// Rate filter - already handled
		} else if strings.HasPrefix(part, "stream_reassemble:") || strings.HasPrefix(part, "stream_size:") {
			// Stream - already handled
		} else if strings.HasPrefix(part, "ldap:") || strings.HasPrefix(part, "ldap_operation:") ||
			strings.HasPrefix(part, "ldap_binddn:") || strings.HasPrefix(part, "ldap_search:") ||
			strings.HasPrefix(part, "ldap_response:") || strings.HasPrefix(part, "ldap_msgid:") {
			// LDAP protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ldap"] = kv[1]
			} else {
				options["ldap"] = "true"
			}
		} else if strings.HasPrefix(part, "ftp_data:") || strings.HasPrefix(part, "ftpdata:") {
			// FTP data options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ftp_data"] = kv[1]
			} else {
				options["ftp_data"] = "true"
			}
		} else if strings.HasPrefix(part, "ssh:") || strings.HasPrefix(part, "ssh_protoversion:") ||
			strings.HasPrefix(part, "ssh_softwareversion:") || strings.HasPrefix(part, "ssh_message:") ||
			strings.HasPrefix(part, "ssh_encryption:") || strings.HasPrefix(part, "ssh_auth:") {
			// SSH protocol options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ssh"] = kv[1]
			} else {
				options["ssh"] = "true"
			}
		} else if strings.HasPrefix(part, "gre:") || strings.HasPrefix(part, "gre_proto:") ||
			strings.HasPrefix(part, "gre_version:") {
			// GRE options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["gre"] = kv[1]
			} else {
				options["gre"] = "true"
			}
		} else if strings.HasPrefix(part, "ethernet:") || strings.HasPrefix(part, "ethertype:") ||
			strings.HasPrefix(part, "mac:") {
			// Ethernet options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ethernet"] = kv[1]
			} else {
				options["ethernet"] = "true"
			}
		} else if strings.HasPrefix(part, "vlan:") {
			// VLAN already handled above
		} else if strings.HasPrefix(part, "mpls:") || strings.HasPrefix(part, "mpls_label:") ||
			strings.HasPrefix(part, "mpls_exp:") || strings.HasPrefix(part, "mpls_bottom:") {
			// MPLS options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["mpls"] = kv[1]
			} else {
				options["mpls"] = "true"
			}
		} else if strings.HasPrefix(part, "ipv4:") || strings.HasPrefix(part, "ipv4_src:") ||
			strings.HasPrefix(part, "ipv4_dst:") || strings.HasPrefix(part, "ipv4_id:") ||
			strings.HasPrefix(part, "ipv4_tos:") || strings.HasPrefix(part, "ipv4_ttl:") {
			// IPv4 options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ipv4"] = kv[1]
			} else {
				options["ipv4"] = "true"
			}
		} else if strings.HasPrefix(part, "ipv6:") || strings.HasPrefix(part, "ipv6_src:") ||
			strings.HasPrefix(part, "ipv6_dst:") || strings.HasPrefix(part, "ipv6_class:") ||
			strings.HasPrefix(part, "ipv6_flow:") || strings.HasPrefix(part, "ipv6_hoplimit:") ||
			strings.HasPrefix(part, "ipv6_dst:") {
			// IPv6 options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["ipv6"] = kv[1]
			} else {
				options["ipv6"] = "true"
			}
		} else if strings.HasPrefix(part, "tcp:") || strings.HasPrefix(part, "tcp_seq:") ||
			strings.HasPrefix(part, "tcp_ack:") || strings.HasPrefix(part, "tcp_win:") ||
			strings.HasPrefix(part, "tcp_len:") || strings.HasPrefix(part, "tcp_flags:") {
			// TCP options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["tcp"] = kv[1]
			} else {
				options["tcp"] = "true"
			}
		} else if strings.HasPrefix(part, "udp:") || strings.HasPrefix(part, "udp_len:") {
			// UDP options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["udp"] = kv[1]
			} else {
				options["udp"] = "true"
			}
		} else if strings.HasPrefix(part, "icmp4:") || strings.HasPrefix(part, "icmp4_type:") ||
			strings.HasPrefix(part, "icmp4_code:") || strings.HasPrefix(part, "icmp4_id:") ||
			strings.HasPrefix(part, "icmp4_seq:") || strings.HasPrefix(part, "icmp4_gw:") {
			// ICMPv4 options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["icmp4"] = kv[1]
			} else {
				options["icmp4"] = "true"
			}
		} else if strings.HasPrefix(part, "icmp6:") || strings.HasPrefix(part, "icmp6_type:") ||
			strings.HasPrefix(part, "icmp6_code:") || strings.HasPrefix(part, "icmp6_target:") ||
			strings.HasPrefix(part, "icmp6_addr:") {
			// ICMPv6 options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["icmp6"] = kv[1]
			} else {
				options["icmp6"] = "true"
			}
		} else if strings.HasPrefix(part, "sctp:") || strings.HasPrefix(part, "sctp_chunk:") ||
			strings.HasPrefix(part, "sctp_type:") || strings.HasPrefix(part, "sctp_offset:") ||
			strings.HasPrefix(part, "sctp_len:") {
			// SCTP options
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["sctp"] = kv[1]
			} else {
				options["sctp"] = "true"
			}
		} else if strings.HasPrefix(part, "pkttype:") || strings.HasPrefix(part, "pkt_type:") {
			// Packet type option
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["pkttype"] = kv[1]
			} else {
				options["pkttype"] = "true"
			}
		} else if strings.HasPrefix(part, "logto:") {
			// Log to option
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["logto"] = kv[1]
			} else {
				options["logto"] = "true"
			}
		} else if strings.HasPrefix(part, "session:") {
			// Session printing option
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["session"] = kv[1]
			} else {
				options["session"] = "true"
			}
		} else if strings.HasPrefix(part, "resp:") || strings.HasPrefix(part, "react:") {
			// Response actions
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options["resp"] = kv[1]
			} else {
				options["resp"] = "true"
			}
		} else {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				options[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			} else if len(kv) == 1 && kv[0] != "" && kv[0] != ")" {
				// Handle options without values (like http_uri, sameip, nocase, etc)
				options[kv[0]] = "true"
			}
		}

		_ = partIdx // avoid unused variable warning
	}

	return ruleID, msg, contents, pcreMatches, byteTests, byteJumps, flow, flowbits, noAlert, options, vlanID, nil
}

func (p *Parser) parsePCRE(part string) (PCREMatch, error) {
	pcre := PCREMatch{}

	re := regexp.MustCompile(`pcre:\s*"/(.+)"/?([imsxAEGRUBPHDMCS]*)"?`)
	m := re.FindStringSubmatch(part)
	if len(m) < 2 {
		return pcre, fmt.Errorf("malformed PCRE expression: %s", part)
	}

	full := m[1]
	modifiers := m[2]

	// Validate the pattern is not empty after delimiter stripping
	if strings.HasPrefix(full, "/") || full == "" {
		return pcre, fmt.Errorf("PCRE pattern cannot be empty")
	}

	slashIdx := strings.LastIndex(full, "/")
	if slashIdx > 0 {
		pcre.Pattern = full[:slashIdx]
		pcre.Modifiers = full[slashIdx+1:] + modifiers
	} else {
		pcre.Pattern = full
	}

	return pcre, nil
}

func (p *Parser) parseContentMatch(part string) (ContentMatch, error) {
	cm := ContentMatch{}

	// Check for negation first - handle content:! and content: !" variants
	negated := strings.Contains(part, "content:!") || strings.Contains(part, "content: !")
	cm.IsNegated = negated

	// Hex content: content:"|48 61|" or content:|48 61|
	// The hex delimiter is |, can be wrapped in quotes
	hexRe := regexp.MustCompile(`content:\s*(?:!)?["']?\|([^|]+)\|["']?`)
	h := hexRe.FindStringSubmatch(part)
	if len(h) > 1 {
		cm.Raw = decodeContent("|" + h[1] + "|")
		cm.IsHex = true
		return cm, nil
	}

	// Updated regex to properly handle negation prefix
	// content:!"value" or content:"value" or content:!value
	strRe := regexp.MustCompile(`content:\s*(?:!)?["']?([^"';]+)["']?`)
	m := strRe.FindStringSubmatch(part)
	if len(m) > 1 {
		content := m[1]
		// If negation was detected but content doesn't start with !, it means
		// the ! was already consumed by the regex prefix, so IsNegated is already true
		if strings.HasPrefix(content, "!") {
			cm.IsNegated = true
			content = content[1:]
		}
		// Handle empty content - if just "!" was provided, content would be empty
		if content == "" && !cm.IsNegated {
			return cm, fmt.Errorf("content match cannot be empty")
		}
		// For negated empty content like "content:!" - this might be valid for matching "not this value"
		// but we should still flag it as potentially problematic
		if content == "" && cm.IsNegated {
			return cm, fmt.Errorf("content match cannot be empty")
		}
		cm.Raw = decodeContent(content)
		return cm, nil
	}

	return cm, fmt.Errorf("malformed content match: %s", part)
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

// parseByteTest parses byte_test option
// Syntax: byte_test:<count>, <operator>, <value>, <offset>[, relative][, big][, little][, string][, hex][, dec][, oct][, negate]
func (p *Parser) parseByteTest(part string) (ByteTest, error) {
	bt := ByteTest{}

	// Remove "byte_test:" prefix
	content := strings.TrimPrefix(part, "byte_test:")
	content = strings.TrimSpace(content)

	// Split by comma
	fields := strings.Split(content, ",")
	if len(fields) < 4 {
		return bt, fmt.Errorf("byte_test requires at least 4 arguments: count, operator, value, offset")
	}

	// Parse count
	count, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		return bt, fmt.Errorf("byte_test count must be a number: %v", err)
	}
	bt.Count = count

	// Parse operator
	op := strings.TrimSpace(fields[1])
	switch op {
	case "<", ">", "=", "!", "!=", "<=", ">=":
		bt.Operator = op
	case "<>":
		// bidirectional - not typically used in byte_test
		bt.Operator = op
	default:
		return bt, fmt.Errorf("byte_test operator must be one of <, >, =, !, !=, <=, >=: got %s", op)
	}

	// Parse value (can be string for string comparison)
	valueStr := strings.TrimSpace(fields[2])
	if strings.HasPrefix(valueStr, "\"") && strings.HasSuffix(valueStr, "\"") {
		// String value
		bt.String = true
		valueStr = valueStr[1 : len(valueStr)-1]
	}
	// Try to parse as number
	if v, err := strconv.ParseUint(valueStr, 0, 64); err == nil {
		bt.Value = v
	}

	// Parse offset
	offset, err := strconv.Atoi(strings.TrimSpace(fields[3]))
	if err != nil {
		return bt, fmt.Errorf("byte_test offset must be a number: %v", err)
	}
	bt.Offset = offset

	// Parse optional modifiers
	for i := 4; i < len(fields); i++ {
		mod := strings.TrimSpace(strings.ToLower(fields[i]))
		switch mod {
		case "relative":
			bt.Relative = true
		case "big":
			bt.BigEndian = true
		case "little":
			bt.LittleEndian = true
		case "string":
			bt.String = true
		case "hex":
			// Value is hex
		case "dec":
			// Value is decimal
		case "oct":
			// Value is octal
		case "negate":
			bt.Negate = true
		}
	}

	return bt, nil
}

// parseByteJump parses byte_jump option
// Syntax: byte_jump:<count>, <offset>[, relative][, big][, little][, string][, hex][, dec][, oct][, align <num>][, post_offset <num>]
func (p *Parser) parseByteJump(part string) (ByteJump, error) {
	bj := ByteJump{}

	// Remove "byte_jump:" prefix
	content := strings.TrimPrefix(part, "byte_jump:")
	content = strings.TrimSpace(content)

	// Split by comma
	fields := strings.Split(content, ",")
	if len(fields) < 2 {
		return bj, fmt.Errorf("byte_jump requires at least 2 arguments: count, offset")
	}

	// Parse count
	count, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil {
		return bj, fmt.Errorf("byte_jump count must be a number: %v", err)
	}
	bj.Count = count

	// Parse offset
	offset, err := strconv.Atoi(strings.TrimSpace(fields[1]))
	if err != nil {
		return bj, fmt.Errorf("byte_jump offset must be a number: %v", err)
	}
	bj.Offset = offset

	// Parse optional modifiers
	for i := 2; i < len(fields); i++ {
		mod := strings.TrimSpace(strings.ToLower(fields[i]))
		switch {
		case mod == "relative":
			bj.Relative = true
		case mod == "big":
			bj.BigEndian = true
		case mod == "little":
			bj.LittleEndian = true
		case mod == "string":
			bj.String = true
		case strings.HasPrefix(mod, "align"):
			// align <num>
			parts := strings.Split(mod, " ")
			if len(parts) >= 2 {
				if v, err := strconv.Atoi(parts[1]); err == nil {
					bj.Align = v
				}
			}
		case strings.HasPrefix(mod, "post_offset"):
			// post_offset <num>
			parts := strings.Split(mod, " ")
			if len(parts) >= 2 {
				if v, err := strconv.Atoi(parts[1]); err == nil {
					bj.PostOffset = v
				}
			}
		}
	}

	return bj, nil
}

// parseFlowbits parses flowbits option
// flowbits:set,name or flowbits:isset,name or flowbits:noalert
func (p *Parser) parseFlowbits(part string) (Flowbit, error) {
	fb := Flowbit{}

	// Remove "flowbits:" prefix
	content := strings.TrimPrefix(part, "flowbits:")
	content = strings.TrimSpace(content)

	// Handle noalert
	if content == "noalert" {
		fb.Op = FlowbitNoAlert
		return fb, nil
	}

	// Parse operation,name format
	fields := strings.Split(content, ",")
	if len(fields) < 2 {
		return fb, fmt.Errorf("flowbits requires operation and name: flowbits:op,name")
	}

	op := strings.TrimSpace(fields[0])
	name := strings.TrimSpace(fields[1])

	switch op {
	case "set":
		fb.Op = FlowbitSet
	case "isset":
		fb.Op = FlowbitIsSet
	case "isnotset":
		fb.Op = FlowbitNotSet
	case "toggle":
		fb.Op = FlowbitToggle
	case "unset":
		fb.Op = FlowbitUnset
	case "noalert":
		fb.Op = FlowbitNoAlert
	default:
		return fb, fmt.Errorf("unknown flowbits operation: %s", op)
	}

	fb.Name = name
	return fb, nil
}

// parseThreshold parses threshold option
// threshold:type <type>, track <by>, count <count>, seconds <seconds>
// type: limit, threshold, both, suppress
// track: by_src, by_dst
func (p *Parser) parseThreshold(part string) (*Threshold, error) {
	th := &Threshold{}

	// Remove "threshold:" prefix
	content := strings.TrimPrefix(part, "threshold:")
	content = strings.TrimSpace(content)

	// Parse key=value pairs
	fields := strings.Split(content, ",")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		kv := strings.SplitN(field, " ", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "type":
			th.Type = ThresholdType(val)
		case "track":
			th.TrackBy = val
		case "count":
			fmt.Sscanf(val, "%d", &th.Count)
		case "seconds":
			fmt.Sscanf(val, "%d", &th.Seconds)
		}
	}

	// Validate
	if th.Type == "" {
		return nil, fmt.Errorf("threshold requires type: limit, threshold, both, or suppress")
	}
	if th.TrackBy == "" {
		return nil, fmt.Errorf("threshold requires track: by_src or by_dst")
	}
	if th.Count == 0 {
		return nil, fmt.Errorf("threshold requires count")
	}
	if th.Seconds == 0 {
		return nil, fmt.Errorf("threshold requires seconds")
	}

	return th, nil
}

// parseRateFilter parses rate_filter option
// rate_filter:type <type>, track <by>, count <count>, seconds <seconds>, new_action <action>
// type: filter
// track: by_src, by_dst
// action: drop, alert, log, pass, reject, sdrop
func (p *Parser) parseRateFilter(part string) (*RateFilter, error) {
	rf := &RateFilter{}

	// Remove "rate_filter:" prefix
	content := strings.TrimPrefix(part, "rate_filter:")
	content = strings.TrimSpace(content)

	// Parse key=value pairs
	fields := strings.Split(content, ",")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		kv := strings.SplitN(field, " ", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "type":
			rf.Type = val
		case "track":
			rf.TrackBy = val
		case "count":
			fmt.Sscanf(val, "%d", &rf.Count)
		case "seconds":
			fmt.Sscanf(val, "%d", &rf.Seconds)
		case "new_action":
			rf.Action = RateFilterAction(val)
		}
	}

	// Validate
	if rf.Type == "" {
		return nil, fmt.Errorf("rate_filter requires type")
	}
	if rf.TrackBy == "" {
		return nil, fmt.Errorf("rate_filter requires track: by_src or by_dst")
	}
	if rf.Count == 0 {
		return nil, fmt.Errorf("rate_filter requires count")
	}
	if rf.Seconds == 0 {
		return nil, fmt.Errorf("rate_filter requires seconds")
	}

	return rf, nil
}

// parseDetectionFilter parses detection_filter option
// detection_filter:track <by>, count <n>, seconds <n>
func (p *Parser) parseDetectionFilter(part string) (*DetectionFilter, error) {
	df := &DetectionFilter{}

	// Remove "detection_filter:" prefix
	content := strings.TrimPrefix(part, "detection_filter:")
	content = strings.TrimSpace(content)

	// Parse key=value pairs
	fields := strings.Split(content, ",")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		kv := strings.SplitN(field, " ", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "track":
			df.TrackBy = val
		case "count":
			fmt.Sscanf(val, "%d", &df.Count)
		case "seconds":
			fmt.Sscanf(val, "%d", &df.Seconds)
		}
	}

	// Validate
	if df.TrackBy == "" {
		return nil, fmt.Errorf("detection_filter requires track: by_src or by_dst")
	}
	if df.Count == 0 {
		return nil, fmt.Errorf("detection_filter requires count")
	}
	if df.Seconds == 0 {
		return nil, fmt.Errorf("detection_filter requires seconds")
	}

	return df, nil
}

// parseDSize parses dsize option
// dsize:<n> or dsize:<n><><m> (range)
func (p *Parser) parseDSize(part string) (*DSizeOption, error) {
	ds := &DSizeOption{}

	// Remove "dsize:" prefix
	content := strings.TrimPrefix(part, "dsize:")
	content = strings.TrimSpace(content)

	// Check for range format <n><><m>
	if strings.Contains(content, "<>") {
		ds.IsRange = true
		parts := strings.Split(content, "<>")
		if len(parts) == 2 {
			fmt.Sscanf(parts[0], "%d", &ds.Min)
			fmt.Sscanf(parts[1], "%d", &ds.Max)
			ds.Op = "<>"
		}
	} else if strings.HasPrefix(content, ">") {
		ds.Op = ">"
		fmt.Sscanf(strings.TrimPrefix(content, ">"), "%d", &ds.Min)
	} else if strings.HasPrefix(content, "<") {
		ds.Op = "<"
		fmt.Sscanf(strings.TrimPrefix(content, "<"), "%d", &ds.Max)
	} else if strings.HasPrefix(content, "=") {
		ds.Op = "="
		fmt.Sscanf(strings.TrimPrefix(content, "="), "%d", &ds.Min)
		ds.Max = ds.Min
	} else {
		// Simple number
		ds.Op = "="
		fmt.Sscanf(content, "%d", &ds.Min)
		ds.Max = ds.Min
	}

	return ds, nil
}

// validateRuleID checks if GID/SID values are within reasonable ranges
func validateRuleID(ruleID RuleID) error {
	// GID should typically be 1-999999999
	if ruleID.GID < 0 || ruleID.GID > 999999999 {
		return fmt.Errorf("invalid GID %d: must be between 0 and 999999999", ruleID.GID)
	}
	// SID should typically be 1-999999999
	if ruleID.SID < 0 || ruleID.SID > 999999999 {
		return fmt.Errorf("invalid SID %d: must be between 0 and 999999999", ruleID.SID)
	}
	// REV should typically be 1-999
	if ruleID.REV < 0 || ruleID.REV > 999 {
		return fmt.Errorf("invalid REV %d: must be between 0 and 999", ruleID.REV)
	}
	return nil
}

// validateFlow validates flow option values
func (p *Parser) validateFlow(flow string) error {
	validFlows := map[string]bool{
		"established":        true,
		"to_server":          true,
		"to_client":          true,
		"from_server":        true,
		"from_client":        true,
		"only_stream":        true,
		"no_stream":         true,
		"established,to_server":   true,
		"established,to_client":   true,
		"established,from_server": true,
		"established,from_client": true,
		"to_server,established":   true,
		"to_client,established":   true,
		"from_server,established": true,
		"from_client,established": true,
		"no_stream,established":   true,
		"only_stream,established": true,
	}

	if validFlows[flow] {
		return nil
	}

	// Check for invalid direction combinations
	if strings.Contains(flow, "to_server") && strings.Contains(flow, "to_client") {
		return fmt.Errorf("flow cannot specify both to_server and to_client")
	}
	if strings.Contains(flow, "from_server") && strings.Contains(flow, "from_client") {
		return fmt.Errorf("flow cannot specify both from_server and from_client")
	}

	return fmt.Errorf("invalid flow value '%s'", flow)
}

// extractIPv6ExtHeaders extracts IPv6 extension header options from the options map
func extractIPv6ExtHeaders(options map[string]string) []IPv6ExtensionHeader {
	var headers []IPv6ExtensionHeader

	extHeaderTypes := []string{
		"hopopts",
		"dstopts",
		"routing",
		"fragment",
		"ah",
		"esp",
		"mip6",
	}

	for _, htype := range extHeaderTypes {
		if val, ok := options[htype]; ok && val != "" && val != "true" {
			headers = append(headers, IPv6ExtensionHeader{
				Type:    htype,
				Options: val,
			})
		}
	}

	return headers
}
