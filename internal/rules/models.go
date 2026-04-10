package rules

import "fmt"

// ErrorPhase indicates which part of the rule failed parsing
type ErrorPhase string

const (
	PhaseHeader   ErrorPhase = "header"
	PhaseOptions  ErrorPhase = "options"
	PhaseContent  ErrorPhase = "content"
	PhasePCRE     ErrorPhase = "pcre"
	PhaseFlow     ErrorPhase = "flow"
	PhaseRuleID   ErrorPhase = "rule_id"
	PhaseVLAN     ErrorPhase = "vlan"
	PhaseFormat   ErrorPhase = "format"
)

// ParseError represents a detailed parsing error with character-level precision
type ParseError struct {
	Line       int       `json:"line"`
	CharOffset int       `json:"char_offset"`
	Phase      ErrorPhase `json:"phase"`
	Message    string   `json:"message"`
	RuleText   string   `json:"rule_text"`
	Context    string   `json:"context,omitempty"` // Surrounding text for context
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d, col %d (%s): %s", e.Line, e.CharOffset+1, e.Phase, e.Message)
	}
	return fmt.Sprintf("col %d (%s): %s", e.CharOffset+1, e.Phase, e.Message)
}

// RuleID represents a Snort rule ID (GID:SID:REV)
type RuleID struct {
	GID int `json:"gid"`
	SID int `json:"sid"`
	REV int `json:"rev"`
}

type ContentMatch struct {
	Raw       []byte `json:"raw"`
	IsHex     bool   `json:"is_hex"`
	IsNegated bool   `json:"is_negated"`
	Nocase    bool   `json:"nocase"`
	Offset    *int   `json:"offset,omitempty"`
	Depth     *int   `json:"depth,omitempty"`
	Distance  *int   `json:"distance,omitempty"`
	Within    *int   `json:"within,omitempty"`
}

type PCREMatch struct {
	Pattern   string `json:"pattern"`
	Modifiers string `json:"modifiers"`
}

// ByteTest represents a byte_test content modifier
// byte_test:<count>, <operator>, <value>, <offset>[, options]
type ByteTest struct {
	Count    int     // number of bytes to extract
	Operator string  // comparison operator: <, >, =, !, <=, >=
	Value    uint64  // value to compare against
	Offset   int     // offset from which to extract
	Relative bool    // offset is relative to last match
	BigEndian bool   // big endian (default is little)
	LittleEndian bool // little endian
	String   bool    // treat value as string
	Negate   bool    // negate the comparison result
}

// ByteJump represents a byte_jump content modifier
// byte_jump:<count>, <offset>[, options]
type ByteJump struct {
	Count    int     // number of bytes to extract
	Offset   int     // offset from which to extract
	Relative bool    // offset is relative to last match
	BigEndian bool  // big endian (default is little)
	LittleEndian bool // little endian
	String   bool    // treat value as string
	Align    int     // align to this boundary (0 = no align)
	PostOffset int   // additional offset after jump
}

// FlowbitOp represents the type of flowbit operation
type FlowbitOp string

const (
	FlowbitSet     FlowbitOp = "set"
	FlowbitIsSet   FlowbitOp = "isset"
	FlowbitNotSet  FlowbitOp = "isnotset"
	FlowbitToggle  FlowbitOp = "toggle"
	FlowbitUnset   FlowbitOp = "unset"
	FlowbitNoAlert FlowbitOp = "noalert"
)

// Flowbit represents a flowbits option
// flowbits:[set|isset|isnotset|toggle|unset],name
// flowbits:noalert
type Flowbit struct {
	Op   FlowbitOp // operation: set, isset, isnotset, toggle, unset, noalert
	Name string    // flowbit name
}

// ThresholdType represents the type of threshold
type ThresholdType string

const (
	ThresholdLimit    ThresholdType = "limit"
	ThresholdBoth     ThresholdType = "both"
	ThresholdSuppress ThresholdType = "suppress"
)

// Threshold represents a threshold option for rate limiting alerts
// threshold:type <type>, track <by>, count <count>, seconds <seconds>
type Threshold struct {
	Type    ThresholdType // limit, threshold, both, suppress
	TrackBy string       // by_src, by_dst
	Count   int          // number of matches
	Seconds int          // time window in seconds
}

// RateFilterAction represents the action a rate_filter can take
type RateFilterAction string

const (
	RateFilterDrop     RateFilterAction = "drop"
	RateFilterAlert    RateFilterAction = "alert"
	RateFilterLog     RateFilterAction = "log"
	RateFilterPass    RateFilterAction = "pass"
	RateFilterReject  RateFilterAction = "reject"
	RateFilterSDrop   RateFilterAction = "sdrop"
)

// RateFilter represents a rate_filter option for dynamic rule modification
// rate_filter:type <type>, track <by>, count <count>, seconds <seconds>, new_action <action>
type RateFilter struct {
	Type    string             // rate_filter type
	TrackBy string             // by_src, by_dst
	Count   int                // number of matches
	Seconds int                // time window in seconds
	Action  RateFilterAction   // new action to take
}

// IPv6ExtensionHeader represents an IPv6 extension header option
// Snort supports: hopopts, dstopts, routing, fragment, ah, esp, mip6
type IPv6ExtensionHeader struct {
	Type    string // header type: hopopts, dstopts, routing, fragment, ah, esp, mip6
	Options string // header-specific options as raw string
}

// DetectionFilter represents a detection_filter option for rate limiting
// detection_filter:track <by>, count <n>, seconds <n>
type DetectionFilter struct {
	TrackBy string // by_src, by_dst
	Count   int   // number of matches
	Seconds int   // time window in seconds
}

// DSizeOption represents payload size matching option
// dsize:<n> or dsize:<n><><m> (range)
type DSizeOption struct {
	Op     string // comparison operator: >, <, <>, =, etc
	Min    int    // minimum size (0 if not set)
	Max    int    // maximum size (0 if not set)
	IsRange bool  // true if range (<>) format
}

// HTTPModifier represents HTTP protocol modifiers
type HTTPModifier struct {
	Type    string // cookie, header, method, stat_code, stat_msg, uri
	Modifies string // raw, norm
	Content   string // the content to match
}

type ParsedRule struct {
	RawText         string            `json:"raw_text"`
	Action          string            `json:"action"`
	Protocol        string            `json:"protocol"`
	SrcNet          string            `json:"src_network"`
	SrcPorts        string            `json:"src_ports"`
	DstNet          string            `json:"dst_network"`
	DstPorts        string            `json:"dst_ports"`
	Direction       string            `json:"direction"`
	IsBidirectional bool              `json:"is_bidirectional"`
	RuleID          RuleID            `json:"rule_id"`
	Msg             string            `json:"msg"`
	Contents        []ContentMatch    `json:"contents"`
	PCREMatches     []PCREMatch       `json:"pcre_matches"`
	ByteTests       []ByteTest        `json:"byte_tests,omitempty"`
	ByteJumps       []ByteJump        `json:"byte_jumps,omitempty"`
	Flow            string            `json:"flow,omitempty"`
	Flowbits        []Flowbit         `json:"flowbits,omitempty"`
	Threshold       *Threshold        `json:"threshold,omitempty"`
	RateFilter      *RateFilter       `json:"rate_filter,omitempty"`
	IPv6ExtHeaders  []IPv6ExtensionHeader `json:"ipv6_ext_headers,omitempty"`
	DetectionFilter *DetectionFilter    `json:"detection_filter,omitempty"`
	DSize          *DSizeOption        `json:"dsize,omitempty"`
	HTTPModifiers  []HTTPModifier      `json:"http_modifiers,omitempty"`
	NoAlert         bool              `json:"no_alert,omitempty"`
	Options         map[string]string `json:"options,omitempty"`
	VLANID          uint16            `json:"vlan_id,omitempty"`
}
