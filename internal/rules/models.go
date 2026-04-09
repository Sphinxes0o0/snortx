package rules

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
	Flow            string            `json:"flow,omitempty"`
	Options         map[string]string `json:"options,omitempty"`
}
