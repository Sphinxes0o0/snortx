package config

import "time"

type Config struct {
	App    AppConfig    `yaml:"app"`
	Engine EngineConfig `yaml:"engine"`
	API    APIConfig    `yaml:"api"`
	CLI    CLIConfig    `yaml:"cli"`
}

type AppConfig struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

type EngineConfig struct {
	WorkerCount  int             `yaml:"worker_count"`
	RuleTimeout  time.Duration   `yaml:"rule_timeout"`
	TotalTimeout time.Duration   `yaml:"total_timeout"`
	Generator    GeneratorConfig `yaml:"generator"`
	Sender       SenderConfig    `yaml:"sender"`
	OutputDir    string          `yaml:"output_dir"`
}

type GeneratorConfig struct {
	DefaultSrcIP   string `yaml:"default_src_ip"`
	DefaultDstIP   string `yaml:"default_dst_ip"`
	DefaultSrcPort uint16 `yaml:"default_src_port"`
	DefaultDstPort uint16 `yaml:"default_dst_port"`
}

type SenderConfig struct {
	Interface string `yaml:"interface"`
	SnapLen   int    `yaml:"snap_len"`
	Timeout   time.Duration `yaml:"timeout"`
}

type APIConfig struct {
	Address    string   `yaml:"address"`
	TLSEnabled bool     `yaml:"tls_enabled"`
	TLSCert    string   `yaml:"tls_cert"`
	TLSKey     string   `yaml:"tls_key"`
	CORS       []string `yaml:"cors_allowed_origins"`
	RateLimit  int      `yaml:"rate_limit"`
	Auth       AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
}

type CLIConfig struct {
	Verbose bool `yaml:"verbose"`
	JSON    bool `yaml:"json"`
}
