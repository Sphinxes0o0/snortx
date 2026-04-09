package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

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
	RuleTimeout  string          `yaml:"rule_timeout"`
	TotalTimeout string          `yaml:"total_timeout"`
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
	Timeout   string `yaml:"timeout"`
}

type APIConfig struct {
	Address    string   `yaml:"address"`
	TLSEnabled bool    `yaml:"tls_enabled"`
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

// Load reads and parses a YAML config file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// LoadDefault loads default configuration
func LoadDefault() *Config {
	return &Config{
		App: AppConfig{
			Name:    "snortx",
			Version: "1.0.0",
		},
		Engine: EngineConfig{
			WorkerCount:  0,
			RuleTimeout:  "30s",
			TotalTimeout: "5m",
			OutputDir:    "./output",
			Generator: GeneratorConfig{
				DefaultSrcIP:   "192.168.1.100",
				DefaultDstIP:   "10.0.0.1",
				DefaultSrcPort: 12345,
				DefaultDstPort: 80,
			},
			Sender: SenderConfig{
				Interface: "lo0",
				SnapLen:   65536,
				Timeout:   "1s",
			},
		},
		API: APIConfig{
			Address:    ":8080",
			TLSEnabled: false,
			RateLimit:  100,
			CORS:       []string{"*"},
			Auth: AuthConfig{
				Enabled: false,
			},
		},
		CLI: CLIConfig{
			Verbose: false,
			JSON:    false,
		},
	}
}
