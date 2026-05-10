package config

import (
	"fmt"
	"os"
	"reflect"
	"time"

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
	DefaultSrcIP   string            `yaml:"default_src_ip"`
	DefaultDstIP   string            `yaml:"default_dst_ip"`
	DefaultSrcPort uint16            `yaml:"default_src_port"`
	DefaultDstPort uint16            `yaml:"default_dst_port"`
	Vars           map[string]string `yaml:"vars"`
}

type SenderConfig struct {
	Interface string `yaml:"interface"`
	SnapLen   int    `yaml:"snap_len"`
	Timeout   string `yaml:"timeout"`
	TxEngine  string `yaml:"tx_engine"`
}

type APIConfig struct {
	Address    string     `yaml:"address"`
	TLSEnabled bool       `yaml:"tls_enabled"`
	TLSCert    string     `yaml:"tls_cert"`
	TLSKey     string     `yaml:"tls_key"`
	CORS       []string   `yaml:"cors_allowed_origins"`
	RateLimit  int        `yaml:"rate_limit"`
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
	// Start with defaults
	cfg := LoadDefault()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var yamlCfg Config
	if err := yaml.Unmarshal(data, &yamlCfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Merge YAML config onto defaults (YAML overrides defaults)
	mergeConfig(cfg, yamlCfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// mergeConfig recursively merges src into dst, overriding only non-zero values from src
func mergeConfig(dst, src interface{}) {
	dstVal := reflect.ValueOf(dst)
	srcVal := reflect.ValueOf(src)

	// Dereference pointers if needed
	if dstVal.Kind() == reflect.Ptr {
		dstVal = dstVal.Elem()
	}
	if srcVal.Kind() == reflect.Ptr {
		srcVal = srcVal.Elem()
	}

	if dstVal.Kind() != srcVal.Kind() {
		return
	}

	switch dstVal.Kind() {
	case reflect.Struct:
		for i := 0; i < dstVal.NumField(); i++ {
			srcField := srcVal.Field(i)
			dstField := dstVal.Field(i)

			if !srcField.IsZero() {
				if dstField.Kind() == reflect.Struct && srcField.Kind() == reflect.Struct {
					// Create addressable copies for recursive merge
					newDst := reflect.New(dstField.Type()).Elem()
					newDst.Set(dstField)
					newSrc := reflect.New(srcField.Type()).Elem()
					newSrc.Set(srcField)
					mergeConfig(newDst.Addr().Interface(), newSrc.Addr().Interface())
					// Copy the merged result back
					dstField.Set(newDst)
				} else {
					dstField.Set(srcField)
				}
			}
		}
	case reflect.Map:
		for _, key := range srcVal.MapKeys() {
			srcValue := srcVal.MapIndex(key)
			if !srcValue.IsZero() {
				dstVal.SetMapIndex(key, srcValue)
			}
		}
	}
}

// Validate checks that the config has valid values
func (c *Config) Validate() error {
	// Validate Engine timeouts
	if c.Engine.RuleTimeout != "" {
		if _, err := time.ParseDuration(c.Engine.RuleTimeout); err != nil {
			return fmt.Errorf("invalid rule_timeout: %w", err)
		}
	}
	if c.Engine.TotalTimeout != "" {
		if _, err := time.ParseDuration(c.Engine.TotalTimeout); err != nil {
			return fmt.Errorf("invalid total_timeout: %w", err)
		}
	}

	// Validate worker count
	if c.Engine.WorkerCount < 0 {
		return fmt.Errorf("worker_count must be >= 0, got %d", c.Engine.WorkerCount)
	}

	// Validate Sender config
	if c.Engine.Sender.Timeout != "" {
		if _, err := time.ParseDuration(c.Engine.Sender.Timeout); err != nil {
			return fmt.Errorf("invalid sender timeout: %w", err)
		}
	}

	// Validate ports
	if c.Engine.Generator.DefaultSrcPort > 65535 {
		return fmt.Errorf("default_src_port must be <= 65535, got %d", c.Engine.Generator.DefaultSrcPort)
	}
	if c.Engine.Generator.DefaultDstPort > 65535 {
		return fmt.Errorf("default_dst_port must be <= 65535, got %d", c.Engine.Generator.DefaultDstPort)
	}

	// Validate TxEngine
	validTxEngines := map[string]bool{"pcap": true, "sendmmsg": true, "afpacket": true}
	if c.Engine.Sender.TxEngine != "" && !validTxEngines[c.Engine.Sender.TxEngine] {
		return fmt.Errorf("tx_engine must be one of pcap, sendmmsg, afpacket, got %q", c.Engine.Sender.TxEngine)
	}

	// Validate API rate limit
	if c.API.RateLimit < 0 {
		return fmt.Errorf("rate_limit must be >= 0, got %d", c.API.RateLimit)
	}

	return nil
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
				Vars: map[string]string{
					"$HOME_NET":     "10.0.0.0/24",
					"$EXTERNAL_NET": "any",
					"$HTTP_SERVERS": "any",
					"$SMTP_SERVERS": "any",
					"$DNS_SERVERS":  "any",
					"$SSH_SERVERS":  "any",
				},
			},
			Sender: SenderConfig{
				Interface: "lo0",
				SnapLen:   65536,
				Timeout:   "1s",
				TxEngine:  "pcap",
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
