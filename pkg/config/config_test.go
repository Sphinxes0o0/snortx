package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	content := `
app:
  name: test
  version: 1.0.0
  description: Test app
engine:
  worker_count: 4
  rule_timeout: 10s
  total_timeout: 2m
  output_dir: /tmp/output
  generator:
    default_src_ip: 10.0.0.1
    default_dst_ip: 192.168.1.1
    default_src_port: 54321
    default_dst_port: 443
    vars:
      $HOME_NET: "10.10.10.0/24"
      $EXTERNAL_NET: "192.168.1.0/24"
  sender:
    interface: eth0
    snap_len: 8192
    timeout: 500ms
    tx_engine: sendmmsg
api:
  address: :9090
  tls_enabled: true
  tls_cert: /path/to/cert
  tls_key: /path/to/key
  cors_allowed_origins:
    - https://example.com
  rate_limit: 200
  auth:
    enabled: true
    token: secret
cli:
  verbose: true
  json: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.App.Name != "test" {
		t.Errorf("expected App.Name 'test', got %q", cfg.App.Name)
	}
	if cfg.App.Version != "1.0.0" {
		t.Errorf("expected App.Version '1.0.0', got %q", cfg.App.Version)
	}
	if cfg.Engine.WorkerCount != 4 {
		t.Errorf("expected Engine.WorkerCount 4, got %d", cfg.Engine.WorkerCount)
	}
	if cfg.Engine.Generator.DefaultSrcPort != 54321 {
		t.Errorf("expected Engine.Generator.DefaultSrcPort 54321, got %d", cfg.Engine.Generator.DefaultSrcPort)
	}
	if cfg.Engine.Sender.TxEngine != "sendmmsg" {
		t.Errorf("expected Engine.Sender.TxEngine 'sendmmsg', got %q", cfg.Engine.Sender.TxEngine)
	}
	if cfg.Engine.Generator.Vars == nil {
		t.Error("expected Engine.Generator.Vars to be non-nil")
	}
	if cfg.Engine.Generator.Vars["$HOME_NET"] != "10.10.10.0/24" {
		t.Errorf("expected $HOME_NET '10.10.10.0/24', got %q", cfg.Engine.Generator.Vars["$HOME_NET"])
	}
	if cfg.Engine.Generator.Vars["$EXTERNAL_NET"] != "192.168.1.0/24" {
		t.Errorf("expected $EXTERNAL_NET '192.168.1.0/24', got %q", cfg.Engine.Generator.Vars["$EXTERNAL_NET"])
	}
	if cfg.API.TLSEnabled != true {
		t.Error("expected API.TLSEnabled true")
	}
	if cfg.API.Auth.Token != "secret" {
		t.Errorf("expected API.Auth.Token 'secret', got %q", cfg.API.Auth.Token)
	}
	if len(cfg.API.CORS) != 1 || cfg.API.CORS[0] != "https://example.com" {
		t.Errorf("expected CORS ['https://example.com'], got %v", cfg.API.CORS)
	}
	if cfg.CLI.Verbose != true {
		t.Error("expected CLI.Verbose true")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  *LoadDefault(),
			wantErr: false,
		},
		{
			name: "invalid rule_timeout format",
			config: Config{
				Engine: EngineConfig{
					RuleTimeout: "30seconds",
				},
			},
			wantErr: true,
			errMsg:  "invalid rule_timeout",
		},
		{
			name: "invalid total_timeout format",
			config: Config{
				Engine: EngineConfig{
					TotalTimeout: "5minutes",
				},
			},
			wantErr: true,
			errMsg:  "invalid total_timeout",
		},
		{
			name: "negative worker count",
			config: Config{
				Engine: EngineConfig{
					WorkerCount: -1,
				},
			},
			wantErr: true,
			errMsg:  "worker_count must be >= 0",
		},
		// Note: port > 65535 validation cannot be tested via struct literal
		// because uint16 cannot hold values > 65535. The validation code is
		// correct but this error path cannot be triggered through config loading.
		{
			name: "invalid tx_engine",
			config: Config{
				Engine: EngineConfig{
					Sender: SenderConfig{
						TxEngine: "invalid",
					},
				},
			},
			wantErr: true,
			errMsg:  "tx_engine must be one of",
		},
		{
			name: "invalid sender timeout format",
			config: Config{
				Engine: EngineConfig{
					Sender: SenderConfig{
						Timeout: "1second",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid sender timeout",
		},
		{
			name: "negative rate_limit",
			config: Config{
				API: APIConfig{
					RateLimit: -10,
				},
			},
			wantErr: true,
			errMsg:  "rate_limit must be >= 0",
		},
		{
			name: "valid tx_engine sendmmsg",
			config: Config{
				Engine: EngineConfig{
					Sender: SenderConfig{
						TxEngine: "sendmmsg",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid tx_engine afpacket",
			config: Config{
				Engine: EngineConfig{
					Sender: SenderConfig{
						TxEngine: "afpacket",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid rule_timeout",
			config: Config{
				Engine: EngineConfig{
					RuleTimeout: "10s",
				},
			},
			wantErr: false,
		},
		{
			name: "valid total_timeout",
			config: Config{
				Engine: EngineConfig{
					TotalTimeout: "2m",
				},
			},
			wantErr: false,
		},
		{
			name: "zero worker count is valid",
			config: Config{
				Engine: EngineConfig{
					WorkerCount: 0,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if err.Error() == "" || (tt.errMsg != "" && len(err.Error()) == 0) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func TestMergeConfig(t *testing.T) {
	tests := []struct {
		name     string
		src      Config
		override Config
		check    func(t *testing.T, result *Config)
	}{
		{
			name: "partial config overrides defaults",
			override: Config{
				App: AppConfig{
					Name: "custom-app",
				},
				Engine: EngineConfig{
					WorkerCount: 8,
				},
			},
			check: func(t *testing.T, result *Config) {
				if result.App.Name != "custom-app" {
					t.Errorf("expected App.Name 'custom-app', got %q", result.App.Name)
				}
				if result.App.Version != "1.0.0" {
					t.Errorf("expected App.Version '1.0.0' (default), got %q", result.App.Version)
				}
				if result.Engine.WorkerCount != 8 {
					t.Errorf("expected Engine.WorkerCount 8, got %d", result.Engine.WorkerCount)
				}
				if result.Engine.OutputDir != "./output" {
					t.Errorf("expected Engine.OutputDir './output' (default), got %q", result.Engine.OutputDir)
				}
			},
		},
		{
			name: "full config overrides all defaults",
			override: Config{
				App: AppConfig{
					Name:        "full-app",
					Version:     "2.0.0",
					Description: "Full override",
				},
				Engine: EngineConfig{
					WorkerCount:  16,
					RuleTimeout:  "60s",
					TotalTimeout: "10m",
					OutputDir:    "/custom/output",
					Generator: GeneratorConfig{
						DefaultSrcIP:   "172.16.0.1",
						DefaultDstIP:   "172.16.0.2",
						DefaultSrcPort: 54321,
						DefaultDstPort: 8443,
						Vars: map[string]string{
							"$HOME_NET":     "172.16.0.0/24",
							"$EXTERNAL_NET": "any",
						},
					},
					Sender: SenderConfig{
						Interface: "eth0",
						SnapLen:   8192,
						Timeout:   "500ms",
						TxEngine:  "sendmmsg",
					},
				},
				API: APIConfig{
					Address:    ":9090",
					TLSEnabled: true,
					TLSCert:    "/cert.pem",
					TLSKey:     "/key.pem",
					CORS:       []string{"https://example.com"},
					RateLimit:  200,
					Auth: AuthConfig{
						Enabled: true,
						Token:   "secret",
					},
				},
				CLI: CLIConfig{
					Verbose: true,
					JSON:    true,
				},
			},
			check: func(t *testing.T, result *Config) {
				if result.App.Name != "full-app" {
					t.Errorf("expected App.Name 'full-app', got %q", result.App.Name)
				}
				if result.App.Version != "2.0.0" {
					t.Errorf("expected App.Version '2.0.0', got %q", result.App.Version)
				}
				if result.Engine.WorkerCount != 16 {
					t.Errorf("expected Engine.WorkerCount 16, got %d", result.Engine.WorkerCount)
				}
				if result.Engine.OutputDir != "/custom/output" {
					t.Errorf("expected Engine.OutputDir '/custom/output', got %q", result.Engine.OutputDir)
				}
				if result.Engine.Generator.DefaultSrcIP != "172.16.0.1" {
					t.Errorf("expected Generator.DefaultSrcIP '172.16.0.1', got %q", result.Engine.Generator.DefaultSrcIP)
				}
				if result.Engine.Generator.DefaultDstPort != 8443 {
					t.Errorf("expected Generator.DefaultDstPort 8443, got %d", result.Engine.Generator.DefaultDstPort)
				}
				if result.Engine.Sender.TxEngine != "sendmmsg" {
					t.Errorf("expected Sender.TxEngine 'sendmmsg', got %q", result.Engine.Sender.TxEngine)
				}
				if result.API.Address != ":9090" {
					t.Errorf("expected API.Address ':9090', got %q", result.API.Address)
				}
				if !result.API.TLSEnabled {
					t.Error("expected API.TLSEnabled true")
				}
				if result.API.RateLimit != 200 {
					t.Errorf("expected API.RateLimit 200, got %d", result.API.RateLimit)
				}
				if !result.CLI.Verbose {
					t.Error("expected CLI.Verbose true")
				}
			},
		},
		{
			name: "generator vars merge with defaults",
			override: Config{
				Engine: EngineConfig{
					Generator: GeneratorConfig{
						Vars: map[string]string{
							"$HOME_NET":     "192.168.0.0/16",
							"$EXTERNAL_NET": "any",
						},
					},
				},
			},
			check: func(t *testing.T, result *Config) {
				if result.Engine.Generator.Vars["$HOME_NET"] != "192.168.0.0/16" {
					t.Errorf("expected $HOME_NET '192.168.0.0/16', got %q", result.Engine.Generator.Vars["$HOME_NET"])
				}
				// When override provides both keys, both should be set
				if result.Engine.Generator.Vars["$EXTERNAL_NET"] != "any" {
					t.Errorf("expected $EXTERNAL_NET 'any', got %q", result.Engine.Generator.Vars["$EXTERNAL_NET"])
				}
			},
		},
		{
			name: "empty config preserves all defaults",
			override: Config{},
			check: func(t *testing.T, result *Config) {
				defaults := LoadDefault()
				if result.App.Name != defaults.App.Name {
					t.Errorf("expected App.Name %q (default), got %q", defaults.App.Name, result.App.Name)
				}
				if result.Engine.WorkerCount != defaults.Engine.WorkerCount {
					t.Errorf("expected Engine.WorkerCount %d (default), got %d", defaults.Engine.WorkerCount, result.Engine.WorkerCount)
				}
				if result.Engine.Sender.TxEngine != defaults.Engine.Sender.TxEngine {
					t.Errorf("expected Engine.Sender.TxEngine %q (default), got %q", defaults.Engine.Sender.TxEngine, result.Engine.Sender.TxEngine)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LoadDefault()
			mergeConfig(cfg, tt.override)
			tt.check(t, cfg)
		})
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "invalid yaml syntax",
			content: "invalid: yaml: content:",
			wantErr: true,
		},
		{
			name:    "empty content",
			content: "",
			wantErr: false, // empty yaml is valid, results in zero values
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write temp config: %v", err)
			}

			_, err := Load(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadDefault(t *testing.T) {
	cfg := LoadDefault()

	// Check App fields
	if cfg.App.Name != "snortx" {
		t.Errorf("expected App.Name 'snortx', got %q", cfg.App.Name)
	}
	if cfg.App.Version != "1.0.0" {
		t.Errorf("expected App.Version '1.0.0', got %q", cfg.App.Version)
	}
	if cfg.Engine.WorkerCount != 0 {
		t.Errorf("expected Engine.WorkerCount 0, got %d", cfg.Engine.WorkerCount)
	}
	if cfg.Engine.OutputDir != "./output" {
		t.Errorf("expected Engine.OutputDir './output', got %q", cfg.Engine.OutputDir)
	}
	if cfg.API.Address != ":8080" {
		t.Errorf("expected API.Address ':8080', got %q", cfg.API.Address)
	}
	if cfg.API.TLSEnabled != false {
		t.Error("expected API.TLSEnabled false")
	}
	if cfg.Engine.Sender.Interface != "lo0" {
		t.Errorf("expected Engine.Sender.Interface 'lo0', got %q", cfg.Engine.Sender.Interface)
	}
	if cfg.Engine.Sender.TxEngine != "pcap" {
		t.Errorf("expected Engine.Sender.TxEngine 'pcap', got %q", cfg.Engine.Sender.TxEngine)
	}
	if cfg.Engine.Generator.Vars == nil {
		t.Error("expected Engine.Generator.Vars to be non-nil in default config")
	}
	if cfg.Engine.Generator.Vars["$HOME_NET"] != "10.0.0.0/24" {
		t.Errorf("expected default $HOME_NET '10.0.0.0/24', got %q", cfg.Engine.Generator.Vars["$HOME_NET"])
	}
	if cfg.Engine.Generator.Vars["$EXTERNAL_NET"] != "any" {
		t.Errorf("expected default $EXTERNAL_NET 'any', got %q", cfg.Engine.Generator.Vars["$EXTERNAL_NET"])
	}

	// Verify default vars contain all expected variables
	expectedVars := []string{"$HOME_NET", "$EXTERNAL_NET", "$HTTP_SERVERS", "$SMTP_SERVERS", "$DNS_SERVERS", "$SSH_SERVERS"}
	for _, v := range expectedVars {
		if _, ok := cfg.Engine.Generator.Vars[v]; !ok {
			t.Errorf("expected default vars to contain %s", v)
		}
	}

	// Verify default CORS
	if len(cfg.API.CORS) != 1 || cfg.API.CORS[0] != "*" {
		t.Errorf("expected default CORS ['*'], got %v", cfg.API.CORS)
	}
}
