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

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadDefault(t *testing.T) {
	cfg := LoadDefault()

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
	if cfg.Engine.Generator.Vars == nil {
		t.Error("expected Engine.Generator.Vars to be non-nil in default config")
	}
	if cfg.Engine.Generator.Vars["$HOME_NET"] != "10.0.0.0/24" {
		t.Errorf("expected default $HOME_NET '10.0.0.0/24', got %q", cfg.Engine.Generator.Vars["$HOME_NET"])
	}
	if cfg.Engine.Generator.Vars["$EXTERNAL_NET"] != "any" {
		t.Errorf("expected default $EXTERNAL_NET 'any', got %q", cfg.Engine.Generator.Vars["$EXTERNAL_NET"])
	}
}
