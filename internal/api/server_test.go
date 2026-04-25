package api

import (
	"strings"
	"testing"
)

func TestServerStart_TLSMissingCertOrKey(t *testing.T) {
	s := NewServer(ServerConfig{
		Address:    "127.0.0.1:0",
		OutputDir:  t.TempDir(),
		TLSEnabled: true,
	})

	err := s.Start()
	if err == nil {
		t.Fatal("expected tls configuration error")
	}
	if !strings.Contains(err.Error(), "tls enabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}
