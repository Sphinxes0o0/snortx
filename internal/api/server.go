package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Server struct {
	srv        *http.Server
	router     *mux.Router
	handlers   *Handlers
	tlsEnabled bool
	tlsCert    string
	tlsKey     string
}

type ServerConfig struct {
	Address    string
	OutputDir  string
	Auth       AuthConfig
	CORS       []string
	RateLimit  int
	TLSEnabled bool
	TLSCert    string
	TLSKey     string
}

type AuthConfig struct {
	Enabled bool
	Token   string
}

func NewServer(cfg ServerConfig) *Server {
	h := NewHandlers(cfg.OutputDir)
	router := NewRouter(h, cfg.Auth, cfg.CORS, cfg.RateLimit)

	srv := &Server{
		srv: &http.Server{
			Addr:         cfg.Address,
			Handler:      router,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		router:     router,
		handlers:   h,
		tlsEnabled: cfg.TLSEnabled,
		tlsCert:    cfg.TLSCert,
		tlsKey:     cfg.TLSKey,
	}

	return srv
}

func (s *Server) Start() error {
	if s.tlsEnabled {
		if s.tlsCert == "" || s.tlsKey == "" {
			return fmt.Errorf("tls enabled but tls_cert or tls_key is empty")
		}
		return s.srv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}
	return s.srv.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
