package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Server struct {
	srv      *http.Server
	router   *mux.Router
	handlers *Handlers
}

type ServerConfig struct {
	Address   string
	OutputDir string
	Auth      AuthConfig
	CORS      []string
	RateLimit int
}

type AuthConfig struct {
	Enabled bool
	Token   string
}

func NewServer(cfg ServerConfig) *Server {
	h := NewHandlers(cfg.OutputDir)
	router := NewRouter(h, cfg.Auth, cfg.CORS, cfg.RateLimit)

	return &Server{
		srv: &http.Server{
			Addr:         cfg.Address,
			Handler:      router,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		router:   router,
		handlers: h,
	}
}

func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
