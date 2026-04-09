package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type middlewares struct {
	auth      AuthConfig
	cors      []string
	rateLimit int
}

type rateLimitEntry struct {
	count     int
	lastReset time.Time
}

var (
	rateLimitMap = make(map[string]*rateLimitEntry)
	rateLimitMu  sync.Mutex
)

func NewRouter(h *Handlers, auth AuthConfig, cors []string, rateLimit int) *mux.Router {
	m := &middlewares{
		auth:      auth,
		cors:      cors,
		rateLimit: rateLimit,
	}

	r := mux.NewRouter()

	r.Use(m.loggingMiddleware)
	r.Use(m.recoveryMiddleware)

	if auth.Enabled {
		r.Use(m.authMiddleware)
	}

	if len(cors) > 0 {
		r.Use(m.corsMiddleware)
	}

	if rateLimit > 0 {
		r.Use(m.rateLimitMiddleware)
	}

	r.HandleFunc("/api/v1/rules/upload", h.UploadRules).Methods("POST")
	r.HandleFunc("/api/v1/rules/parse", h.ParseRules).Methods("POST")
	r.HandleFunc("/api/v1/tests/run", h.RunTests).Methods("POST")
	r.HandleFunc("/api/v1/tests/results", h.GetTestResults).Methods("GET")
	r.HandleFunc("/api/v1/health", h.HealthCheck).Methods("GET")

	return r
}

func (m *middlewares) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		_ = time.Since(start)
	})
}

func (m *middlewares) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (m *middlewares) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		if token != m.auth.Token {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *middlewares) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		for _, allowed := range m.cors {
			if allowed == "*" || allowed == origin {
				w.Header().Set("Access-Control-Allow-Origin", allowed)
				break
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *middlewares) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		rateLimitMu.Lock()
		defer rateLimitMu.Unlock()

		now := time.Now()
		entry, exists := rateLimitMap[ip]

		if !exists || now.Sub(entry.lastReset) > time.Second {
			rateLimitMap[ip] = &rateLimitEntry{
				count:     1,
				lastReset: now,
			}
			next.ServeHTTP(w, r)
			return
		}

		if entry.count >= m.rateLimit {
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(m.rateLimit))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		entry.count++
		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}
