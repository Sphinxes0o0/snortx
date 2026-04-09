package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/snortx/internal/api"
)

var (
	listenAddr  string
	outputDir   string
	authToken   string
	corsOrigins string
	rateLimit   int
)

var rootCmd = &cobra.Command{
	Use:   "snortx",
	Short: "Snort rule testing tool",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the REST API server",
	RunE:  startServer,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVar(&listenAddr, "addr", ":8080", "Listen address")
	serveCmd.Flags().StringVarP(&outputDir, "output", "o", "./output", "Output directory")
	serveCmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token for API authentication")
	serveCmd.Flags().StringVar(&corsOrigins, "cors", "", "Comma-separated list of allowed CORS origins")
	serveCmd.Flags().IntVar(&rateLimit, "rate-limit", 100, "Rate limit (requests per second)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startServer(cmd *cobra.Command, args []string) error {
	cors := []string{}
	if corsOrigins != "" {
		for _, origin := range strings.Split(corsOrigins, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" {
				cors = append(cors, origin)
			}
		}
	}

	srv := api.NewServer(api.ServerConfig{
		Address:   listenAddr,
		OutputDir: outputDir,
		Auth: api.AuthConfig{
			Enabled: authToken != "",
			Token:   authToken,
		},
		CORS:      cors,
		RateLimit: rateLimit,
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	fmt.Printf("Starting API server on %s\n", listenAddr)
	fmt.Printf("Output directory: %s\n", outputDir)
	if authToken != "" {
		fmt.Println("Auth: enabled (Bearer token)")
	}
	if len(cors) > 0 {
		fmt.Printf("CORS: %v\n", cors)
	}
	fmt.Printf("Rate limit: %d req/s\n", rateLimit)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case sig := <-sigCh:
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Stop(ctx); err != nil {
			return fmt.Errorf("shutdown error: %w", err)
		}
		fmt.Println("Server stopped gracefully")
	}

	return nil
}
