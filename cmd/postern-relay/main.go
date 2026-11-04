// Command postern-relay runs the Postern relay.
//
//	postern-relay [-config /etc/postern/relay.json]
//	postern-relay healthcheck [-url http://127.0.0.1:8080/healthz]
//
// The healthcheck subcommand exists for the container healthcheck: the
// runtime image is distroless and has no shell or curl.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"postern/internal/relay"
)

const (
	defaultConfigPath  = "/etc/postern/relay.json"
	defaultHealthURL   = "http://127.0.0.1:8080/healthz"
	expiryInterval     = time.Minute
	shutdownGrace      = 30 * time.Second
	healthcheckTimeout = 5 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "healthcheck" {
		return healthcheck(args[1:], stderr)
	}
	fs := flag.NewFlagSet("postern-relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "path to the relay configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "postern-relay: unexpected arguments")
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := relay.LoadConfig(*configPath)
	if err != nil {
		logger.Error("cannot load config", "err", err)
		return 1
	}
	st, err := relay.OpenStore(cfg.DB)
	if err != nil {
		logger.Error("cannot open store", "err", err)
		return 1
	}
	defer st.Close()
	srv, err := relay.New(cfg, st, logger)
	if err != nil {
		logger.Error("cannot start relay", "err", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Cancelling baseCtx ends in-flight long-polls promptly on shutdown;
	// they answer with an empty batch and the bridge simply polls again.
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      40 * time.Second, // long-poll holds up to 25s
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		ErrorLog:          log.New(serverErrorWriter{logger}, "", 0),
	}
	if cfg.Identity == relay.IdentityMTLS {
		tlsCfg, err := srv.ServerTLSConfig()
		if err != nil {
			logger.Error("cannot load TLS config", "err", err)
			return 1
		}
		hs.TLSConfig = tlsCfg
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("cannot listen", "err", err)
		return 1
	}

	expiryDone := make(chan struct{})
	go func() {
		defer close(expiryDone)
		srv.RunExpiry(ctx, expiryInterval)
	}()

	serveErr := make(chan error, 1)
	go func() {
		if hs.TLSConfig != nil {
			serveErr <- hs.ServeTLS(ln, "", "") // certificate comes from TLSConfig
		} else {
			serveErr <- hs.Serve(ln)
		}
	}()
	logger.Info("relay listening", "listen", cfg.Listen, "identity", cfg.Identity, "peers", len(cfg.Peers))

	code := 0
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "err", err)
			code = 1
		}
	}
	stop()
	cancelBase()
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := hs.Shutdown(shCtx); err != nil {
		logger.Error("shutdown", "err", err)
		code = 1
	}
	<-expiryDone
	return code
}

// serverErrorWriter turns net/http's internal error log into a fixed
// event. Those lines carry the client's address (and TLS details), which
// the relay never logs.
type serverErrorWriter struct{ log *slog.Logger }

func (w serverErrorWriter) Write(p []byte) (int, error) {
	kind := "http_server_error"
	if strings.Contains(string(p), "TLS handshake error") {
		kind = "tls_handshake_error"
	}
	w.log.Warn("http server", "kind", kind)
	return len(p), nil
}

// healthcheck exits 0 when the relay answers 200 on /healthz, else 1.
func healthcheck(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("postern-relay healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", defaultHealthURL, "health endpoint to check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{
		Timeout:   healthcheckTimeout,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy: no response")
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "unhealthy: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
