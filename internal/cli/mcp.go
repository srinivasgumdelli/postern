package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"postern/internal/bridge"
	"postern/internal/envelope"
	"postern/internal/mcpserver"
	"postern/internal/scan"
	"postern/internal/secrets"
	"postern/internal/tlsutil"
)

func cmdMCP(ctx context.Context, env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "mcp")
	session := fs.String("session", "", "name of the agent session using this server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *session == "" {
		return errors.New("--session is required")
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	if !l.cfg.HasSession(*session) {
		return fmt.Errorf("session %q is not allowed to use this bridge; the human can add it with `postern session add %s`", *session, *session)
	}
	if len(l.cfg.Peers) == 0 {
		return errors.New("no peers configured (postern peer add)")
	}
	logger := slog.New(slog.NewJSONHandler(env.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("session", *session)
	opts, err := bridgeOptions(l, logger)
	if err != nil {
		return err
	}
	al, err := openAudit(l.cfg)
	if err != nil {
		return err
	}
	if al != nil {
		defer al.Close()
		opts.Audit = al
	}
	b, err := bridge.Open(opts)
	if err != nil {
		return err
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	var t mcp.Transport = &mcp.StdioTransport{}
	if env.MCPTransport != nil {
		t = env.MCPTransport
	}
	srv := mcpserver.New(service{b}, *session, env.Version)
	err = srv.Run(ctx, t)
	cancel()
	<-done
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// bridgeOptions loads keys from the keychain and builds bridge options.
func bridgeOptions(l *loaded, logger *slog.Logger) (bridge.Options, error) {
	c := l.cfg
	box, err := loadBoxKey(l.store)
	if err != nil {
		return bridge.Options{}, err
	}
	inboxKey, err := loadInboxKey(l.store)
	if err != nil {
		return bridge.Options{}, err
	}
	cert, err := loadClientCert(l.store)
	if err != nil {
		return bridge.Options{}, err
	}
	if time.Now().After(cert.Leaf.NotAfter) {
		return bridge.Options{}, errors.New("client certificate has expired; rotate it (postern cert csr --new-key)")
	}
	var roots *x509.CertPool
	if c.RelayCAFile != "" {
		pemBytes, err := os.ReadFile(c.RelayCAFile)
		if err != nil {
			return bridge.Options{}, fmt.Errorf("read relay CA file: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return bridge.Options{}, errors.New("relay CA file holds no certificates")
		}
	}
	var peers []bridge.Peer
	for _, p := range c.Peers {
		k, err := envelope.DecodeKey(p.PublicKey)
		if err != nil {
			return bridge.Options{}, fmt.Errorf("peer %s: %w", p.Name, err)
		}
		peers = append(peers, bridge.Peer{Name: p.Name, PublicKey: k})
	}
	lim := c.EffectiveLimits()
	return bridge.Options{
		Scanner:    scan.Check,
		Self:       c.PeerName,
		BoxPrivate: box,
		InboxKey:   inboxKey,
		// After a rotation the human imports a new certificate while
		// sessions keep running; the bridge re-reads it on a 401/403.
		ReloadClientCert: func() (tls.Certificate, error) { return loadClientCert(l.store) },
		Peers:            peers,
		RelayURL:         c.RelayURL,
		ClientCert:       cert,
		RootCAs:          roots,
		DBPath:           c.DBPath(),
		Limits: bridge.Limits{
			SessionPerHour:    lim.SessionPerHour,
			GlobalPerHour:     lim.GlobalPerHour,
			ThreadMax:         lim.ThreadMax,
			ThreadBurst:       lim.ThreadBurst,
			ThreadBurstWindow: time.Duration(lim.ThreadBurstWindowMinutes) * time.Minute,
		},
		MessageRetention: time.Duration(lim.MessageRetentionDays) * 24 * time.Hour,
		Logger:           logger,
	}, nil
}

func loadClientCert(store secrets.Store) (tls.Certificate, error) {
	keyDER, err := store.Get(secrets.TLSPrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load client key from keychain: %w", err)
	}
	defer clear(keyDER)
	certPEM, err := store.Get(secrets.TLSCertificate)
	if err != nil {
		return tls.Certificate{}, errors.New("no client certificate imported yet (postern cert import FILE)")
	}
	return tlsutil.ClientCertificate(certPEM, keyDER)
}

func loadInboxKey(store secrets.Store) (*[32]byte, error) {
	b, err := store.Get(secrets.InboxKey)
	if err != nil {
		return nil, fmt.Errorf("load inbox key from keychain: %w", err)
	}
	defer clear(b)
	if len(b) != 32 {
		return nil, errors.New("inbox key in keychain has the wrong length")
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}

// clientTLS returns a TLS config for talking to the relay, with or
// without the client certificate.
func clientTLS(opts bridge.Options, withCert bool) *tls.Config {
	tc := &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12}
	if withCert {
		tc.Certificates = []tls.Certificate{opts.ClientCert}
	}
	return tc
}

// service adapts the bridge to the MCP server's interface.
type service struct{ b *bridge.Bridge }

func (s service) Send(ctx context.Context, session string, in mcpserver.SendInput) (mcpserver.SendOutput, error) {
	r, err := s.b.Send(ctx, session, bridge.SendRequest{To: in.To, Subject: in.Subject, Body: in.Body, Thread: in.Thread})
	return mcpserver.SendOutput{ID: r.ID, Thread: r.Thread, Status: r.Status}, err
}

func (s service) Reply(ctx context.Context, session string, in mcpserver.ReplyInput) (mcpserver.SendOutput, error) {
	r, err := s.b.Reply(ctx, session, in.Thread, in.Body)
	return mcpserver.SendOutput{ID: r.ID, Thread: r.Thread, Status: r.Status}, err
}

func (s service) CheckInbox(ctx context.Context, in mcpserver.CheckInboxInput) ([]mcpserver.Message, error) {
	msgs, err := s.b.CheckInbox(ctx, bridge.InboxQuery{SinceID: in.SinceID, Limit: in.Limit, Thread: in.Thread, IncludeRead: in.IncludeRead})
	if err != nil {
		return nil, err
	}
	out := make([]mcpserver.Message, len(msgs))
	for i, m := range msgs {
		out[i] = mcpserver.Message{
			ID: m.ID, Thread: m.Thread, FromPeer: m.FromPeer, FromSession: m.FromSession,
			Subject: m.Subject, Body: m.Body, ReceivedAt: m.ReceivedAt,
		}
	}
	return out, nil
}

func (s service) MarkRead(ctx context.Context, ids []string) (int, error) {
	return s.b.MarkRead(ctx, ids)
}

// RelayStatus lets the MCP server tell the agent when the relay is
// rejecting this bridge or unreachable.
func (s service) RelayStatus() string { return s.b.RelayStatus() }
