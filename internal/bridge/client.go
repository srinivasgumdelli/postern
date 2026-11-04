package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"postern/internal/envelope"
)

const (
	// A poll returns at most 50 envelopes of at most 48 KB each.
	maxPollResponseBytes = 4 << 20
	maxDrainBytes        = 64 << 10
	// pollGrace is added to the long-poll timeout for the request deadline.
	pollGrace = 10 * time.Second
)

var errBadResponse = errors.New("bridge: malformed relay response")

// relayClient talks to the relay over HTTPS with the client certificate.
//
// It deliberately ignores proxy environment variables (Proxy: nil): an
// agent that can set HTTPS_PROXY in the bridge's environment must not be
// able to route traffic through a host of its choosing. It never follows
// redirects, so a hostile or misconfigured redirect cannot move traffic
// (or the client certificate handshake) elsewhere.
type relayClient struct {
	base        string
	tr          *http.Transport
	hc          *http.Client
	pollTimeout time.Duration
}

// parseRelayURL checks that raw is an https URL with a host and no
// credentials, query or fragment, and returns it without a trailing slash.
func parseRelayURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("bridge: relay URL must be an https URL with a host and no credentials, query or fragment")
	}
	return "https://" + u.Host + strings.TrimRight(u.EscapedPath(), "/"), nil
}

func newRelayClient(base string, cert tls.Certificate, roots *x509.CertPool, pollTimeout time.Duration) *relayClient {
	tr := &http.Transport{
		Proxy: nil, // never use proxy env vars
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS12,
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    10 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &relayClient{
		base: base,
		tr:   tr,
		hc: &http.Client{
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		pollTimeout: pollTimeout,
	}
}

func (c *relayClient) pollSeconds() int {
	return int(c.pollTimeout / time.Second)
}

// post sends one sealed envelope and returns the HTTP status.
func (c *relayClient) post(ctx context.Context, e envelope.Envelope) (int, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/msg", bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	drainClose(resp.Body)
	return resp.StatusCode, nil
}

type pollResponse struct {
	Envelopes []json.RawMessage `json:"envelopes"`
	Cursor    int64             `json:"cursor"`
}

// poll long-polls the mailbox for to. A non-200 status is returned with a
// nil error.
func (c *relayClient) poll(ctx context.Context, to string, after int64) (pollResponse, int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.pollTimeout+pollGrace)
	defer cancel()
	q := url.Values{
		"to":      {to},
		"after":   {strconv.FormatInt(after, 10)},
		"timeout": {strconv.Itoa(c.pollSeconds())},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/poll?"+q.Encode(), nil)
	if err != nil {
		return pollResponse{}, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return pollResponse{}, 0, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return pollResponse{}, resp.StatusCode, nil
	}
	var pr pollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPollResponseBytes)).Decode(&pr); err != nil {
		return pollResponse{}, resp.StatusCode, errBadResponse
	}
	return pr, resp.StatusCode, nil
}

// ack confirms delivery of id from the mailbox for to.
func (c *relayClient) ack(ctx context.Context, to, id string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, ackTimeout)
	defer cancel()
	raw, err := json.Marshal(struct {
		To string `json:"to"`
	}{to})
	if err != nil {
		return 0, err
	}
	// id is a validated ULID, so it is safe in a path segment.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/ack/"+id, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	drainClose(resp.Body)
	return resp.StatusCode, nil
}

func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxDrainBytes))
	rc.Close()
}

// netReason classifies a transport error into a short, log-safe code.
// Raw transport errors are never logged: *url.Error embeds the request
// URL, including the query string.
func netReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errBadResponse):
		return "bad_response"
	}
	var (
		unknownCA   x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certInvalid x509.CertificateInvalidError
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
		dnsErr      *net.DNSError
		opErr       *net.OpError
		netErr      net.Error
	)
	switch {
	case errors.As(err, &unknownCA):
		return "tls_unknown_authority"
	case errors.As(err, &hostErr):
		return "tls_hostname"
	case errors.As(err, &certInvalid):
		return "tls_certificate_invalid"
	case errors.As(err, &verifyErr):
		return "tls_verify"
	case errors.As(err, &recordErr):
		return "tls_record"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "connect"
	case errors.As(err, &opErr) && opErr.Op == "remote error":
		return "tls_remote_alert"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}
	return "network"
}
