package bridge

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
)

// TestTransportIgnoresProxyEnv: an agent that can set HTTPS_PROXY must
// not be able to route bridge traffic. The relay is addressed by a
// non-loopback name (Go never proxies loopback hosts, which would make
// this test vacuous) and the name is resolved by a test dialer; if the
// transport honoured the proxy variable it would dial 127.0.0.1:1 and
// fail.
func TestTransportIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	w := newWorld(t)
	relay := newFakeRelay(t, w.ca, w.clock, "relay.test")
	relay.bind(w.a.cert.Fingerprint, w.a.name)
	_, port, err := net.SplitHostPort(relay.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	o := w.options(w.a, "", w.b)
	o.RelayURL = "https://relay.test:" + port
	a := w.open(o)

	if a.client.tr.Proxy != nil {
		t.Fatal("transport has a proxy function")
	}
	real := relay.srv.Listener.Addr().String()
	a.client.tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "relay.test:"+port {
			addr = real
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	subject, body := msg("proxy", "proxy")
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if res.Status != StatusSent {
		t.Fatalf("status = %s; want sent (proxy env must be ignored)", res.Status)
	}
	if len(relay.acceptedPosts()) != 1 {
		t.Fatal("relay did not receive the post")
	}
}

// TestRedirectNotFollowed: a redirect from the relay must not move the
// post (or the client certificate handshake) to another server.
func TestRedirectNotFollowed(t *testing.T) {
	w := newWorld(t)
	evil := newFakeRelay(t, w.ca, w.clock)
	evil.bind(w.a.cert.Fingerprint, w.a.name)
	a, _ := w.pair()
	w.relay.setRedirect(evil.URL() + "/v1/msg")

	subject, body := msg("redirect", "redirect")
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if res.Status != StatusQueued {
		t.Fatalf("status = %s; want queued", res.Status)
	}
	if n := evil.requestCount(); n != 0 {
		t.Fatalf("redirect target received %d requests", n)
	}
}

func TestRelayCertificateMustVerify(t *testing.T) {
	w := newWorld(t)
	o := w.options(w.a, "", w.b)
	o.RootCAs = nil // system roots do not trust the test CA
	a := w.open(o)
	subject, body := msg("tls", "tls")
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if res.Status != StatusQueued || len(w.relay.acceptedPosts()) != 0 {
		t.Fatalf("status = %s with an untrusted relay certificate", res.Status)
	}
}

func TestParseRelayURL(t *testing.T) {
	good := map[string]string{
		"https://relay.example.com":         "https://relay.example.com",
		"https://relay.example.com/":        "https://relay.example.com",
		"https://relay.example.com:8443/pf": "https://relay.example.com:8443/pf",
	}
	for in, want := range good {
		got, err := parseRelayURL(in)
		if err != nil || got != want {
			t.Errorf("parseRelayURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "http://relay.example.com", "relay.example.com", "https://", "https://u:p@relay.example.com",
		"https://relay.example.com/?a=b", "https://relay.example.com/#f", "ftp://relay.example.com",
	} {
		if _, err := parseRelayURL(bad); err == nil {
			t.Errorf("parseRelayURL(%q) accepted", bad)
		}
	}
}

func TestNetReasonNeverEchoesURL(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://relay.example.com/v1/poll?to=peer-a&after=1", Err: errors.New("boom")}
	if r := netReason(err); r != "network" {
		t.Fatalf("netReason = %q", r)
	}
	if r := netReason(context.Canceled); r != "canceled" {
		t.Fatalf("netReason(canceled) = %q", r)
	}
}
