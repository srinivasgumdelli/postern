package relay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"postern/internal/envelope"
	"postern/internal/tlsutil/tlstest"
	"postern/internal/ulid"
)

type mtlsFixture struct {
	srv    *Server
	ca     *tlstest.CA
	peerA  tlstest.ClientCert
	peerB  tlstest.ClientCert
	keys   map[string]keyPair
	server tls.Certificate
	dir    string
}

func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()
	ca := tlstest.NewCA(t)
	fx := &mtlsFixture{
		ca:     ca,
		peerA:  ca.ClientCert(t, "peer-a"),
		peerB:  ca.ClientCert(t, "peer-b"),
		server: ca.ServerCert(t),
		keys:   map[string]keyPair{},
		dir:    t.TempDir(),
	}
	for _, p := range []string{"peer-a", "peer-b"} {
		pub, priv, err := envelope.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		fx.keys[p] = keyPair{pub, priv}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(fx.server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	files := &TLSFiles{
		CertFile:     filepath.Join(fx.dir, "server.pem"),
		KeyFile:      filepath.Join(fx.dir, "server-key.pem"),
		ClientCAFile: filepath.Join(fx.dir, "client-ca.pem"),
	}
	writePEM(t, files.CertFile, "CERTIFICATE", fx.server.Certificate[0])
	writePEM(t, files.KeyFile, "PRIVATE KEY", keyDER)
	if err := os.WriteFile(files.ClientCAFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(filepath.Join(fx.dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := New(Config{
		Identity: IdentityMTLS,
		TLS:      files,
		Peers: map[string][]string{
			"peer-a": {fx.peerA.Fingerprint},
			"peer-b": {fx.peerB.Fingerprint},
		},
	}, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	fx.srv = srv
	return fx
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// start serves the relay the way the end-to-end test does: httptest with
// a caller-supplied tls.Config.
func (fx *mtlsFixture) start(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	hs := httptest.NewUnstartedServer(fx.srv.Handler())
	hs.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	hs.TLS = cfg
	hs.StartTLS()
	t.Cleanup(hs.Close)
	return hs
}

func (fx *mtlsFixture) client(certs ...tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				RootCAs:      fx.ca.Pool(),
				Certificates: certs,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

func (fx *mtlsFixture) seal(t *testing.T, from, to string) (envelope.Envelope, []byte) {
	t.Helper()
	e, err := envelope.Seal(envelope.Message{
		ID: ulid.New(), From: from, To: to, Thread: envelope.NewThreadID(), TS: time.Now().Unix(),
		Session: "build", Subject: "hello", Body: "world",
	}, fx.keys[to].pub, fx.keys[from].priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	return e, raw
}

func doReq(t *testing.T, c *http.Client, method, url string, body []byte, hdr map[string]string) (int, string, error) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return resp.StatusCode, e.Error, nil
}

func TestMTLSIdentityFromVerifiedClientCert(t *testing.T) {
	fx := newMTLSFixture(t)
	verifyCfg := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    fx.ca.Pool(),
		Certificates: []tls.Certificate{fx.server},
		MinVersion:   tls.VersionTLS12,
	}
	fromRelay, err := fx.srv.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fromRelay.ClientAuth != tls.RequireAndVerifyClientCert || fromRelay.MinVersion != tls.VersionTLS12 || fromRelay.ClientCAs == nil {
		t.Fatalf("ServerTLSConfig is not strict: %+v", fromRelay)
	}
	for name, cfg := range map[string]*tls.Config{"caller tls.Config": verifyCfg, "ServerTLSConfig": fromRelay} {
		t.Run(name, func(t *testing.T) {
			hs := fx.start(t, cfg)
			a, b := fx.client(fx.peerA.TLS), fx.client(fx.peerB.TLS)

			e, raw := fx.seal(t, "peer-a", "peer-b")
			if st, code, err := doReq(t, a, http.MethodPost, hs.URL+"/v1/msg", raw, nil); err != nil || st != http.StatusCreated {
				t.Fatalf("post as peer-a: %d %s %v", st, code, err)
			}
			// peer-b's certificate cannot post as peer-a.
			_, forged := fx.seal(t, "peer-a", "peer-b")
			if st, code, err := doReq(t, b, http.MethodPost, hs.URL+"/v1/msg", forged, nil); err != nil || st != http.StatusForbidden || code != "forbidden" {
				t.Fatalf("forged post: %d %s %v", st, code, err)
			}
			// In mtls mode the fingerprint header is ignored: peer-b claiming
			// peer-a's fingerprint is still peer-b.
			hdr := map[string]string{DefaultFingerprintHeader: fx.peerA.Fingerprint}
			if st, code, err := doReq(t, b, http.MethodPost, hs.URL+"/v1/msg", forged, hdr); err != nil || st != http.StatusForbidden || code != "forbidden" {
				t.Fatalf("header-forged post: %d %s %v", st, code, err)
			}
			if st, _, err := doReq(t, a, http.MethodGet, hs.URL+"/v1/poll?to=peer-b&timeout=0", nil, nil); err != nil || st != http.StatusForbidden {
				t.Fatalf("peer-a polled peer-b: %d %v", st, err)
			}
			if st, _, err := doReq(t, b, http.MethodGet, hs.URL+"/v1/poll?to=peer-b&timeout=0", nil, nil); err != nil || st != http.StatusOK {
				t.Fatalf("peer-b poll: %d %v", st, err)
			}
			if st, _, err := doReq(t, b, http.MethodPost, hs.URL+"/v1/ack/"+e.ID, []byte(`{"to":"peer-b"}`), nil); err != nil || st != http.StatusOK {
				t.Fatalf("peer-b ack: %d %v", st, err)
			}
		})
	}
}

func TestMTLSClientWithoutValidCertCannotCompleteRequest(t *testing.T) {
	fx := newMTLSFixture(t)
	cfg, err := fx.srv.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	hs := fx.start(t, cfg)
	other := tlstest.NewCA(t).ClientCert(t, "peer-a")
	for name, c := range map[string]*http.Client{
		"no certificate":              fx.client(),
		"certificate from another CA": fx.client(other.TLS),
	} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{"/healthz", "/v1/poll?to=peer-a&timeout=0"} {
				st, _, err := doReq(t, c, http.MethodGet, hs.URL+path, nil, nil)
				if err == nil {
					t.Fatalf("%s: request completed with status %d", path, st)
				}
			}
		})
	}
}

func TestMTLSKnownCAButUnknownFingerprint403(t *testing.T) {
	fx := newMTLSFixture(t)
	cfg, err := fx.srv.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	hs := fx.start(t, cfg)
	stranger := fx.ca.ClientCert(t, "peer-a") // right CA and CN, wrong certificate
	st, code, err := doReq(t, fx.client(stranger.TLS), http.MethodGet, hs.URL+"/v1/poll?to=peer-a&timeout=0", nil, nil)
	if err != nil || st != http.StatusForbidden || code != "forbidden" {
		t.Fatalf("stranger poll: %d %s %v", st, code, err)
	}
}

func TestMTLSModeWithoutTLSHasNoIdentity(t *testing.T) {
	fx := newMTLSFixture(t)
	hs := httptest.NewServer(fx.srv.Handler()) // plain HTTP: no verified certificate
	defer hs.Close()
	hdr := map[string]string{DefaultFingerprintHeader: fx.peerA.Fingerprint}
	st, code, err := doReq(t, hs.Client(), http.MethodGet, hs.URL+"/v1/poll?to=peer-a&timeout=0", nil, hdr)
	if err != nil || st != http.StatusUnauthorized || code != "no_identity" {
		t.Fatalf("plain poll in mtls mode: %d %s %v", st, code, err)
	}
}

func TestMTLSUnverifiedCertificateIsNotAnIdentity(t *testing.T) {
	// If someone serves the handler with a TLS config that requests but
	// does not verify client certificates, the relay still refuses.
	fx := newMTLSFixture(t)
	hs := fx.start(t, &tls.Config{
		ClientAuth:   tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{fx.server},
	})
	st, code, err := doReq(t, fx.client(fx.peerA.TLS), http.MethodGet, hs.URL+"/v1/poll?to=peer-a&timeout=0", nil, nil)
	if err != nil || st != http.StatusUnauthorized || code != "no_identity" {
		t.Fatalf("unverified cert poll: %d %s %v", st, code, err)
	}
}

func TestServerTLSConfigBadFiles(t *testing.T) {
	fx := newMTLSFixture(t)
	if err := os.WriteFile(fx.srv.cfg.TLS.ClientCAFile, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.srv.ServerTLSConfig(); err == nil {
		t.Fatal("ServerTLSConfig accepted a CA file with no certificates")
	}
	if err := os.Remove(fx.srv.cfg.TLS.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.srv.ServerTLSConfig(); err == nil {
		t.Fatal("ServerTLSConfig worked without a key file")
	}
}
