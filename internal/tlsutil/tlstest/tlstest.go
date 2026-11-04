// Package tlstest provides a throwaway CA and certificates for tests.
// It stands in for the edge's client certificate authority.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"postern/internal/tlsutil"
)

// CA is a test certificate authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// ClientCert is a client certificate issued by a test CA.
type ClientCert struct {
	TLS         tls.Certificate
	CertPEM     []byte
	KeyDER      []byte
	Fingerprint string
}

// NewCA creates a fresh CA.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key, err := tlsutil.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "postern test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Pool returns a pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// CertPEM returns the CA certificate in PEM form.
func (c *CA) CertPEM() []byte { return c.pem }

// ServerCert issues a server certificate for the given hosts (DNS names
// or IP addresses). With no hosts it covers 127.0.0.1 and localhost.
func (c *CA) ServerCert(t testing.TB, hosts ...string) tls.Certificate {
	t.Helper()
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	cc := c.issue(t, tmpl)
	return cc.TLS
}

// ClientCert issues a client certificate with the given common name.
func (c *CA) ClientCert(t testing.TB, cn string) ClientCert {
	t.Helper()
	return c.issue(t, &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

func (c *CA) issue(t testing.TB, tmpl *x509.Certificate) ClientCert {
	t.Helper()
	key, err := tlsutil.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := tlsutil.MarshalKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tc, err := tlsutil.ClientCertificate(certPEM, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	return ClientCert{TLS: tc, CertPEM: certPEM, KeyDER: keyDER, Fingerprint: tlsutil.Fingerprint(der)}
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
