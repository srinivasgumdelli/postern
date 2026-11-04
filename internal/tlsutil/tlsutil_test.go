package tlsutil_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"postern/internal/tlsutil"
	"postern/internal/tlsutil/tlstest"
)

func TestKeyRoundTrip(t *testing.T) {
	k, err := tlsutil.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := tlsutil.MarshalKey(k)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := tlsutil.ParseKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(k2) {
		t.Fatal("key changed in round trip")
	}
	if _, err := tlsutil.ParseKey([]byte("junk")); err == nil {
		t.Fatal("junk key parsed")
	}
}

func TestCSR(t *testing.T) {
	k, _ := tlsutil.GenerateKey()
	p, err := tlsutil.CreateCSR(k, "peer-a")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM block: %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "peer-a" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
}

func TestClientCertificateMatchAndMismatch(t *testing.T) {
	ca := tlstest.NewCA(t)
	a := ca.ClientCert(t, "peer-a")
	b := ca.ClientCert(t, "peer-b")
	if _, err := tlsutil.ClientCertificate(a.CertPEM, a.KeyDER); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsutil.ClientCertificate(a.CertPEM, b.KeyDER); err == nil {
		t.Fatal("mismatched cert and key accepted")
	}
	cert, err := tlsutil.ParseCertPEM(a.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if tlsutil.Fingerprint(cert.Raw) != a.Fingerprint || len(a.Fingerprint) != 64 {
		t.Fatalf("fingerprint %q", a.Fingerprint)
	}
}

func TestParseCertPEMSkipsOtherBlocks(t *testing.T) {
	ca := tlstest.NewCA(t)
	a := ca.ClientCert(t, "peer-a")
	other := pem.EncodeToMemory(&pem.Block{Type: "OTHER", Bytes: []byte{1}})
	if _, err := tlsutil.ParseCertPEM(append(other, a.CertPEM...)); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsutil.ParseCertPEM(other); err == nil {
		t.Fatal("PEM with no certificate accepted")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	got := tlsutil.NormalizeFingerprint(" AB:CD:ef 01 ")
	if got != "abcdef01" {
		t.Fatalf("got %q", got)
	}
}
