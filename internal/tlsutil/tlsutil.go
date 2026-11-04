// Package tlsutil handles the bridge's mTLS client key and certificate:
// key generation, CSRs for the edge, certificate parsing and fingerprints.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// GenerateKey returns a new P-256 key for the client certificate.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalKey encodes a key as PKCS#8 DER.
func MarshalKey(k *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(k)
}

// ParseKey decodes a PKCS#8 DER ECDSA key.
func ParseKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("tlsutil: cannot parse private key")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("tlsutil: private key is not ECDSA")
	}
	return ek, nil
}

// CreateCSR returns a PEM certificate signing request for key. The key
// never leaves the machine; only the CSR goes to the edge.
func CreateCSR(key *ecdsa.PrivateKey, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCertPEM returns the first certificate in pemBytes.
func ParseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("tlsutil: no certificate in PEM")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// CertMatchesKey reports whether cert's public key belongs to key.
func CertMatchesKey(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&key.PublicKey)
}

// Fingerprint returns the lowercase hex SHA-256 of a DER certificate,
// the same value the edge reports as the client cert fingerprint.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NormalizeFingerprint lower-cases a fingerprint and strips ':' and spaces.
func NormalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer(":", "", " ", "").Replace(s)
}

// ClientCertificate builds a tls.Certificate from a PEM certificate and
// a PKCS#8 DER key, checking that they match.
func ClientCertificate(certPEM, keyDER []byte) (tls.Certificate, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ParseKey(keyDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !CertMatchesKey(cert, key) {
		return tls.Certificate{}, errors.New("tlsutil: certificate does not match private key")
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, nil
}
