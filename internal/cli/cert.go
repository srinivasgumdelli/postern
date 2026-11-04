package cli

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"time"

	"postern/internal/secrets"
	"postern/internal/tlsutil"
)

// nextTLSKey holds a rotated client key until its certificate arrives,
// so the current certificate keeps working during rotation.
const nextTLSKey = "tls-private-key-next"

func cmdCertCSR(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "cert csr")
	newKey := fs.Bool("new-key", false, "generate a new client key for rotation (the current certificate keeps working)")
	out := fs.String("out", "", "write the CSR to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	name := secrets.TLSPrivateKey
	if *newKey {
		k, err := tlsutil.GenerateKey()
		if err != nil {
			return err
		}
		der, err := tlsutil.MarshalKey(k)
		if err != nil {
			return err
		}
		if err := l.store.Set(nextTLSKey, der); err != nil {
			return fmt.Errorf("store new tls key: %w", err)
		}
		clear(der)
		name = nextTLSKey
	}
	key, err := loadTLSKey(l.store, name)
	if err != nil {
		return err
	}
	csr, err := tlsutil.CreateCSR(key, l.cfg.PeerName)
	if err != nil {
		return err
	}
	if *out != "" {
		return os.WriteFile(*out, csr, 0o644)
	}
	_, err = env.Stdout.Write(csr)
	return err
}

func cmdCertImport(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "cert import")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("expected one certificate PEM file")
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	pemBytes, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	cert, err := tlsutil.ParseCertPEM(pemBytes)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("certificate has expired")
	}
	current, err := loadTLSKey(l.store, secrets.TLSPrivateKey)
	if err != nil {
		return err
	}
	switch {
	case tlsutil.CertMatchesKey(cert, current):
	default:
		next, err := loadTLSKey(l.store, nextTLSKey)
		if err != nil || !tlsutil.CertMatchesKey(cert, next) {
			return errors.New("certificate does not match this bridge's client key (or a pending rotated key)")
		}
		nextDER, err := l.store.Get(nextTLSKey)
		if err != nil {
			return err
		}
		if err := l.store.Set(secrets.TLSPrivateKey, nextDER); err != nil {
			return fmt.Errorf("promote rotated key: %w", err)
		}
		clear(nextDER)
		if err := l.store.Delete(nextTLSKey); err != nil {
			return fmt.Errorf("remove pending key: %w", err)
		}
		fmt.Fprintln(env.Stdout, "Rotated: the new client key is now active.")
	}
	if err := l.store.Set(secrets.TLSCertificate, pemBytes); err != nil {
		return fmt.Errorf("store certificate: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Imported client certificate for %s.\nSHA-256: %s\nExpires: %s\n",
		l.cfg.PeerName, tlsutil.Fingerprint(cert.Raw), cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintln(env.Stdout, "Add the SHA-256 under this peer in the relay's relay.json, then run `postern edge-check`.")
	return nil
}

func loadTLSKey(store secrets.Store, name string) (*ecdsa.PrivateKey, error) {
	der, err := store.Get(name)
	if err != nil {
		return nil, fmt.Errorf("load %s from keychain: %w", name, err)
	}
	defer clear(der)
	return tlsutil.ParseKey(der)
}
