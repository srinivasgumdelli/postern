package cli

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"postern/internal/config"
	"postern/internal/envelope"
	"postern/internal/secrets"
	"postern/internal/tlsutil"
)

func cmdInit(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "init")
	peerName := fs.String("peer-name", "", "this machine's peer name, e.g. peer-a")
	relayURL := fs.String("relay-url", "", "relay base URL, https only")
	service := fs.String("keychain-service", "postern", "keychain service name for this bridge's items")
	caFile := fs.String("relay-ca-file", "", "extra CA for the relay (dev and tests only)")
	force := fs.Bool("force", false, "replace an existing config and generate new keys")
	var sessions stringList
	fs.Var(&sessions, "session", "session allowed to use the bridge (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *peerName == "" || *relayURL == "" {
		return errors.New("--peer-name and --relay-url are required")
	}
	path, err := configPath(*cfgFlag)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("config already exists at %s (use --force to replace it and its keys)", path)
	}
	cfg := &config.Config{
		PeerName:        *peerName,
		RelayURL:        *relayURL,
		RelayCAFile:     *caFile,
		KeychainService: *service,
		Sessions:        []string(sessions),
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	store, err := env.OpenStore(cfg.KeychainService)
	if err != nil {
		return fmt.Errorf("open keychain: %w", err)
	}
	pinStore, err := env.OpenStore(config.PinService)
	if err != nil {
		return fmt.Errorf("open keychain: %w", err)
	}
	if !*force {
		if _, err := store.Get(secrets.BoxPrivateKey); err == nil {
			return fmt.Errorf("keychain service %q already holds a Postern key (use --force to replace it)", cfg.KeychainService)
		}
	}
	what := "Initialise this bridge: generate new keys and trust this config."
	if *force {
		what = "Re-initialise this bridge: REPLACE its keys (peers must re-pin the new public key) and trust this config."
	}
	if err := confirm(env, what+"\n\n"+describe(path, cfg)); err != nil {
		return err
	}

	pub, priv, err := envelope.GenerateKey()
	if err != nil {
		return err
	}
	defer clear(priv[:])
	if err := store.Set(secrets.BoxPrivateKey, priv[:]); err != nil {
		return fmt.Errorf("store box key: %w", err)
	}
	tlsKey, err := tlsutil.GenerateKey()
	if err != nil {
		return err
	}
	der, err := tlsutil.MarshalKey(tlsKey)
	if err != nil {
		return err
	}
	if err := store.Set(secrets.TLSPrivateKey, der); err != nil {
		return fmt.Errorf("store tls key: %w", err)
	}
	clear(der)
	// The inbox key encrypts the local inbox at rest. Keep an existing
	// one so a re-init does not orphan stored messages.
	if _, err := store.Get(secrets.InboxKey); errors.Is(err, secrets.ErrNotFound) {
		var k [32]byte
		if _, err := rand.Read(k[:]); err != nil {
			return err
		}
		if err := store.Set(secrets.InboxKey, k[:]); err != nil {
			return fmt.Errorf("store inbox key: %w", err)
		}
		clear(k[:])
	} else if err != nil {
		return fmt.Errorf("read inbox key: %w", err)
	}
	for _, stale := range []string{secrets.TLSCertificate, nextTLSKey} {
		if err := store.Delete(stale); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return fmt.Errorf("remove old %s: %w", stale, err)
		}
	}
	raw, err := config.Save(path, cfg)
	if err != nil {
		return err
	}
	if err := config.Pin(pinStore, path, raw); err != nil {
		return err
	}
	csr, err := tlsutil.CreateCSR(tlsKey, cfg.PeerName)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Initialised %s (config %s, pinned).\n\n", cfg.PeerName, path)
	fmt.Fprintf(env.Stdout, "Public key:  %s\nFingerprint: %s\n\n", envelope.EncodeKey(pub), envelope.Fingerprint(pub))
	fmt.Fprintf(env.Stdout, "Send the public key to your peer and compare fingerprints out of band.\n")
	fmt.Fprintf(env.Stdout, "Give this certificate signing request to the edge operator:\n\n%s", csr)
	return nil
}

func cmdShow(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	priv, err := loadBoxKey(l.store)
	if err != nil {
		return err
	}
	defer clear(priv[:])
	pub, err := envelope.PublicKey(priv)
	if err != nil {
		return err
	}
	c := l.cfg
	w := env.Stdout
	fmt.Fprintf(w, "Peer:        %s\nRelay:       %s\nConfig:      %s\n", c.PeerName, c.RelayURL, l.path)
	fmt.Fprintf(w, "Public key:  %s\nFingerprint: %s\n", envelope.EncodeKey(pub), envelope.Fingerprint(pub))
	if pemBytes, err := l.store.Get(secrets.TLSCertificate); err == nil {
		if cert, err := tlsutil.ParseCertPEM(pemBytes); err == nil {
			fmt.Fprintf(w, "Client cert: sha256 %s, expires %s\n", tlsutil.Fingerprint(cert.Raw), cert.NotAfter.UTC().Format(time.RFC3339))
		}
	} else {
		fmt.Fprintln(w, "Client cert: none imported (postern cert import FILE)")
	}
	if _, err := l.store.Get(nextTLSKey); err == nil {
		fmt.Fprintln(w, "Rotation:    a new client key is waiting for its certificate")
	}
	fmt.Fprintf(w, "Sessions:    %s\n", strings.Join(c.Sessions, ", "))
	for _, p := range c.Peers {
		fmt.Fprintf(w, "Peer %-8s %s\n", p.Name+":", p.Fingerprint)
	}
	return nil
}

func cmdPeerAdd(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "peer add")
	name := fs.String("name", "", "peer name")
	pubKey := fs.String("public-key", "", "peer's base64 public key")
	fp := fs.String("fingerprint", "", "fingerprint you compared out of band")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *pubKey == "" || *fp == "" {
		return errors.New("--name, --public-key and --fingerprint are required")
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	key, err := envelope.DecodeKey(*pubKey)
	if err != nil {
		return errors.New("public key is not a base64 X25519 key")
	}
	want := envelope.Fingerprint(key)
	if compactFP(*fp) != compactFP(want) {
		return errors.New("fingerprint does not match the public key; do not add this peer until you have compared fingerprints again")
	}
	if _, ok := l.cfg.Peer(*name); ok {
		return fmt.Errorf("peer %q already exists (remove it first)", *name)
	}
	l.cfg.Peers = append(l.cfg.Peers, config.PeerConfig{Name: *name, PublicKey: envelope.EncodeKey(key), Fingerprint: want})
	if err := l.cfg.Validate(); err != nil {
		return err
	}
	if err := l.save(env, fmt.Sprintf("Trust peer %s with fingerprint\n  %s\nOnly confirm if you compared this fingerprint with the peer out of band.", *name, want)); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Added peer %s (%s). Config re-pinned.\n", *name, want)
	return nil
}

func cmdPeerRemove(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "peer remove")
	name := fs.String("name", "", "peer name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(l.cfg.Peers, func(p config.PeerConfig) bool { return p.Name == *name })
	if i < 0 {
		return fmt.Errorf("no peer %q", *name)
	}
	l.cfg.Peers = slices.Delete(l.cfg.Peers, i, i+1)
	if err := l.save(env, "Stop trusting peer "+*name+"."); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed peer %s. Config re-pinned.\n", *name)
	return nil
}

func cmdSessionAdd(env Env, args []string) error {
	return editSessions(env, "session add", args, func(c *config.Config, name string) error {
		if c.HasSession(name) {
			return fmt.Errorf("session %q already listed", name)
		}
		c.Sessions = append(c.Sessions, name)
		return nil
	})
}

func cmdSessionRemove(env Env, args []string) error {
	return editSessions(env, "session remove", args, func(c *config.Config, name string) error {
		i := slices.Index(c.Sessions, name)
		if i < 0 {
			return fmt.Errorf("session %q not listed", name)
		}
		c.Sessions = slices.Delete(c.Sessions, i, i+1)
		return nil
	})
}

func editSessions(env Env, cmd string, args []string, edit func(*config.Config, string) error) error {
	fs, cfgFlag := newFlags(env, cmd)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("expected one session name")
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	if err := edit(l.cfg, fs.Arg(0)); err != nil {
		return err
	}
	if err := l.cfg.Validate(); err != nil {
		return err
	}
	if err := l.save(env, "Change which sessions may use this bridge ("+cmd+" "+fs.Arg(0)+")."); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Sessions: %s. Config re-pinned.\n", strings.Join(l.cfg.Sessions, ", "))
	return nil
}

// cmdConfigPin is the one command that accepts an unpinned or changed
// config: it shows the human what will be trusted, then pins it.
func cmdConfigPin(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "config pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := configPath(*cfgFlag)
	if err != nil {
		return err
	}
	cfg, raw, err := config.Load(path)
	if err != nil {
		return err
	}
	pinStore, err := env.OpenStore(config.PinService)
	if err != nil {
		return fmt.Errorf("open keychain: %w", err)
	}
	summary := fmt.Sprintf("Pin this config as trusted (sha256 %s).\nCheck every line; anything you did not change yourself is tampering.\n\n%s",
		config.Digest(raw), describe(path, cfg))
	if err := confirm(env, summary); err != nil {
		return err
	}
	if err := config.Pin(pinStore, path, raw); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Pinned.")
	return nil
}

func compactFP(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), ""))
}

func loadBoxKey(store secrets.Store) (*[32]byte, error) {
	b, err := store.Get(secrets.BoxPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load box key from keychain: %w", err)
	}
	defer clear(b)
	if len(b) != 32 {
		return nil, errors.New("box key in keychain has the wrong length")
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}
