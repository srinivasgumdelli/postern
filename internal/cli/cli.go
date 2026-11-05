// Package cli implements the postern command. cmd/postern is a thin
// wrapper so that tests can drive every command in-process with an
// in-memory secret store.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"postern/internal/config"
	"postern/internal/presence"
	"postern/internal/secrets"
)

// Env is everything a command touches outside the process.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// OpenStore opens the secret store for a keychain service name.
	// Production uses secrets.NewKeychain.
	OpenStore func(service string) (secrets.Store, error)
	// MCPTransport is used by "postern mcp"; nil means stdio.
	MCPTransport mcp.Transport
	// Executable returns the absolute path of the running binary.
	Executable func() (string, error)
	// ClaudeVersion returns the output of `claude --version`.
	ClaudeVersion func() (string, error)
	// Confirm asks the human to approve a change to what the bridge
	// trusts (keys, peers, sessions, the config pin, the client key).
	// reason is a short phrase for the system dialog; summary is the full
	// change. Production prints the summary to Stdout, then asks the OS
	// for user presence (Touch ID or the login password), which an agent
	// cannot answer through a terminal. Tests inject their own.
	Confirm func(reason, summary string) error
	Version string
}

// DefaultEnv is the environment of the real binary.
func DefaultEnv(version string) Env {
	return Env{
		Stdin:         os.Stdin,
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		OpenStore:     secrets.NewKeychain,
		Executable:    os.Executable,
		ClaudeVersion: claudeVersion,
		Confirm:       presenceConfirm(os.Stdout, presence.Confirm),
		Version:       version,
	}
}

const usage = `postern - encrypted side gate between agent sessions

Setup (run these yourself; changes ask for Touch ID or your login password):
  postern init --peer-name NAME --relay-url URL [--session NAME]...
  postern show
  postern peer add --name NAME --public-key KEY --fingerprint FP
  postern peer remove --name NAME
  postern session add NAME | session remove NAME
  postern cert csr [--new-key] [--out FILE]
  postern cert import FILE
  postern config pin
  postern guard install --project DIR [--server postern] [--skip-claude-version-check]
  postern guard install-codex [--skills-dir DIR]
  postern edge-check
  postern thread reset THREAD

Used by agent tools:
  postern mcp --session NAME
  postern hook pre-tool-use|post-tool-use|user-prompt-submit|session-start [--server postern]

Watching for messages (prints a count and peer names only, never content):
  postern wait --session NAME [--timeout DURATION]
      exits 0 when new messages arrive, 3 on timeout, 1 on error

Commands that use the bridge config accept --config PATH (default
$POSTERN_CONFIG or the user config dir). guard and hook do not read it.
`

// Run executes one postern command and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "init":
		err = cmdInit(env, rest)
	case "show":
		err = cmdShow(env, rest)
	case "peer":
		err = sub(env, rest, map[string]func(Env, []string) error{"add": cmdPeerAdd, "remove": cmdPeerRemove})
	case "session":
		err = sub(env, rest, map[string]func(Env, []string) error{"add": cmdSessionAdd, "remove": cmdSessionRemove})
	case "cert":
		err = sub(env, rest, map[string]func(Env, []string) error{"csr": cmdCertCSR, "import": cmdCertImport})
	case "config":
		err = sub(env, rest, map[string]func(Env, []string) error{"pin": cmdConfigPin})
	case "guard":
		err = sub(env, rest, map[string]func(Env, []string) error{"install": cmdGuardInstall, "install-codex": cmdGuardInstallCodex})
	case "thread":
		err = sub(env, rest, map[string]func(Env, []string) error{"reset": func(e Env, a []string) error { return cmdThreadReset(ctx, e, a) }})
	case "mcp":
		err = cmdMCP(ctx, env, rest)
	case "wait":
		if err = cmdWait(ctx, env, rest); errors.Is(err, errWaitTimeout) {
			return exitWaitTimeout
		}
	case "edge-check":
		err = cmdEdgeCheck(ctx, env, rest)
	case "hook":
		return cmdHook(env, rest)
	case "version":
		fmt.Fprintln(env.Stdout, env.Version)
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
	default:
		fmt.Fprintf(env.Stderr, "postern: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintf(env.Stderr, "postern: %v\n", err)
		return 1
	}
	return 0
}

func sub(env Env, args []string, cmds map[string]func(Env, []string) error) error {
	if len(args) == 0 {
		return errors.New("missing subcommand")
	}
	f, ok := cmds[args[0]]
	if !ok {
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
	return f(env, args[1:])
}

func newFlags(env Env, name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("postern "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	cfg := fs.String("config", "", "config file (default $POSTERN_CONFIG or the user config dir)")
	return fs, cfg
}

func configPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return config.DefaultPath()
}

// loaded is a config that passed its pin check, with its secret stores.
type loaded struct {
	path     string
	cfg      *config.Config
	store    secrets.Store // the bridge's keys (cfg.KeychainService)
	pinStore secrets.Store // config pins (config.PinService, fixed)
}

// loadPinned loads the config and refuses it unless it matches the pin
// in the keychain. Every command except "config pin" and "init" goes
// through here, so an edited config is never used or re-blessed silently.
func loadPinned(env Env, flagValue string) (*loaded, error) {
	path, err := configPath(flagValue)
	if err != nil {
		return nil, err
	}
	cfg, raw, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	// The pin lives under a fixed service, never one named by the file.
	pinStore, err := env.OpenStore(config.PinService)
	if err != nil {
		return nil, fmt.Errorf("open keychain: %w", err)
	}
	switch err := config.VerifyPin(pinStore, path, raw); {
	case errors.Is(err, config.ErrNotPinned):
		return nil, errors.New("config is not pinned; review it, then run `postern config pin`")
	case errors.Is(err, config.ErrPinMismatch):
		return nil, errors.New("config changed since it was pinned; review it (relay URL, peer keys, sessions), then run `postern config pin` if the change is yours")
	case err != nil:
		return nil, fmt.Errorf("check config pin: %w", err)
	}
	// Only now is anything from the file trusted, including where the
	// bridge's own keys live.
	store, err := env.OpenStore(cfg.KeychainService)
	if err != nil {
		return nil, fmt.Errorf("open keychain: %w", err)
	}
	return &loaded{path: path, cfg: cfg, store: store, pinStore: pinStore}, nil
}

// save asks the human to confirm, then writes the config and re-pins it.
func (l *loaded) save(env Env, reason, what string) error {
	if err := confirm(env, reason, what+"\n\n"+describe(l.path, l.cfg)); err != nil {
		return err
	}
	raw, err := config.Save(l.path, l.cfg)
	if err != nil {
		return err
	}
	return config.Pin(l.pinStore, l.path, raw)
}

// describe summarises what a config makes the bridge trust.
func describe(path string, c *config.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Config:    %s\nPeer name: %s\nRelay:     %s\n", path, c.PeerName, c.RelayURL)
	if c.RelayCAFile != "" {
		fmt.Fprintf(&b, "Relay CA:  %s\n", c.RelayCAFile)
	}
	fmt.Fprintf(&b, "Keychain:  %s\nSessions:  %s\n", c.KeychainService, strings.Join(c.Sessions, ", "))
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "Peer:      %s  %s\n", p.Name, p.Fingerprint)
	}
	return b.String()
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
