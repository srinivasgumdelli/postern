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
	Version    string
}

// DefaultEnv is the environment of the real binary.
func DefaultEnv(version string) Env {
	return Env{
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		OpenStore:  secrets.NewKeychain,
		Executable: os.Executable,
		Version:    version,
	}
}

const usage = `postern - encrypted side gate between agent sessions

Setup (run these yourself, not through an agent):
  postern init --peer-name NAME --relay-url URL [--session NAME]...
  postern show
  postern peer add --name NAME --public-key KEY --fingerprint FP
  postern peer remove --name NAME
  postern session add NAME | session remove NAME
  postern cert csr [--new-key] [--out FILE]
  postern cert import FILE
  postern config pin
  postern guard install --project DIR [--server postern]
  postern edge-check
  postern thread reset THREAD

Used by agent tools:
  postern mcp --session NAME
  postern hook pre-tool-use|post-tool-use|user-prompt-submit|session-start [--server postern]

Every command accepts --config PATH (default $POSTERN_CONFIG or the user config dir).
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
		err = sub(env, rest, map[string]func(Env, []string) error{"install": cmdGuardInstall})
	case "thread":
		err = sub(env, rest, map[string]func(Env, []string) error{"reset": func(e Env, a []string) error { return cmdThreadReset(ctx, e, a) }})
	case "mcp":
		err = cmdMCP(ctx, env, rest)
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

// loaded is a config that passed its pin check, with its secret store.
type loaded struct {
	path  string
	cfg   *config.Config
	store secrets.Store
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
	store, err := env.OpenStore(cfg.KeychainService)
	if err != nil {
		return nil, fmt.Errorf("open keychain: %w", err)
	}
	switch err := config.VerifyPin(store, raw); {
	case errors.Is(err, config.ErrNotPinned):
		return nil, errors.New("config is not pinned; review it, then run `postern config pin`")
	case errors.Is(err, config.ErrPinMismatch):
		return nil, errors.New("config changed since it was pinned; review it (relay URL, peer keys, sessions), then run `postern config pin` if the change is yours")
	case err != nil:
		return nil, fmt.Errorf("check config pin: %w", err)
	}
	return &loaded{path: path, cfg: cfg, store: store}, nil
}

// save writes the config and re-pins it in one step.
func (l *loaded) save() error {
	raw, err := config.Save(l.path, l.cfg)
	if err != nil {
		return err
	}
	return config.Pin(l.store, raw)
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
