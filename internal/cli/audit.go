package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"postern/internal/audit"
	"postern/internal/config"
)

// auditTimeout bounds one CLI audit write.
const auditTimeout = 10 * time.Second

// recordTrust appends a CLI trust-change event to the machine's audit
// log, after the change succeeded. The change has already happened, so a
// failure is a warning on stderr, not an error. Nothing is recorded when
// the config turns the audit log off, unless always is set (config pin
// records even the pin that turns it off, so that is visible).
func recordTrust(env Env, cfg *config.Config, always bool, e audit.Event) {
	if !always && !cfg.AuditEnabled() {
		return
	}
	path := cfg.AuditPath()
	if path == "" {
		fmt.Fprintln(env.Stderr, "postern: warning: not recorded in the audit log: no data directory")
		return
	}
	l, err := audit.Open(path)
	if err != nil {
		fmt.Fprintf(env.Stderr, "postern: warning: not recorded in the audit log: %v\n", err)
		return
	}
	defer l.Close()
	e.Actor = audit.ActorCLI
	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()
	if err := l.Record(ctx, e); err != nil {
		fmt.Fprintf(env.Stderr, "postern: warning: not recorded in the audit log: %v\n", err)
	}
}

// recordGuardInstall records guard_install when the config at flagValue
// loads and passes its pin check. guard install works before init, so a
// missing config is silent; any other problem is a warning.
func recordGuardInstall(env Env, flagValue, client string) {
	if env.OpenStore == nil {
		return
	}
	l, err := loadPinnedConfig(env, flagValue)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(env.Stderr, "postern: warning: not recorded in the audit log: %v\n", err)
		}
		return
	}
	recordTrust(env, l.cfg, false, audit.Event{Event: audit.EventGuardInstall, Reason: client})
}

// openAudit opens the audit log for a bridge process, or returns nil when
// the config turns it off.
func openAudit(cfg *config.Config) (*audit.Log, error) {
	if !cfg.AuditEnabled() {
		return nil, nil
	}
	path := cfg.AuditPath()
	if path == "" {
		return nil, errors.New("audit log: no data directory")
	}
	l, err := audit.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w (fix it, or set \"audit\": {\"enabled\": false} and run `postern config pin`)", err)
	}
	return l, nil
}

func cmdAuditTail(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "audit tail")
	n := fs.Int("n", 20, "number of events")
	asJSON := fs.Bool("json", false, "print one JSON object per line")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("audit tail takes no arguments")
	}
	if *n < 1 || *n > 100000 {
		return errors.New("-n must be between 1 and 100000")
	}
	l, err := loadPinnedConfig(env, *cfgFlag)
	if err != nil {
		return err
	}
	if !l.cfg.AuditEnabled() {
		fmt.Fprintln(env.Stderr, "postern: note: the audit log is turned off in the config")
	}
	es, err := audit.Tail(l.cfg.AuditPath(), *n)
	if err != nil {
		return err
	}
	if len(es) == 0 {
		fmt.Fprintln(env.Stderr, "No audit events.")
		return nil
	}
	for _, e := range es {
		if *asJSON {
			raw, err := json.Marshal(e)
			if err != nil {
				return err
			}
			fmt.Fprintf(env.Stdout, "%s\n", raw)
			continue
		}
		fmt.Fprintln(env.Stdout, formatEntry(e))
	}
	return nil
}

// formatEntry prints one entry on a line. Tail has already replaced any
// field that does not match its pattern, so this is never free text.
func formatEntry(e audit.Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%6d  %s  %-18s %-6s", e.Seq, e.TS, e.Event, e.Actor)
	kv := func(k, v string) {
		if v != "" {
			b.WriteString(" " + k + "=" + v)
		}
	}
	kv("peer", e.Peer)
	kv("session", e.Session)
	kv("thread", e.Thread)
	kv("id", e.ID)
	if e.SizeBytes > 0 {
		kv("size_bytes", strconv.FormatInt(e.SizeBytes, 10))
	}
	if e.Status > 0 {
		kv("status", strconv.Itoa(e.Status))
	}
	kv("reason", e.Reason)
	return b.String()
}

func cmdAuditVerify(env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "audit verify")
	hash := fs.String("hash", "", "a last hash noted earlier; check that the log still contains that entry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("audit verify takes no arguments")
	}
	l, err := loadPinnedConfig(env, *cfgFlag)
	if err != nil {
		return err
	}
	var s audit.Summary
	if *hash != "" {
		s, err = audit.VerifyHash(l.cfg.AuditPath(), strings.ToLower(strings.TrimSpace(*hash)))
	} else {
		s, err = audit.Verify(l.cfg.AuditPath())
	}
	if err != nil {
		var be *audit.BreakError
		if errors.As(err, &be) {
			return fmt.Errorf("%w\nThe log was edited, cut or reordered after it was written (or a write was interrupted). Entries before seq %d still verify.", be, be.Seq)
		}
		if errors.Is(err, audit.ErrHashNotFound) {
			return fmt.Errorf("%w; the entries up to it were cut, rewritten or rotated away", err)
		}
		return err
	}
	w := env.Stdout
	if s.Events == 0 {
		fmt.Fprintln(w, "No audit events yet.")
		return nil
	}
	fmt.Fprintf(w, "OK: %d events, seq %d to %d, in %d file(s): %s\n",
		s.Events, s.FirstSeq, s.LastSeq, len(s.Files), strings.Join(s.Files, ", "))
	if s.Anchored {
		fmt.Fprintln(w, "The chain starts at the first event ever recorded.")
	} else {
		fmt.Fprintf(w, "The chain starts at seq %d: older files were rotated away, so that entry is taken as given.\n", s.FirstSeq)
	}
	if s.HashSeq != 0 {
		fmt.Fprintf(w, "The hash you gave is entry seq %d; the entries up to it are unchanged.\n", s.HashSeq)
	}
	fmt.Fprintf(w, "Last hash: %s\n", s.LastHash)
	fmt.Fprintln(w, "This shows the entries are consistent with each other, not that nobody rewrote them: anything running as your user can rewrite the whole log. Keep the last hash somewhere else and check it next time with `postern audit verify --hash HASH`.")
	return nil
}
