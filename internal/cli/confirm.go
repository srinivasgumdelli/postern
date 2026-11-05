package cli

import (
	"errors"
	"fmt"
	"io"

	"postern/internal/presence"
)

var errNotConfirmed = errors.New("not approved; nothing changed")

// presenceConfirm is the production Env.Confirm. It prints the full
// summary of the change to w, then asks the operating system for user
// presence (Touch ID or the login password) with the short reason. The
// dialog is drawn by the OS, so an agent that runs this command through
// a pseudo-terminal cannot see or answer it. If the check is
// unsupported or unavailable (no GUI session, SSH, another platform),
// the change is refused; there is no weaker fallback.
func presenceConfirm(w io.Writer, check func(reason string) error) func(reason, summary string) error {
	return func(reason, summary string) error {
		fmt.Fprintf(w, "\n%s\nApprove this change with Touch ID or your login password in the system dialog.\n", summary)
		switch err := check(reason); {
		case err == nil:
			return nil
		case errors.Is(err, presence.ErrDenied):
			fmt.Fprintln(w, "Not approved; nothing changed.")
			return errNotConfirmed
		case errors.Is(err, presence.ErrUnsupported), errors.Is(err, presence.ErrUnavailable):
			return fmt.Errorf("this change needs the human's approval with Touch ID or the login password, in a logged-in macOS GUI session on this machine; nothing changed (%v)", err)
		default:
			return fmt.Errorf("could not get the human's approval; nothing changed: %w", err)
		}
	}
}

// confirm asks the human to approve a change to what the bridge trusts.
// reason is a short phrase for the system dialog ("trust peer peer-b");
// summary is the full description printed before it.
func confirm(env Env, reason, summary string) error {
	if env.Confirm == nil {
		return errors.New("no way to get the human's approval; nothing changed")
	}
	return env.Confirm(reason, summary)
}
