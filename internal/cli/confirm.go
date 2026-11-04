package cli

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
)

var errNotConfirmed = errors.New("not confirmed")

// ttyConfirm shows the summary on the controlling terminal and asks for
// a one-time code printed only there. The code never reaches stdout, so
// a process that captures this command's output (an agent's shell tool)
// cannot read it back, and with no terminal at all the change is refused.
// This raises the bar for same-user processes; it is not a boundary
// against one that can inject keystrokes into the terminal.
func ttyConfirm(summary string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("this change needs a human at a terminal; run the command yourself, not through an agent")
	}
	defer tty.Close()
	code := oneTimeCode()
	fmt.Fprintf(tty, "\n%s\nIf this is what you want, type %s and press Enter: ", summary, code)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return errNotConfirmed
	}
	if strings.ToUpper(strings.TrimSpace(line)) != code {
		fmt.Fprintln(tty, "Not confirmed; nothing changed.")
		return errNotConfirmed
	}
	return nil
}

func oneTimeCode() string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
