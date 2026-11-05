//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package audit

import (
	"context"
	"errors"
	"os"
)

const oNoFollow = 0

// lockFile is not implemented on this platform, so Record always fails
// rather than risk interleaved or unchained lines.
func lockFile(context.Context, *os.File) error {
	return errors.New("audit: file locking is not supported on this platform")
}

func unlockFile(*os.File) {}
