//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package audit

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

const oNoFollow = syscall.O_NOFOLLOW

// lockFile takes an exclusive flock on f, polling so that ctx can bound
// the wait. flock locks belong to the open file description, so two Logs
// in one process exclude each other just as two processes do.
func lockFile(ctx context.Context, f *os.File) error {
	wait := time.Millisecond
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return &opError{op: "lock", err: err}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return errors.New("audit: timed out waiting for the log lock")
		case <-t.C:
		}
		wait = min(wait*2, 20*time.Millisecond)
	}
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
