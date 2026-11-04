package bridge

import (
	"net/http"
	"time"
)

// Values returned by RelayStatus.
const (
	RelayAuthFailed  = "relay_auth_failed"
	RelayUnreachable = "relay_unreachable"
)

const (
	// unreachableAfter: polls must fail this long before RelayStatus
	// reports the relay unreachable (a single blip is not worth showing).
	unreachableAfter = 2 * time.Minute
	// reloadEvery limits how often ReloadClientCert is called.
	reloadEvery = time.Minute
)

// RelayStatus summarises this process's recent relay exchanges, for the
// agent:
//   - "" when the last exchange succeeded;
//   - RelayAuthFailed ("relay_auth_failed") when the last poll or post got
//     401/403 (certificate revoked, expired or not yet issued);
//   - RelayUnreachable ("relay_unreachable") when polls have failed with
//     network errors or 5xx for more than 2 minutes.
func (b *Bridge) RelayStatus() string {
	b.statusMu.Lock()
	defer b.statusMu.Unlock()
	if !b.pollFailSince.IsZero() && b.now().Sub(b.pollFailSince) > unreachableAfter {
		return RelayUnreachable
	}
	if b.authFailed {
		return RelayAuthFailed
	}
	return ""
}

func isAuthStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// noteRelay records the outcome of one relay exchange (status 0 with a
// non-nil err means no response). On 401/403 it may reload the client
// certificate.
func (b *Bridge) noteRelay(status int, err error, isPoll bool) {
	if err != nil && status == 0 {
		if isPoll {
			b.statusMu.Lock()
			if b.pollFailSince.IsZero() {
				b.pollFailSince = b.now()
			}
			b.statusMu.Unlock()
		}
		return
	}
	switch {
	case status >= 500:
		if isPoll {
			b.statusMu.Lock()
			if b.pollFailSince.IsZero() {
				b.pollFailSince = b.now()
			}
			b.statusMu.Unlock()
		}
	case isAuthStatus(status):
		b.statusMu.Lock()
		b.authFailed = true
		b.pollFailSince = time.Time{}
		b.statusMu.Unlock()
		b.maybeReloadCert()
	default:
		// Any other answer means the relay is reachable and accepted the
		// certificate.
		b.statusMu.Lock()
		b.authFailed = false
		b.pollFailSince = time.Time{}
		b.statusMu.Unlock()
	}
}

// maybeReloadCert calls ReloadClientCert (at most once per reloadEvery)
// and switches to the returned certificate if it differs.
func (b *Bridge) maybeReloadCert() {
	if b.reload == nil {
		return
	}
	b.statusMu.Lock()
	now := b.now()
	if !b.lastReload.IsZero() && now.Sub(b.lastReload) < reloadEvery && !now.Before(b.lastReload) {
		b.statusMu.Unlock()
		return
	}
	b.lastReload = now
	b.statusMu.Unlock()

	cert, err := b.reload()
	if err != nil {
		b.log.Warn("client certificate reload failed")
		return
	}
	if b.client.swapCert(cert) {
		b.log.Info("client certificate reloaded")
	} else {
		b.log.Info("client certificate unchanged after reload")
	}
}
