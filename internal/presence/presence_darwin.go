//go:build darwin && cgo

package presence

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

enum {
	POSTERN_PRESENCE_OK = 0,
	POSTERN_PRESENCE_FAILED = 1,      // evaluatePolicy replied with an error
	POSTERN_PRESENCE_CANNOT = 2,      // canEvaluatePolicy said no
	POSTERN_PRESENCE_TIMEOUT = 3,     // no answer in time; dialog dismissed
	POSTERN_PRESENCE_EXCEPTION = 4,   // LocalAuthentication raised
};

// postern_presence asks for device-owner authentication (Touch ID or the
// login password) and waits for the reply. *code receives the LAError
// code when there is one.
static int postern_presence(const char *reason, long timeout_seconds, long *code) {
	*code = 0;
	@autoreleasepool {
		@try {
			NSString *r = [NSString stringWithUTF8String:reason];
			if (r == nil || r.length == 0) {
				return POSTERN_PRESENCE_EXCEPTION;
			}
			LAContext *ctx = [[LAContext alloc] init];
			NSError *err = nil;
			if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&err]) {
				*code = err != nil ? (long)err.code : 0;
				return POSTERN_PRESENCE_CANNOT;
			}
			__block BOOL ok = NO;
			__block long replyCode = 0;
			dispatch_semaphore_t sem = dispatch_semaphore_create(0);
			// The reply arrives on a private queue; this thread only waits.
			[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
			    localizedReason:r
			              reply:^(BOOL success, NSError *e) {
				ok = success;
				replyCode = e != nil ? (long)e.code : 0;
				dispatch_semaphore_signal(sem);
			}];
			dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_seconds * NSEC_PER_SEC);
			if (dispatch_semaphore_wait(sem, deadline) != 0) {
				// Dismiss the dialog so a late approval cannot count.
				[ctx invalidate];
				dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
				return POSTERN_PRESENCE_TIMEOUT;
			}
			if (ok) {
				return POSTERN_PRESENCE_OK;
			}
			*code = replyCode;
			return POSTERN_PRESENCE_FAILED;
		} @catch (NSException *ex) {
			return POSTERN_PRESENCE_EXCEPTION;
		}
	}
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// available reports that this build has a user-presence check.
const available = true

// timeoutSeconds bounds how long the dialog waits for the human.
const timeoutSeconds = 120

// LAError codes (LocalAuthentication/LAError.h).
const (
	laAuthenticationFailed = -1
	laUserCancel           = -2
	laUserFallback         = -3
	laSystemCancel         = -4
	laAppCancel            = -9
)

// mu keeps one dialog at a time from this process.
var mu sync.Mutex

func confirm(reason string) error {
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	mu.Lock()
	defer mu.Unlock()
	var code C.long
	switch C.postern_presence(cr, timeoutSeconds, &code) {
	case C.POSTERN_PRESENCE_OK:
		return nil
	case C.POSTERN_PRESENCE_TIMEOUT:
		return fmt.Errorf("%w (no answer within %d seconds)", ErrDenied, timeoutSeconds)
	case C.POSTERN_PRESENCE_FAILED:
		switch code {
		case laAuthenticationFailed, laUserCancel, laUserFallback, laSystemCancel, laAppCancel:
			return ErrDenied
		}
		return fmt.Errorf("%w (LAError %d)", ErrUnavailable, int(code))
	case C.POSTERN_PRESENCE_CANNOT:
		return fmt.Errorf("%w (LAError %d)", ErrUnavailable, int(code))
	default:
		return ErrUnavailable
	}
}
