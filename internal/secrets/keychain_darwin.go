//go:build darwin && cgo

package secrets

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

static CFStringRef postern_str(const char *s) {
	return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef postern_dict(void) {
	return CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

// postern_query returns a new dictionary that matches one generic
// password item in the file-based (login) keychain, or NULL. The caller
// releases it.
static CFMutableDictionaryRef postern_query(const char *service, const char *account) {
	CFMutableDictionaryRef q = postern_dict();
	CFStringRef svc = postern_str(service);
	CFStringRef acct = postern_str(account);
	if (q == NULL || svc == NULL || acct == NULL) {
		if (q != NULL) CFRelease(q);
		if (svc != NULL) CFRelease(svc);
		if (acct != NULL) CFRelease(acct);
		return NULL;
	}
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, svc);
	CFDictionarySetValue(q, kSecAttrAccount, acct);
	// The data-protection keychain needs entitlements an unsigned or
	// ad-hoc signed binary does not have. Stay on the login keychain,
	// where the item ACL names the creating binary.
	CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanFalse);
	CFRelease(svc);
	CFRelease(acct);
	return q;
}

// postern_get copies the item's data into *out (caller releases it).
static OSStatus postern_get(const char *service, const char *account, CFDataRef *out) {
	*out = NULL;
	CFMutableDictionaryRef q = postern_query(service, account);
	if (q == NULL) return errSecAllocate;
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) {
		if (result != NULL) CFRelease(result);
		return st;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecInternalComponent;
	}
	*out = (CFDataRef)result;
	return errSecSuccess;
}

// postern_set updates the item if it exists, otherwise adds it.
static OSStatus postern_set(const char *service, const char *account, const char *label,
		const UInt8 *data, CFIndex len) {
	CFMutableDictionaryRef q = postern_query(service, account);
	CFMutableDictionaryRef attrs = postern_dict();
	CFDataRef value = CFDataCreate(kCFAllocatorDefault, data, len);
	CFStringRef lbl = postern_str(label);
	OSStatus st = errSecAllocate;
	if (q == NULL || attrs == NULL || value == NULL || lbl == NULL) goto done;

	CFDictionarySetValue(attrs, kSecValueData, value);
	CFDictionarySetValue(attrs, kSecAttrLabel, lbl);
	st = SecItemUpdate(q, attrs);
	if (st != errSecItemNotFound) goto done;

	CFDictionarySetValue(q, kSecValueData, value);
	CFDictionarySetValue(q, kSecAttrLabel, lbl);
	st = SecItemAdd(q, NULL);
	if (st == errSecDuplicateItem) {
		// Another process added it between our update and add.
		CFDictionaryRemoveValue(q, kSecValueData);
		CFDictionaryRemoveValue(q, kSecAttrLabel);
		st = SecItemUpdate(q, attrs);
	}

done:
	if (q != NULL) CFRelease(q);
	if (attrs != NULL) CFRelease(attrs);
	if (value != NULL) CFRelease(value);
	if (lbl != NULL) CFRelease(lbl);
	return st;
}

static OSStatus postern_delete(const char *service, const char *account) {
	CFMutableDictionaryRef q = postern_query(service, account);
	if (q == NULL) return errSecAllocate;
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// The SecKeychainItem / SecAccess / SecACL calls below are deprecated
// but are the only API that exposes the access list of a login-keychain
// item. Silence the warnings for this block only.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// postern_acl_reads reports whether an ACL entry grants reading the
// item's secret in the clear.
static Boolean postern_acl_reads(SecACLRef acl) {
	Boolean reads = false;
	CFArrayRef auths = SecACLCopyAuthorizations(acl);
	if (auths == NULL) return true; // unknown: treat as reading
	for (CFIndex i = 0; i < CFArrayGetCount(auths); i++) {
		CFTypeRef a = CFArrayGetValueAtIndex(auths, i);
		if (CFEqual(a, kSecACLAuthorizationDecrypt) || CFEqual(a, kSecACLAuthorizationAny) ||
				CFEqual(a, kSecACLAuthorizationExportClear)) {
			reads = true;
		}
	}
	CFRelease(auths);
	return reads;
}

// postern_acl_open sets *open to 1 if any ACL entry that grants reading
// the item has a NULL application list, which means "any application"
// (what `security add-generic-password -A` creates). It reads only the
// item's access object, never its data, so it does not prompt.
static OSStatus postern_acl_open(const char *service, const char *account, int *open) {
	*open = 0;
	CFMutableDictionaryRef q = postern_query(service, account);
	if (q == NULL) return errSecAllocate;
	CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef item = NULL;
	OSStatus st = SecItemCopyMatching(q, &item);
	CFRelease(q);
	if (st != errSecSuccess) {
		if (item != NULL) CFRelease(item);
		return st;
	}
	if (item == NULL || CFGetTypeID(item) != SecKeychainItemGetTypeID()) {
		if (item != NULL) CFRelease(item);
		return errSecInternalComponent;
	}
	SecAccessRef access = NULL;
	st = SecKeychainItemCopyAccess((SecKeychainItemRef)item, &access);
	CFRelease(item);
	if (st != errSecSuccess) return st;
	if (access == NULL) return errSecInternalComponent;
	CFArrayRef acls = NULL;
	st = SecAccessCopyACLList(access, &acls);
	CFRelease(access);
	if (st != errSecSuccess) return st;
	if (acls == NULL) return errSecInternalComponent;
	for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
		SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
		if (!postern_acl_reads(acl)) continue;
		CFArrayRef apps = NULL;
		CFStringRef desc = NULL;
		SecKeychainPromptSelector sel = 0;
		st = SecACLCopyContents(acl, &apps, &desc, &sel);
		if (st != errSecSuccess) {
			CFRelease(acls);
			return st;
		}
		if (desc != NULL) CFRelease(desc);
		if (apps == NULL) {
			*open = 1;
		} else {
			CFRelease(apps);
		}
	}
	CFRelease(acls);
	return errSecSuccess;
}
#pragma clang diagnostic pop
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

const (
	errSecSuccess      = 0
	errSecItemNotFound = -25300
)

// keychainMu serializes keychain calls from this process. The update
// then add sequence in Set is not atomic on its own.
var keychainMu sync.Mutex

type keychain struct {
	service string
}

// NewKeychain returns a Store backed by generic password items in the
// user's login keychain (kSecClassGenericPassword, kSecAttrService =
// service, kSecAttrAccount = item name).
//
// Items are created in-process through Security.framework rather than
// by shelling out to /usr/bin/security. That matters: macOS records the
// creating binary in the item's ACL, so only the bridge binary reads
// the item silently. Any other process (including `security
// find-generic-password`) triggers a macOS prompt that the human must
// approve. A rebuilt binary has a new code hash and also prompts once.
//
// Values are copied into Core Foundation buffers for the duration of
// each call; Core Foundation does not zero them when it frees them.
func NewKeychain(service string) (Store, error) {
	if !ValidName(service) {
		return nil, ErrInvalidName
	}
	return &keychain{service: service}, nil
}

func (k *keychain) label(name string) string {
	return "postern (" + k.service + "): " + name
}

func statusError(op, name string, st C.OSStatus) error {
	return fmt.Errorf("secrets: keychain %s %s: OSStatus %d", op, name, int32(st))
}

func (k *keychain) Get(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrInvalidName
	}
	svc := C.CString(k.service)
	defer C.free(unsafe.Pointer(svc))
	acct := C.CString(name)
	defer C.free(unsafe.Pointer(acct))

	keychainMu.Lock()
	defer keychainMu.Unlock()
	var data C.CFDataRef
	st := C.postern_get(svc, acct, &data)
	switch st {
	case errSecSuccess:
	case errSecItemNotFound:
		return nil, ErrNotFound
	default:
		return nil, statusError("get", name, st)
	}
	defer C.CFRelease(C.CFTypeRef(data))
	n := C.CFDataGetLength(data)
	if n == 0 {
		return []byte{}, nil
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(n)), nil
}

func (k *keychain) Set(name string, value []byte) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	svc := C.CString(k.service)
	defer C.free(unsafe.Pointer(svc))
	acct := C.CString(name)
	defer C.free(unsafe.Pointer(acct))
	lbl := C.CString(k.label(name))
	defer C.free(unsafe.Pointer(lbl))

	var ptr *C.UInt8
	if len(value) > 0 {
		ptr = (*C.UInt8)(unsafe.Pointer(&value[0]))
	}
	keychainMu.Lock()
	defer keychainMu.Unlock()
	if st := C.postern_set(svc, acct, lbl, ptr, C.CFIndex(len(value))); st != errSecSuccess {
		return statusError("set", name, st)
	}
	return nil
}

var _ ACLChecker = (*keychain)(nil)

// CheckOwnedACL refuses an item whose access list lets any application
// read it. Items postern creates in-process name the postern binary
// instead. This catches an item planted with `security
// add-generic-password -A`; it cannot tell apart an item planted with an
// access list that names the postern binary (-T), see DESIGN.md.
func (k *keychain) CheckOwnedACL(name string) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	svc := C.CString(k.service)
	defer C.free(unsafe.Pointer(svc))
	acct := C.CString(name)
	defer C.free(unsafe.Pointer(acct))

	keychainMu.Lock()
	defer keychainMu.Unlock()
	var open C.int
	switch st := C.postern_acl_open(svc, acct, &open); st {
	case errSecSuccess:
	case errSecItemNotFound:
		return ErrNotFound
	default:
		return statusError("read access list of", name, st)
	}
	if open != 0 {
		return fmt.Errorf("%w: %s %s", ErrNotOwned, k.service, name)
	}
	return nil
}

func (k *keychain) Delete(name string) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	svc := C.CString(k.service)
	defer C.free(unsafe.Pointer(svc))
	acct := C.CString(name)
	defer C.free(unsafe.Pointer(acct))

	keychainMu.Lock()
	defer keychainMu.Unlock()
	switch st := C.postern_delete(svc, acct); st {
	case errSecSuccess:
		return nil
	case errSecItemNotFound:
		return ErrNotFound
	default:
		return statusError("delete", name, st)
	}
}
