# shellcheck shell=bash
# Shared helpers for the operator scripts in deploy/scripts. Sourced by
# them, never run on its own.
#
# Token rule: the Cloudflare API token is read from the operator's login
# keychain (or a 0600 file given with --token-file) into a shell variable
# and handed to curl on stdin as an "Authorization" header line (-H @-).
# It is never a command-line argument, never an environment variable,
# never written to disk by these scripts, and never printed. printf is a
# shell builtin, so writing it into the pipe starts no process with the
# token in its argv.
#
# JSON is handled with python3 (-I: isolated mode, so nothing is imported
# from the current directory or the environment).

CF_API="https://api.cloudflare.com/client/v4"
KEYCHAIN_SERVICE="postern-edge-token"
# shellcheck disable=SC2034 # used by the scripts that source this file
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PROG=$(basename "$0")

TOKEN_FILE=""
# shellcheck disable=SC2034 # used by the scripts that source this file
DRY_RUN=0
WORK_DIR=""
CF_TOKEN=""

die() {
	printf '%s: %s\n' "$PROG" "$*" >&2
	exit 1
}

usage_error() {
	printf '%s: %s\nRun %s --help for usage.\n' "$PROG" "$*" "$PROG" >&2
	exit 2
}

# need_arg OPTION VALUE: an option's value must be present.
need_arg() {
	if [ -z "${2:-}" ] || [ "${2#-}" != "$2" ]; then
		usage_error "$1 needs a value"
	fi
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required but was not found on PATH"
}

need_python() {
	need python3
	python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' ||
		die "python3 3.8 or later is required"
}

cleanup() {
	CF_TOKEN=""
	if [ -n "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}

# make_work_dir creates a private (0700) scratch directory, removed on
# exit, for request bodies and responses. None of them hold the token.
make_work_dir() {
	WORK_DIR=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/postern-ops.XXXXXX") ||
		die "cannot create a temporary directory"
	trap cleanup EXIT
	trap 'exit 130' HUP INT TERM
}

valid_zone_id() {
	# A zone id is 32 lowercase hex characters (as the dashboard shows it).
	printf '%s' "$1" | grep -Eq '^[0-9a-f]{32}$'
}

check_zone_id() {
	[ -n "$1" ] || usage_error "--zone is required"
	case "$1" in
	*'<'* | *'>'*) usage_error "--zone still holds a placeholder; use the zone id from the dashboard (zone overview)" ;;
	esac
	valid_zone_id "$1" || usage_error "--zone must be a zone id: 32 lowercase hex characters"
}

valid_fingerprint() {
	printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$'
}

# normalize_fingerprint lower-cases and strips colons and spaces.
normalize_fingerprint() {
	printf '%s' "$1" | tr 'A-F' 'a-f' | tr -d ': '
}

# check_token_file refuses a token file that others could read.
check_token_file() {
	[ -f "$TOKEN_FILE" ] || die "token file not found or not a regular file: $TOKEN_FILE"
	[ -r "$TOKEN_FILE" ] || die "token file is not readable: $TOKEN_FILE"
	python3 -I -c 'import os, sys; sys.exit(1 if os.stat(sys.argv[1]).st_mode & 0o077 else 0)' "$TOKEN_FILE" ||
		die "token file $TOKEN_FILE is accessible by group or others; chmod 600 it first"
}

# load_token reads the API token once into CF_TOKEN (a shell variable,
# not exported) and checks its shape. Prompts from the keychain go to
# the terminal, not to stdout.
load_token() {
	if [ -n "$TOKEN_FILE" ]; then
		check_token_file
		CF_TOKEN=$(head -n 1 "$TOKEN_FILE" | tr -d '\r') || die "cannot read the token file"
	else
		need security
		CF_TOKEN=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -w) ||
			die "cannot read the API token from the keychain (service $KEYCHAIN_SERVICE); see docs/edge-setup.md step 3, or use --token-file"
	fi
	case "$CF_TOKEN" in
	'' | *[!A-Za-z0-9._~+/=-]*)
		CF_TOKEN=""
		die "the API token is empty or has unexpected characters (it is not shown)"
		;;
	esac
	[ "${#CF_TOKEN}" -ge 20 ] || {
		CF_TOKEN=""
		die "the API token is too short (it is not shown)"
	}
}

# cf_request METHOD PATH OUTFILE [BODYFILE] sends one API request and
# writes the response body to OUTFILE. Returns curl's exit status.
# -q comes first so no curlrc can add tracing or other headers; the
# Authorization header arrives on stdin.
cf_request() {
	local method=$1 path=$2 out=$3 body=${4:-}
	[ -n "$CF_TOKEN" ] || die "internal error: token not loaded"
	if [ -n "$body" ]; then
		printf 'Authorization: Bearer %s\n' "$CF_TOKEN" |
			curl -q -sS --proto '=https' --max-time 60 --fail-with-body \
				-H @- -X "$method" -H 'Content-Type: application/json' \
				--data-binary "@$body" "$CF_API$path" >"$out"
	else
		printf 'Authorization: Bearer %s\n' "$CF_TOKEN" |
			curl -q -sS --proto '=https' --max-time 60 --fail-with-body \
				-H @- -X "$method" "$CF_API$path" >"$out"
	fi
}

# print_request METHOD PATH [BODYFILE] shows what cf_request would send,
# with the token redacted. The token is not read in dry-run mode.
print_request() {
	printf '%s %s\n' "$1" "$CF_API$2"
	printf 'Authorization: Bearer [REDACTED]\n'
	if [ -n "${3:-}" ]; then
		printf 'Content-Type: application/json\n\n'
		cat "$3"
		printf '\n'
	fi
}

# API_ERRORS prints the "errors" of a Cloudflare API response (code and
# message only), or a note that the response was not JSON.
API_ERRORS='
import json, sys
try:
    with open(sys.argv[1], "rb") as f:
        doc = json.load(f)
except Exception:
    print("  (response is not JSON)")
    sys.exit(0)
errs = doc.get("errors") if isinstance(doc, dict) else None
if not errs:
    print("  (no error details in the response)")
for e in errs or []:
    if isinstance(e, dict):
        msg = "".join(c for c in str(e.get("message", "")) if c.isprintable())[:300]
        print("  error %s: %s" % (e.get("code", "?"), msg))
'

api_failed() {
	printf '%s: the API request failed:\n' "$PROG" >&2
	python3 -I -c "$API_ERRORS" "$1" >&2 || true
	exit 1
}
