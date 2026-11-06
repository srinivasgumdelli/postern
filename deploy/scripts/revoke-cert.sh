#!/usr/bin/env bash
# Revoke a client certificate at the edge, by id or by SHA-256
# fingerprint. See docs/edge-setup.md step 5 ("Revoke") and the
# revocation drill in docs/operations.md.
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
. "$(dirname "$0")/_common.sh"

usage() {
	cat <<EOF
Usage: $PROG --zone ZONE_ID --id CERT_ID [--yes] [--token-file FILE] [--dry-run]
       $PROG --zone ZONE_ID --fingerprint SHA256 [--lookup-only | --yes]
                      [--token-file FILE] [--dry-run]

Revokes a client certificate of the zone. With --fingerprint it first
lists the zone's client certificates to find the id of the one with that
SHA-256 fingerprint; --lookup-only prints the id and stops.

  --zone ZONE_ID       zone id of the zone that holds the relay hostname
  --id CERT_ID         the certificate id (issue-cert.sh prints it)
  --fingerprint SHA256 find the certificate by its SHA-256 fingerprint
  --lookup-only        with --fingerprint: print the id, revoke nothing
  --yes                do not ask for confirmation
  --token-file FILE    read the API token from FILE (mode 0600) instead of
                       the keychain item "$KEYCHAIN_SERVICE"
  --dry-run            print the requests instead of sending them; reads no token
  -h, --help           show this help

Revocation at the edge is not enough: afterwards, replace the fingerprint
in deploy/relay.json (or PEERS in relay-worker/wrangler.toml) with a value
that matches no certificate, then restart or redeploy the relay.
The token is passed to curl on stdin, never in argv or the environment.
Needs curl (7.76 or later) and python3.
EOF
}

ZONE="" CERT_ID="" FP="" LOOKUP_ONLY=0 YES=0
while [ $# -gt 0 ]; do
	case "$1" in
	--zone) need_arg "$1" "${2:-}"; ZONE=$2; shift 2 ;;
	--id) need_arg "$1" "${2:-}"; CERT_ID=$2; shift 2 ;;
	--fingerprint) need_arg "$1" "${2:-}"; FP=$2; shift 2 ;;
	--lookup-only) LOOKUP_ONLY=1; shift ;;
	--yes) YES=1; shift ;;
	--token-file) need_arg "$1" "${2:-}"; TOKEN_FILE=$2; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage_error "unknown argument: $1" ;;
	esac
done

check_zone_id "$ZONE"
if [ -n "$CERT_ID" ] && [ -n "$FP" ]; then
	usage_error "give --id or --fingerprint, not both"
fi
if [ -z "$CERT_ID" ] && [ -z "$FP" ]; then
	usage_error "--id or --fingerprint is required"
fi
if [ -n "$CERT_ID" ]; then
	printf '%s' "$CERT_ID" | grep -Eq '^[A-Za-z0-9-]{1,64}$' ||
		usage_error "--id must be a certificate id (letters, digits and hyphens)"
	[ "$LOOKUP_ONLY" = 0 ] || usage_error "--lookup-only needs --fingerprint"
fi
if [ -n "$FP" ]; then
	FP=$(normalize_fingerprint "$FP")
	valid_fingerprint "$FP" || usage_error "--fingerprint must be a SHA-256 fingerprint: 64 hex characters"
fi

need_python
[ "$DRY_RUN" = 1 ] || need curl
make_work_dir

LIST_PATH="/zones/$ZONE/client_certificates"
PER_PAGE=50
MAX_PAGES=40

reminder() {
	local old=${1:-<OLD_SHA256>} which="fingerprint ${1:-}"
	[ -n "${1:-}" ] || which="that certificate's fingerprint"
	cat <<EOF

The edge refuses the certificate once its status reaches "revoked" (how
fast that is enforced is unverified; measure it). Also cut it off at the
relay: replace $which in deploy/relay.json (or PEERS in
relay-worker/wrangler.toml) with a value that matches no certificate,
rather than deleting it, because every peer must keep at least one
fingerprint (docs/operations.md, revocation drill step 4):

  deploy/scripts/add-fingerprint.sh --peer <PEER> --replace $old --fingerprint "\$(openssl rand -hex 32)"

  Docker relay:  that edits deploy/relay.json; then docker compose restart relay
  Worker relay:  add --worker-peers relay-worker/wrangler.toml; then npx wrangler deploy
EOF
}

if [ "$DRY_RUN" = 1 ]; then
	printf 'Dry run: these requests would be sent (token not read):\n\n'
	if [ -n "$FP" ]; then
		print_request GET "$LIST_PATH?per_page=$PER_PAGE&page=1"
		printf '(further pages while needed, up to %s; then the id of the certificate whose fingerprint_sha256 is %s)\n\n' "$MAX_PAGES" "$FP"
		[ "$LOOKUP_ONLY" = 0 ] || exit 0
		print_request DELETE "$LIST_PATH/<CERT_ID from the lookup>"
	else
		print_request DELETE "$LIST_PATH/$CERT_ID"
	fi
	exit 0
fi

load_token

if [ -n "$FP" ]; then
	# Page through the list until the fingerprint turns up. Filter and
	# pagination parameters are unverified; a server that ignores them
	# returns the same page, which the empty-page and total_pages checks
	# and MAX_PAGES end.
	FOUND="$WORK_DIR/found"
	: >"$FOUND"
	page=1
	while [ "$page" -le "$MAX_PAGES" ]; do
		RESP="$WORK_DIR/list.$page.json"
		cf_request GET "$LIST_PATH?per_page=$PER_PAGE&page=$page" "$RESP" || api_failed "$RESP"
		more=$(python3 -I -c '
import json, re, sys
with open(sys.argv[1], "rb") as f:
    doc = json.load(f)
if not isinstance(doc, dict) or doc.get("success") is not True or not isinstance(doc.get("result"), list):
    sys.exit("the API did not return a certificate list")
want, page = sys.argv[2], int(sys.argv[4])
def clean(v, pattern):
    v = v if isinstance(v, str) else ""
    return v if re.fullmatch(pattern, v) else "?"
with open(sys.argv[3], "a") as out:
    for c in doc["result"]:
        if not isinstance(c, dict):
            continue
        fp = str(c.get("fingerprint_sha256", "")).lower().replace(":", "").replace(" ", "")
        if fp == want:
            out.write("\t".join([clean(c.get("id"), r"[A-Za-z0-9-]{1,64}"), clean(c.get("status"), r"[a-z_]{1,40}"),
                                 clean(c.get("expires_on"), r"[0-9A-Za-z:.+-]{1,40}")]) + "\n")
info = doc.get("result_info") if isinstance(doc.get("result_info"), dict) else {}
total = info.get("total_pages")
same = False
if page > 1:
    with open(sys.argv[6], "rb") as f:
        same = json.load(f).get("result") == doc["result"]
if same or not doc["result"] or (isinstance(total, int) and page >= total) or len(doc["result"]) < int(sys.argv[5]):
    print("no")
else:
    print("yes")
' "$RESP" "$FP" "$FOUND" "$page" "$PER_PAGE" "$WORK_DIR/list.$((page - 1)).json") ||
			die "unexpected response from the API"
		[ "$more" = yes ] || break
		[ ! -s "$FOUND" ] || break
		page=$((page + 1))
	done
	matches=$(sort -u "$FOUND" | wc -l | tr -d ' ')
	if [ "$matches" = 0 ]; then
		die "no client certificate in this zone has fingerprint $FP"
	fi
	if [ "$matches" != 1 ]; then
		printf '%s: more than one certificate has fingerprint %s:\n' "$PROG" "$FP" >&2
		sort -u "$FOUND" >&2
		exit 1
	fi
	IFS="$(printf '\t')" read -r CERT_ID found_status found_expires <"$FOUND"
	[ "$CERT_ID" != "?" ] || die "the certificate with fingerprint $FP has no usable id in the response"
	printf 'Certificate with fingerprint %s:\n  id:       %s\n  status:   %s\n  expires:  %s\n' \
		"$FP" "$CERT_ID" "$found_status" "$found_expires"
	if [ "$LOOKUP_ONLY" = 1 ]; then
		exit 0
	fi
	case "$found_status" in
	revoked | pending_revocation)
		printf 'It is already %s; nothing to revoke at the edge.\n' "$found_status"
		reminder "$FP"
		exit 0
		;;
	esac
fi

if [ "$YES" != 1 ]; then
	printf 'Revoke client certificate %s? This cannot be undone. Type "revoke" to confirm: ' "$CERT_ID" >&2
	answer=""
	read -r answer || true
	[ "$answer" = revoke ] || die "not confirmed; nothing revoked"
fi

RESP="$WORK_DIR/revoke.json"
cf_request DELETE "$LIST_PATH/$CERT_ID" "$RESP" || api_failed "$RESP"
CF_TOKEN=""
python3 -I -c '
import json, re, sys
with open(sys.argv[1], "rb") as f:
    doc = json.load(f)
if not isinstance(doc, dict) or doc.get("success") is not True:
    sys.exit("the API did not report success")
r = doc.get("result") if isinstance(doc.get("result"), dict) else {}
def clean(v, pattern):
    v = v if isinstance(v, str) else ""
    return v if re.fullmatch(pattern, v) else "unknown"
print("Revocation requested for certificate %s." % sys.argv[2])
print("  status:   %s" % clean(r.get("status"), r"[a-z_]{1,40}"))
fp = clean(r.get("fingerprint_sha256"), r"[0-9A-Fa-f: ]{64,95}")
fp = "" if fp == "unknown" else fp.lower().replace(":", "").replace(" ", "")
if fp:
    print("  sha256:   %s" % fp)
with open(sys.argv[3], "w") as f:
    f.write(fp)
' "$RESP" "$CERT_ID" "$WORK_DIR/revoked-fp" || die "unexpected response from the API; check the certificate status in the dashboard"

if [ -z "$FP" ]; then
	FP=$(cat "$WORK_DIR/revoked-fp")
	valid_fingerprint "$FP" || FP=""
fi
reminder "$FP"
