#!/usr/bin/env bash
# Issue a client certificate for a bridge from its CSR, using the edge's
# client-certificate API (Cloudflare-managed CA). See docs/edge-setup.md
# step 5.
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
. "$(dirname "$0")/_common.sh"

usage() {
	cat <<EOF
Usage: $PROG --zone ZONE_ID --csr peer-a.csr [--days 14] [--out peer-a.pem]
                     [--token-file FILE] [--force] [--dry-run]

POSTs the CSR to the client-certificate API of the zone, writes the
returned certificate as PEM, and prints its id and SHA-256 fingerprint.
The fingerprint is computed locally with openssl and must match the API's
fingerprint_sha256, and the certificate must carry the CSR's public key;
otherwise nothing is written.

  --zone ZONE_ID     zone id of the zone that holds the relay hostname
  --csr FILE         the bridge's CSR (postern cert csr --out FILE)
  --days N           validity in days (default 14; certificates rotate weekly)
  --out FILE         where to write the PEM (default: the CSR path with .pem)
  --token-file FILE  read the API token from FILE (mode 0600) instead of the
                     keychain item "$KEYCHAIN_SERVICE"
  --force            overwrite an existing --out file
  --dry-run          print the request instead of sending it; reads no token
  -h, --help         show this help

The token is passed to curl on stdin, never in argv or the environment.
Needs curl (7.76 or later), openssl and python3.
EOF
}

ZONE="" CSR="" DAYS=14 OUT="" FORCE=0
while [ $# -gt 0 ]; do
	case "$1" in
	--zone) need_arg "$1" "${2:-}"; ZONE=$2; shift 2 ;;
	--csr) need_arg "$1" "${2:-}"; CSR=$2; shift 2 ;;
	--days) need_arg "$1" "${2:-}"; DAYS=$2; shift 2 ;;
	--out) need_arg "$1" "${2:-}"; OUT=$2; shift 2 ;;
	--token-file) need_arg "$1" "${2:-}"; TOKEN_FILE=$2; shift 2 ;;
	--force) FORCE=1; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage_error "unknown argument: $1" ;;
	esac
done

check_zone_id "$ZONE"
[ -n "$CSR" ] || usage_error "--csr is required"
case "$DAYS" in
'' | *[!0-9]*) usage_error "--days must be a whole number of days" ;;
esac
if [ "${#DAYS}" -gt 4 ] || [ "$DAYS" -lt 1 ] || [ "$DAYS" -gt 3650 ]; then
	usage_error "--days must be between 1 and 3650"
fi
if [ -z "$OUT" ]; then
	OUT="${CSR%.csr}.pem"
	[ "$OUT" != "$CSR" ] || OUT="$CSR.pem"
fi

need_python
need openssl
[ "$DRY_RUN" = 1 ] || need curl

if [ ! -f "$CSR" ] || [ ! -r "$CSR" ]; then
	die "CSR not found or not readable: $CSR"
fi
[ "$(wc -c <"$CSR" | tr -d ' ')" -le 65536 ] || die "CSR file is too large: $CSR"
grep -q -- '-----BEGIN CERTIFICATE REQUEST-----' "$CSR" ||
	die "$CSR is not a PEM certificate signing request"
openssl req -in "$CSR" -noout -verify >/dev/null 2>&1 ||
	die "$CSR does not parse as a CSR, or its signature is invalid"
if [ -e "$OUT" ] && [ "$FORCE" != 1 ]; then
	die "$OUT exists; refusing to overwrite it (use --force)"
fi

make_work_dir
BODY="$WORK_DIR/request.json"
python3 -I -c '
import json, sys
with open(sys.argv[1]) as f:
    csr = f.read()
with open(sys.argv[3], "w") as f:
    json.dump({"csr": csr, "validity_days": int(sys.argv[2])}, f)
' "$CSR" "$DAYS" "$BODY"

PATH_ISSUE="/zones/$ZONE/client_certificates"
if [ "$DRY_RUN" = 1 ]; then
	printf 'Dry run: this request would be sent (token not read, nothing written):\n\n'
	print_request POST "$PATH_ISSUE" "$BODY"
	printf '\nThe certificate would be written to %s.\n' "$OUT"
	exit 0
fi

load_token
RESP="$WORK_DIR/response.json"
cf_request POST "$PATH_ISSUE" "$RESP" "$BODY" || api_failed "$RESP"
CF_TOKEN=""

# Pull the fields out of the response; the certificate goes to a file.
PEM_TMP="$WORK_DIR/cert.pem"
FIELDS="$WORK_DIR/fields"
python3 -I -c '
import json, re, sys
with open(sys.argv[1], "rb") as f:
    doc = json.load(f)
if not isinstance(doc, dict) or doc.get("success") is not True or not isinstance(doc.get("result"), dict):
    sys.exit("the API did not report success")
r = doc["result"]
cert = r.get("certificate")
if not isinstance(cert, str) or "-----BEGIN CERTIFICATE-----" not in cert:
    sys.exit("the response has no certificate")
def field(name, pattern):
    v = r.get(name)
    v = v if isinstance(v, str) else ""
    return v if re.fullmatch(pattern, v) else ""
cid = field("id", r"[A-Za-z0-9-]{1,64}")
if not cid:
    sys.exit("the response has no usable certificate id")
fp = field("fingerprint_sha256", r"[0-9A-Fa-f: ]{64,95}")
with open(sys.argv[2], "w") as f:
    f.write(cert if cert.endswith("\n") else cert + "\n")
with open(sys.argv[3], "w") as f:
    f.write("\n".join([cid, fp, field("expires_on", r"[0-9A-Za-z:.+-]{1,40}"), field("status", r"[a-z_]{1,40}")]) + "\n")
' "$RESP" "$PEM_TMP" "$FIELDS" || die "unexpected response from the API; nothing written"

{
	read -r CERT_ID
	read -r API_FP
	read -r EXPIRES
	read -r STATUS
} <"$FIELDS"

LOCAL_FP=$(openssl x509 -in "$PEM_TMP" -outform DER | openssl dgst -sha256 | awk '{print $NF}' | tr 'A-F' 'a-f')
valid_fingerprint "$LOCAL_FP" || die "cannot compute the certificate's fingerprint (id $CERT_ID); nothing written"
API_FP=$(normalize_fingerprint "$API_FP")
if [ "$API_FP" != "$LOCAL_FP" ]; then
	die "fingerprint mismatch: computed $LOCAL_FP, the API says ${API_FP:-nothing}. Nothing written. Revoke certificate $CERT_ID (revoke-cert.sh --id $CERT_ID) and investigate."
fi
CSR_KEY=$(openssl req -in "$CSR" -noout -pubkey)
CERT_KEY=$(openssl x509 -in "$PEM_TMP" -noout -pubkey)
if [ "$CSR_KEY" != "$CERT_KEY" ]; then
	die "the issued certificate does not carry the CSR's public key. Nothing written. Revoke certificate $CERT_ID (revoke-cert.sh --id $CERT_ID) and investigate."
fi

# Certificates are public; write it next to the destination, then rename.
OUT_TMP=$(mktemp "$(dirname "$OUT")/.issue-cert.XXXXXX") || die "cannot write next to $OUT"
cat "$PEM_TMP" >"$OUT_TMP"
chmod 0644 "$OUT_TMP"
mv -f "$OUT_TMP" "$OUT"

cat <<EOF
Issued client certificate.
  id:       $CERT_ID   (keep it: revoking needs it)
  sha256:   $LOCAL_FP   (matches the API's fingerprint_sha256)
  expires:  ${EXPIRES:-unknown}
  status:   ${STATUS:-unknown}
  written:  $OUT

Next: give $OUT to the bridge (postern cert import $(basename "$OUT")); it must print the
same SHA-256. Then register it with the relay:
  deploy/scripts/add-fingerprint.sh --peer <PEER> --fingerprint $LOCAL_FP
EOF
