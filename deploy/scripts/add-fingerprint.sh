#!/usr/bin/env bash
# Add, replace or remove a client certificate fingerprint in the relay's
# peers map: deploy/relay.json (Docker relay) or PEERS in
# relay-worker/wrangler.toml (Worker relay). See docs/edge-setup.md
# step 6 and docs/operations.md.
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
. "$(dirname "$0")/_common.sh"

usage() {
	cat <<EOF
Usage: $PROG --peer NAME --fingerprint SHA256 [--replace OLD_SHA256 | --remove]
                        [--relay-json FILE | --worker-peers FILE] [--new-peer] [--dry-run]

Edits the peers map (peer name -> SHA-256 fingerprints of its client
certificates). A peer may list at most 2 fingerprints: the current
certificate and, during a rotation, the next one.

  --peer NAME           the peer (lowercase letters, digits, hyphens)
  --fingerprint SHA256  64 lowercase hex characters, as postern cert import
                        and issue-cert.sh print it
  --replace OLD_SHA256  put --fingerprint in place of OLD_SHA256 (for example
                        an unmatchable value after a revocation)
  --remove              remove --fingerprint from the peer (refused for the
                        peer's last one; use --replace instead)
  --relay-json FILE     edit this relay.json (default: deploy/relay.json)
  --worker-peers FILE   edit PEERS in this wrangler.toml instead
  --new-peer            allow adding a peer that is not in the map yet
  --dry-run             print the resulting peers map, write nothing
  -h, --help            show this help

Placeholder entries such as <PEER_A_CERT_SHA256> are dropped when a real
fingerprint is added. Fingerprints are public; nothing here is secret.
Needs python3 (3.11 or later also cross-checks wrangler.toml with tomllib).
EOF
}

PEER="" FPRINT="" REPLACE="" REMOVE=0 RELAY_JSON="" WORKER="" NEW_PEER=0
while [ $# -gt 0 ]; do
	case "$1" in
	--peer) need_arg "$1" "${2:-}"; PEER=$2; shift 2 ;;
	--fingerprint) need_arg "$1" "${2:-}"; FPRINT=$2; shift 2 ;;
	--replace) need_arg "$1" "${2:-}"; REPLACE=$2; shift 2 ;;
	--remove) REMOVE=1; shift ;;
	--relay-json) need_arg "$1" "${2:-}"; RELAY_JSON=$2; shift 2 ;;
	--worker-peers) need_arg "$1" "${2:-}"; WORKER=$2; shift 2 ;;
	--new-peer) NEW_PEER=1; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage_error "unknown argument: $1" ;;
	esac
done

[ -n "$PEER" ] || usage_error "--peer is required"
printf '%s' "$PEER" | grep -Eq '^[a-z0-9][a-z0-9-]{0,31}$' ||
	usage_error "--peer must be 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit"
[ -n "$FPRINT" ] || usage_error "--fingerprint is required"
valid_fingerprint "$FPRINT" ||
	usage_error "--fingerprint must be 64 lowercase hex characters (no colons or spaces)"
if [ -n "$REPLACE" ]; then
	valid_fingerprint "$REPLACE" || usage_error "--replace must be 64 lowercase hex characters"
	[ "$REMOVE" = 0 ] || usage_error "give --replace or --remove, not both"
	[ "$REPLACE" != "$FPRINT" ] || usage_error "--replace and --fingerprint are the same"
fi
if [ -n "$RELAY_JSON" ] && [ -n "$WORKER" ]; then
	usage_error "give --relay-json or --worker-peers, not both"
fi
MODE=json FILE=${RELAY_JSON:-$REPO_ROOT/deploy/relay.json}
if [ -n "$WORKER" ]; then
	MODE=toml FILE=$WORKER
fi
OP=add
[ -z "$REPLACE" ] || OP=replace
[ "$REMOVE" = 0 ] || OP=remove

need_python
[ -f "$FILE" ] || die "$FILE not found (copy it from the example first; see docs/edge-setup.md)"

# All edits are done in python: the file is parsed, changed and written
# back atomically (same directory, same mode), or left untouched.
# shellcheck disable=SC2016 # the $(openssl ...) in a message is for the operator to run
python3 -I -c '
import json, os, re, sys, tempfile

prog, mode, path, op, peer, fp, old, new_peer, dry = sys.argv[1:10]
FP = re.compile(r"[0-9a-f]{64}")
PLACEHOLDER = re.compile(r"<[^<>]*>")
MAX = 2

def die(msg):
    sys.stderr.write("%s: %s\n" % (prog, msg))
    sys.exit(1)

def no_dupes(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            die("%s has the key %r twice; fix it by hand first" % (path, k))
        seen[k] = v
    return seen

with open(path, encoding="utf-8") as f:
    text = f.read()

if mode == "json":
    try:
        doc = json.loads(text, object_pairs_hook=no_dupes)
    except ValueError as e:
        die("%s is not valid JSON: %s" % (path, e))
    if not isinstance(doc, dict) or not isinstance(doc.get("peers"), dict):
        die("%s has no \"peers\" object" % path)
    peers = doc["peers"]
else:
    lines = text.splitlines(keepends=True)
    hits = [i for i, l in enumerate(lines) if re.match(r"\s*PEERS\s*=", l)]
    if len(hits) != 1:
        die("%s must have exactly one PEERS = ... line (found %d)" % (path, len(hits)))
    idx = hits[0]
    m = re.fullmatch(r"(\s*PEERS\s*=\s*)\x27([^\x27\n]*)\x27(\s*(?:#[^\n]*)?)(\n?)", lines[idx])
    if not m:
        die("%s: the PEERS line must be one single-quoted TOML string, as in wrangler.toml.example" % path)
    section = ""
    for l in lines[:idx]:
        s = re.match(r"\s*\[([^\]]*)\]", l)
        if s:
            section = s.group(1).strip()
    if section != "vars":
        die("%s: the PEERS line is not in the [vars] table" % path)
    try:
        import tomllib
    except ImportError:
        tomllib = None
    if tomllib is not None:
        try:
            parsed = tomllib.loads(text)
        except Exception as e:
            die("%s is not valid TOML: %s" % (path, e))
        if parsed.get("vars", {}).get("PEERS") != m.group(2):
            die("%s: the PEERS line does not match the parsed [vars] PEERS value" % path)
    try:
        peers = json.loads(m.group(2), object_pairs_hook=no_dupes)
    except ValueError as e:
        die("%s: PEERS is not valid JSON: %s" % (path, e))
    if not isinstance(peers, dict):
        die("%s: PEERS must be a JSON object of peer name to fingerprints" % path)

for name, fps in peers.items():
    if not isinstance(fps, list) or not all(isinstance(x, str) for x in fps):
        die("peer %r: fingerprints must be a list of strings" % name)

def norm(s):
    return s.lower().replace(":", "").replace(" ", "")

owner = {norm(x): name for name, fps in peers.items() for x in fps}

if peer not in peers:
    if op != "add":
        die("peer %s is not in %s" % (peer, path))
    if new_peer != "1":
        die("peer %s is not in %s; check the name, or pass --new-peer to add it (known: %s)"
            % (peer, path, ", ".join(sorted(peers)) or "none"))
    peers[peer] = []

cur = peers[peer]
real = [x for x in cur if not PLACEHOLDER.fullmatch(x.strip())]
dropped = len(cur) - len(real)

if op == "add":
    if fp in owner:
        if owner[fp] == peer:
            print("%s is already listed for %s in %s; nothing changed." % (fp, peer, path))
            sys.exit(0)
        die("%s is already listed for peer %s; a fingerprint may belong to one peer only" % (fp, owner[fp]))
    if len(real) >= MAX:
        die("peer %s already lists %d fingerprints, the most allowed (current and next during a rotation). "
            "Remove the old one first: add-fingerprint.sh --peer %s --remove --fingerprint <OLD_SHA256>"
            % (peer, len(real), peer))
    peers[peer] = real + [fp]
    what = "Added %s to peer %s" % (fp, peer)
    if dropped:
        what += " (dropped %d placeholder%s)" % (dropped, "" if dropped == 1 else "s")
elif op == "replace":
    if norm(old) not in [norm(x) for x in cur]:
        die("%s is not listed for peer %s" % (old, peer))
    if fp in owner:
        die("%s is already listed for peer %s" % (fp, owner[fp]))
    peers[peer] = [fp if norm(x) == norm(old) else x for x in cur]
    what = "Replaced %s with %s for peer %s" % (old, fp, peer)
else:
    if fp not in [norm(x) for x in cur]:
        die("%s is not listed for peer %s" % (fp, peer))
    rest = [x for x in cur if norm(x) != fp]
    if not [x for x in rest if not PLACEHOLDER.fullmatch(x.strip())]:
        die("%s is the last fingerprint of peer %s, and every peer needs one. Replace it with a value that "
            "matches no certificate instead: add-fingerprint.sh --peer %s --replace %s --fingerprint \"$(openssl rand -hex 32)\""
            % (fp, peer, peer, fp))
    peers[peer] = rest
    what = "Removed %s from peer %s" % (fp, peer)

warnings = []
for name, fps in peers.items():
    for x in fps:
        if not FP.fullmatch(norm(x)):
            warnings.append("peer %s still has %r, which is not a fingerprint; the relay refuses to start until it is replaced" % (name, x))
if len(peers) < 2:
    warnings.append("the relay needs at least two peers")

if mode == "json":
    out = json.dumps(doc, indent=2) + "\n"
else:
    value = json.dumps(peers, separators=(",", ":"))
    if "\x27" in value or "\n" in value:
        die("internal error: PEERS value cannot be written as a TOML literal string")
    lines[idx] = m.group(1) + "\x27" + value + "\x27" + m.group(3) + m.group(4)
    out = "".join(lines)

print("Peers after the change:")
for name, fps in peers.items():
    print("  %s: %s" % (name, ", ".join(fps) if fps else "(none)"))
for w in warnings:
    print("Warning: " + w)

if dry == "1":
    print("Dry run: %s would be changed: %s. Nothing written." % (path, what))
    sys.exit(0)

st = os.stat(path)
d = os.path.dirname(os.path.abspath(path))
fd, tmp = tempfile.mkstemp(prefix=".add-fingerprint.", dir=d)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(out)
    os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
print("%s in %s." % (what, path))
if mode == "json":
    print("Next: docker compose restart relay (the relay reads relay.json only at start).")
else:
    print("Next: cd relay-worker && npx wrangler deploy (vars change only with a deploy).")
' "$PROG" "$MODE" "$FILE" "$OP" "$PEER" "$FPRINT" "$REPLACE" "$NEW_PEER" "$DRY_RUN"
