#!/usr/bin/env bash
# Generate the Docker relay's edge secret, or the next one for a rotation.
# See docs/edge-setup.md step 1 and "Edge secret rotation".
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
. "$(dirname "$0")/_common.sh"

usage() {
	cat <<EOF
Usage: $PROG [--next] [--force] [--secrets-dir DIR] [--dry-run]

Writes a new random edge secret (openssl rand -hex 32) to
deploy/secrets/edge-secret, or with --next to deploy/secrets/edge-secret-next,
with umask 077 and mode 0400. The value is never printed.

  --next             write the next secret, for a rotation without downtime
  --force            replace an existing file (for the current secret this
                     breaks the edge until the transform rule is updated;
                     prefer a rotation with --next)
  --secrets-dir DIR  directory to write to (default: deploy/secrets in this repo)
  --dry-run          say what would be written, write nothing
  -h, --help         show this help

Needs openssl.
EOF
}

NEXT=0 FORCE=0 DIR="$REPO_ROOT/deploy/secrets"
while [ $# -gt 0 ]; do
	case "$1" in
	--next) NEXT=1; shift ;;
	--force) FORCE=1; shift ;;
	--secrets-dir) need_arg "$1" "${2:-}"; DIR=$2; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage_error "unknown argument: $1" ;;
	esac
done

CURRENT="$DIR/edge-secret"
TARGET=$CURRENT
[ "$NEXT" = 0 ] || TARGET="$DIR/edge-secret-next"

need openssl
if [ -d "$TARGET" ] || [ -L "$TARGET" ]; then
	die "$TARGET is a directory or a symbolic link; refusing to touch it"
fi
if [ -e "$TARGET" ] && [ "$FORCE" != 1 ]; then
	if [ "$NEXT" = 1 ]; then
		die "$TARGET exists; refusing to overwrite it. Finish or abandon the rotation in progress first (docs/edge-setup.md), or use --force"
	fi
	die "$TARGET exists; refusing to overwrite it. To change it, rotate: $PROG --next (docs/edge-setup.md, Edge secret rotation)"
fi
if [ "$NEXT" = 1 ] && [ ! -e "$CURRENT" ]; then
	die "there is no current edge secret ($CURRENT); run $PROG without --next first"
fi

if [ "$DRY_RUN" = 1 ]; then
	printf 'Dry run: would write %s (mode 0400, umask 077) from openssl rand -hex 32. Nothing written.\n' "$TARGET"
	exit 0
fi

if [ ! -d "$DIR" ]; then
	(umask 077 && mkdir -p "$DIR") || die "cannot create $DIR"
	chmod 0700 "$DIR"
fi

umask 077
TMP=$(mktemp "$DIR/.edge-secret.XXXXXX") || die "cannot create a file in $DIR"
trap 'rm -f "$TMP"' EXIT
trap 'exit 130' HUP INT TERM
openssl rand -hex 32 >"$TMP" || die "openssl rand failed"
# Check the shape without printing it: one line of 64 lowercase hex.
if [ "$(wc -l <"$TMP" | tr -d ' ')" != 1 ] || ! grep -Eq '^[0-9a-f]{64}$' "$TMP"; then
	die "openssl rand produced unexpected output; nothing written"
fi
chmod 0400 "$TMP"
mv -f "$TMP" "$TARGET" || die "cannot move the new secret into place at $TARGET (owned by another user? use sudo mv)"
trap - EXIT

printf 'Wrote %s (mode 0400, 64 hex characters). The value was not printed.\n' "$TARGET"
if [ "$NEXT" = 1 ]; then
	cat <<'EOF'

Next (docs/edge-setup.md, "Edge secret rotation"):
  1. Add "edge_secret_next_file": "/run/secrets/edge_secret_next" to deploy/relay.json.
  2. docker compose -f docker-compose.yml -f deploy/compose.edge-secret-next.yml up -d --force-recreate relay
  3. Put the new value in the transform rule, wait for "edge_secret_slot":"next" in the relay log.
  4. mv deploy/secrets/edge-secret-next deploy/secrets/edge-secret, remove the relay.json line,
     docker compose up -d --force-recreate relay
On a Linux host the relay (65532:65532) must be able to read it:
  sudo chown 65532:65532 deploy/secrets/edge-secret-next
EOF
else
	cat <<'EOF'

Next: copy it into the transform rule (docs/edge-setup.md step 8) without printing it,
for example pbcopy < deploy/secrets/edge-secret, and clear the clipboard afterwards.
On a Linux host, after that: sudo chown 65532:65532 deploy/secrets/edge-secret
EOF
fi
