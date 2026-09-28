#!/bin/sh
# Installer smoke test for a fresh distro container (no running init):
# install, check the generated service files, run the node the way the
# service would, query its API, then re-run the installer as an upgrade.
# Usage: installer-smoke.sh INIT   (systemd | openrc | none)
set -eu
init=$1
src=$(cd "$(dirname "$0")/../.." && pwd)

sh "$src/scripts/install.sh" --source "$src" --yes --init "$init" \
    --no-detect --no-asn-db --asn 64500 --country DE --peer https://peer.example.invalid

witness --version
case "$init" in
    systemd) systemd-analyze verify /etc/systemd/system/witness.service \
        /etc/systemd/system/witness-asn-update.service /etc/systemd/system/witness-asn-update.timer ;;
    openrc) test -x /etc/init.d/witness && sh -n /etc/init.d/witness ;;
esac

as_witness() {
    if command -v runuser >/dev/null 2>&1; then runuser -u witness -- "$@"; else su-exec witness "$@"; fi
}

as_witness env WITNESS_DIR=/var/lib/witness HOME=/var/lib/witness \
    witness serve --addr 127.0.0.1:8480 --api-addr 127.0.0.1:8481 --watch >/tmp/witness.log 2>&1 &
pid=$!
i=0
until curl -fsS http://127.0.0.1:8481/v1/descriptor >/tmp/descriptor.json 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 30 ]; then cat /tmp/witness.log; exit 1; fi
    sleep 1
done
grep -q '"asn":64500' /tmp/descriptor.json
kill "$pid"
wait "$pid" 2>/dev/null || true

# Plain `witness` as root: it finds the node and becomes the witness user.
witness watch add https://example.org/ --every 6h >/dev/null
test "$(stat -c %U /var/lib/witness/index.sqlite)" = witness

key() { witness id | awk '/witness key/ {print $3}'; }
before=$(key)
sh "$src/scripts/install.sh" --source "$src" --yes --init "$init" --no-detect --no-asn-db --retain normalized
test "$before" = "$(key)"
test "$(witness config get content.retain)" = normalized

sh "$src/scripts/install.sh" --uninstall --purge --yes --init "$init"
if id witness >/dev/null 2>&1; then echo "the witness user still exists" >&2; exit 1; fi
echo "installer smoke test passed ($init)"
