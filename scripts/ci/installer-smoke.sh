#!/bin/sh
# Installer smoke test for a fresh distro container (no running init):
# install, check the generated service files, run the node the way the
# service would, query its API, then re-run the installer as an upgrade.
# The node never dials the default seeds: it would join the real network.
# Usage: installer-smoke.sh INIT   (systemd | openrc | none)
set -eu
init=$1
src=$(cd "$(dirname "$0")/../.." && pwd)

sh "$src/scripts/install.sh" --source "$src" --yes --init "$init" \
    --no-detect --no-asn-db --asn 64500 --country DE --peer https://peer.example.invalid --no-seeds

keepword --version
test "$(keepword config get network.seeds)" = false
case "$init" in
    systemd) systemd-analyze verify /etc/systemd/system/keepword.service \
        /etc/systemd/system/keepword-asn-update.service /etc/systemd/system/keepword-asn-update.timer ;;
    openrc) test -x /etc/init.d/keepword && sh -n /etc/init.d/keepword ;;
esac

as_keepword() {
    if command -v runuser >/dev/null 2>&1; then runuser -u keepword -- "$@"; else su-exec keepword "$@"; fi
}

as_keepword env KEEPWORD_DIR=/var/lib/keepword HOME=/var/lib/keepword \
    keepword serve --addr 127.0.0.1:8480 --api-addr 127.0.0.1:8481 --watch >/tmp/keepword.log 2>&1 &
pid=$!
i=0
until curl -fsS http://127.0.0.1:8481/v1/descriptor >/tmp/descriptor.json 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 30 ]; then cat /tmp/keepword.log; exit 1; fi
    sleep 1
done
grep -q '"asn":64500' /tmp/descriptor.json
kill "$pid"
wait "$pid" 2>/dev/null || true

# Plain `keepword` as root: it finds the node and becomes the keepword user.
keepword watch add https://example.org/ --every 6h >/dev/null
test "$(stat -c %U /var/lib/keepword/index.sqlite)" = keepword

key() { keepword id | awk '/witness key/ {print $3}'; }
before=$(key)
sh "$src/scripts/install.sh" --source "$src" --yes --init "$init" --no-detect --no-asn-db --retain normalized
test "$before" = "$(key)"
test "$(keepword config get content.retain)" = normalized
test "$(keepword config get network.seeds)" = false

sh "$src/scripts/install.sh" --uninstall --purge --yes --init "$init"
if id keepword >/dev/null 2>&1; then echo "the keepword user still exists" >&2; exit 1; fi
echo "installer smoke test passed ($init)"
