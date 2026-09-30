#!/bin/sh
# Keepword production installer.
#
# Builds Keepword from source and sets it up as a hardened system service:
# a dedicated user, a data directory, an IP-to-ASN table that refreshes
# weekly, systemd (or OpenRC) units, and optionally a TLS reverse proxy
# (Caddy) and the TLSNotary notary service.
#
# Supported: Debian, Ubuntu, Fedora, RHEL-likes, Arch, openSUSE, Alpine.
# Re-running upgrades an existing installation in place; the witness key and
# data are never touched. Run with --help for options.

set -eu

REPO_URL="https://github.com/aelthorim/keepword.git"
REPO_REF="main"
PREFIX="/usr/local"
DATA_DIR="/var/lib/keepword"
OPT_DIR="/opt/keepword"
SVC_USER="keepword"
UI_ADDR="127.0.0.1:8480"
API_ADDR="127.0.0.1:8481"
NOTARY_ADDR="0.0.0.0:8482"
ASN_DB_URL="https://iptoasn.com/data/ip2asn-combined.tsv.gz"
MIN_RUST="1.85"
NOTARY_MIN_RUST="1.95"

SOURCE=""
ASN=""
COUNTRY=""
DOMAIN=""
ENDPOINT=""
PUBLIC_API=""
PEERS=""
SEEDS=1
RETAIN=""
RENDER=0
NOTARY=0
CADDY=0
START=1
INIT=""
PACKAGES=1
ASN_DB=1
DETECT=1
YES=0
UNINSTALL=0
PURGE=0

usage() {
    cat <<'EOF'
Usage: install.sh [options]

Where this node is (self-reported; peers corroborate it):
  --asn N               Autonomous system number, e.g. 3320
  --country CC          ISO country code, e.g. DE
  --no-detect           Don't detect ASN/country from this machine's public IP
                        (detection asks api.ipify.org for the address)

Network:
  --domain NAME         Serve the peer API at https://NAME/v1 through a reverse
                        proxy; the API itself binds to 127.0.0.1:8481
  --caddy               Install and configure Caddy for --domain (automatic TLS)
  --public-api ADDR     Bind the API directly on ADDR (e.g. 0.0.0.0:8481)
  --endpoint URL        Public API URL to advertise (default: from --domain)
  --peer URL            Bootstrap peer; repeat for several
  --no-seeds            Don't join through the project's seed witnesses (a
                        separate network, or a test install)
  --no-asn-db           Skip the IP-to-ASN table (verdicts need it)

Features:
  --retain MODE         full | normalized | none (default: full)
  --render              Build headless-browser capture and install Chromium
  --notary              Build the TLSNotary tier and run a notary on :8482

Installation:
  --source DIR          Build from a local checkout
  --repo URL            Git repository (default: aelthorim/keepword on GitHub)
  --ref REF             Branch or tag (default: main)
  --prefix DIR          Binary prefix (default: /usr/local)
  --data-dir DIR        Data directory (default: /var/lib/keepword)
  --no-start            Install and configure, but don't start services
  --init SYSTEM         systemd | openrc | none (default: detect); set it when
                        installing into an image or chroot
  --no-packages         Don't install system packages (you provide a C
                        compiler, git, curl, and Chromium/Caddy if used)
  -y, --yes             Don't ask for confirmation

  --uninstall           Remove services and binaries, keep data
  --purge               With --uninstall: also delete data and the user
  -h, --help            Show this help
EOF
}

# ------------------------------------------------------------------ output

if [ -t 1 ]; then
    BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RESET=$(printf '\033[0m')
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

step() { printf '\n%s==>%s %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$*" "$RESET"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die() { printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# --------------------------------------------------------------- arguments

need_arg() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --asn) need_arg "$@"; ASN=$2; shift ;;
        --country) need_arg "$@"; COUNTRY=$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]'); shift ;;
        --no-detect) DETECT=0 ;;
        --domain) need_arg "$@"; DOMAIN=$2; shift ;;
        --caddy) CADDY=1 ;;
        --public-api) need_arg "$@"; PUBLIC_API=$2; shift ;;
        --endpoint) need_arg "$@"; ENDPOINT=$2; shift ;;
        --peer) need_arg "$@"; PEERS="$PEERS $2"; shift ;;
        --no-seeds) SEEDS=0 ;;
        --no-asn-db) ASN_DB=0 ;;
        --retain) need_arg "$@"; RETAIN=$2; shift ;;
        --render) RENDER=1 ;;
        --notary) NOTARY=1 ;;
        --source) need_arg "$@"; SOURCE=$2; shift ;;
        --repo) need_arg "$@"; REPO_URL=$2; shift ;;
        --ref) need_arg "$@"; REPO_REF=$2; shift ;;
        --prefix) need_arg "$@"; PREFIX=$2; shift ;;
        --data-dir) need_arg "$@"; DATA_DIR=$2; shift ;;
        --no-start) START=0 ;;
        --init) need_arg "$@"; INIT=$2; shift ;;
        --no-packages) PACKAGES=0 ;;
        -y|--yes) YES=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

case "$ASN" in ''|*[!0-9]*) [ -z "$ASN" ] || die "--asn must be a number" ;; esac
case "$COUNTRY" in ''|[A-Z][A-Z]) ;; *) die "--country must be a two-letter code like DE" ;; esac
case "$RETAIN" in ''|full|normalized|none) ;; *) die "--retain must be full, normalized or none" ;; esac
[ "$CADDY" -eq 0 ] || [ -n "$DOMAIN" ] || die "--caddy needs --domain"
[ -z "$DOMAIN" ] || [ -z "$PUBLIC_API" ] || die "use either --domain or --public-api, not both"
[ "$PURGE" -eq 0 ] || [ "$UNINSTALL" -eq 1 ] || die "--purge only works with --uninstall"
case "$INIT" in ''|systemd|openrc|none) ;; *) die "--init must be systemd, openrc or none" ;; esac

BIN="$PREFIX/bin"
LIBEXEC="$PREFIX/lib/keepword"
if [ -n "$DOMAIN" ] && [ -z "$ENDPOINT" ]; then ENDPOINT="https://$DOMAIN"; fi
if [ -n "$PUBLIC_API" ]; then API_ADDR=$PUBLIC_API; fi

# ------------------------------------------------------------ environment

[ "$(id -u)" -eq 0 ] || die "run as root, e.g. sudo sh install.sh"

PKG=""
for pm in apt-get dnf yum pacman zypper apk; do
    if command -v "$pm" >/dev/null 2>&1; then PKG=$pm; break; fi
done

# Whether the init system is actually running (not just installed).
LIVE_INIT=0
if [ -d /run/systemd/system ]; then
    [ -n "$INIT" ] || INIT="systemd"
    [ "$INIT" != "systemd" ] || LIVE_INIT=1
elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
    [ -n "$INIT" ] || INIT="openrc"
    if [ "$INIT" = "openrc" ] && [ -d /run/openrc ]; then LIVE_INIT=1; fi
fi
[ -n "$INIT" ] || INIT="none"
# Without a running init system, services are installed but not started.
[ "$LIVE_INIT" -eq 1 ] || START=0

DISTRO="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    DISTRO=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
fi

# Run a command as the service user.
as_keepword() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$SVC_USER" -- "$@"
    elif command -v su-exec >/dev/null 2>&1; then
        su-exec "$SVC_USER" "$@"
    elif command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$SVC_USER" --regid="$SVC_USER" --init-groups "$@"
    else
        die "need runuser, su-exec or setpriv to drop privileges"
    fi
}

keepword() { as_keepword env KEEPWORD_DIR="$DATA_DIR" HOME="$DATA_DIR" "$BIN/keepword" "$@"; }

confirm() {
    [ "$YES" -eq 1 ] && return 0
    [ -t 0 ] || die "not a terminal; re-run with --yes to proceed"
    printf '%s [y/N] ' "$1"
    read -r answer
    case "$answer" in y|Y|yes|YES) return 0 ;; *) die "aborted" ;; esac
}

svc() { # svc enable|start|restart|stop|disable NAME
    action=$1; name=$2
    case "$INIT" in
        systemd)
            case "$action" in
                enable) systemctl enable "$name" >/dev/null 2>&1 ;;
                disable) systemctl disable "$name" >/dev/null 2>&1 || true ;;
                stop) systemctl stop "$name" >/dev/null 2>&1 || true ;;
                *) systemctl "$action" "$name" ;;
            esac ;;
        openrc)
            case "$action" in
                enable) rc-update add "$name" default >/dev/null ;;
                disable) rc-update del "$name" default >/dev/null 2>&1 || true ;;
                stop) rc-service "$name" stop >/dev/null 2>&1 || true ;;
                *) rc-service "$name" "$action" ;;
            esac ;;
        *) : ;;
    esac
}

# --------------------------------------------------------------- uninstall

if [ "$UNINSTALL" -eq 1 ]; then
    step "Uninstalling Keepword"
    if [ "$PURGE" -eq 1 ]; then
        confirm "This deletes $DATA_DIR, including the witness key and its log. Continue?"
    fi
    for s in keepword-notary keepword keepword-asn-update.timer; do
        svc stop "$s"; svc disable "$s"
    done
    rm -f /etc/systemd/system/keepword.service /etc/systemd/system/keepword-notary.service \
        /etc/systemd/system/keepword-asn-update.service /etc/systemd/system/keepword-asn-update.timer \
        /etc/init.d/keepword /etc/init.d/keepword-notary /etc/periodic/weekly/keepword-asn-update \
        /etc/cron.weekly/keepword-asn-update
    [ "$LIVE_INIT" -eq 0 ] || [ "$INIT" != "systemd" ] || systemctl daemon-reload
    rm -f "$BIN/keepword" "$BIN/keepword-tlsn" /etc/keepword/data-dir
    rmdir /etc/keepword 2>/dev/null || true
    rm -rf "$LIBEXEC"
    if [ -f /etc/caddy/keepword.caddy ]; then
        rm -f /etc/caddy/keepword.caddy
        sed -i '/^import \/etc\/caddy\/keepword.caddy$/d' /etc/caddy/Caddyfile 2>/dev/null || true
        svc reload caddy 2>/dev/null || true
    fi
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$DATA_DIR" "$OPT_DIR" /var/log/keepword
        if id "$SVC_USER" >/dev/null 2>&1; then
            # Anything still running as the user (started by hand) would
            # block its removal.
            pkill -u "$SVC_USER" 2>/dev/null && sleep 2
            userdel "$SVC_USER" >/dev/null 2>&1 || deluser "$SVC_USER" >/dev/null 2>&1 || true
        fi
        if id "$SVC_USER" >/dev/null 2>&1; then
            warn "could not remove the $SVC_USER user; remove it with: userdel $SVC_USER"
            info "removed data and build files"
        else
            info "removed data, build files and the $SVC_USER user"
        fi
    else
        info "kept $DATA_DIR (the witness key and log); use --purge to delete it"
    fi
    exit 0
fi

UPGRADE=0
[ ! -f "$DATA_DIR/keepword.toml" ] || UPGRADE=1

step "Keepword installer"
info "system:   $DISTRO, packages via ${PKG:-none}, services via $INIT"
info "data:     $DATA_DIR$( [ "$UPGRADE" -eq 1 ] && printf ' (existing node: upgrade in place)')"
info "binaries: $BIN"
[ -z "$ENDPOINT" ] || info "endpoint: $ENDPOINT"
[ "$RENDER" -eq 0 ] || info "extras:   headless rendering (Chromium)"
[ "$NOTARY" -eq 0 ] || info "extras:   TLSNotary notary on $NOTARY_ADDR"
[ "$CADDY" -eq 0 ] || info "extras:   Caddy reverse proxy for $DOMAIN"
confirm "Proceed?"

# ---------------------------------------------------------------- packages

step "Installing system packages"
[ "$PACKAGES" -eq 1 ] || PKG="skip"
case "$PKG" in
    apt-get)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        pkgs="ca-certificates curl git gcc g++ make pkg-config gzip util-linux"
        if [ "$RENDER" -eq 1 ]; then
            if [ "$DISTRO" = "ubuntu" ]; then
                warn "Ubuntu ships Chromium only as a snap, which services can't use reliably;"
                warn "install Google Chrome or a Chromium .deb yourself and set capture.chrome"
            else
                pkgs="$pkgs chromium"
            fi
        fi
        [ "$CADDY" -eq 0 ] || pkgs="$pkgs caddy"
        # shellcheck disable=SC2086
        apt-get install -y -qq --no-install-recommends $pkgs >/dev/null ;;
    dnf|yum)
        pkgs="ca-certificates curl git gcc gcc-c++ make pkgconf-pkg-config gzip util-linux shadow-utils"
        [ "$RENDER" -eq 0 ] || pkgs="$pkgs chromium"
        [ "$CADDY" -eq 0 ] || pkgs="$pkgs caddy"
        # shellcheck disable=SC2086
        "$PKG" install -y -q $pkgs ;;
    pacman)
        pkgs="ca-certificates curl git gcc make pkgconf gzip util-linux"
        [ "$RENDER" -eq 0 ] || pkgs="$pkgs chromium"
        [ "$CADDY" -eq 0 ] || pkgs="$pkgs caddy"
        # shellcheck disable=SC2086
        # Arch only supports full upgrades; -Sy alone can break the system.
        pacman -Syu --noconfirm --needed $pkgs >/dev/null ;;
    zypper)
        pkgs="ca-certificates curl git gcc gcc-c++ make pkg-config gzip util-linux shadow"
        [ "$RENDER" -eq 0 ] || pkgs="$pkgs chromium"
        [ "$CADDY" -eq 0 ] || pkgs="$pkgs caddy"
        # shellcheck disable=SC2086
        zypper --non-interactive install --no-recommends $pkgs >/dev/null ;;
    apk)
        pkgs="ca-certificates curl git build-base pkgconf gzip su-exec shadow"
        [ "$RENDER" -eq 0 ] || pkgs="$pkgs chromium"
        [ "$CADDY" -eq 0 ] || pkgs="$pkgs caddy"
        # shellcheck disable=SC2086
        apk add --no-cache -q $pkgs ;;
    skip)
        info "skipped (--no-packages)" ;;
    *)
        warn "unknown package manager; make sure a C compiler, git and curl are installed" ;;
esac
[ "$PKG" = "skip" ] || info "done"

# ---------------------------------------------------------------- toolchain

version_ge() { # version_ge 1.94.1 1.85 -> true
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

rust_target() {
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) die "no Rust toolchain for CPU $(uname -m)" ;;
    esac
    libc=gnu
    if [ -f /etc/alpine-release ] || ldd --version 2>&1 | grep -qi musl; then libc=musl; fi
    printf '%s-unknown-linux-%s' "$arch" "$libc"
}

step "Preparing the Rust toolchain"
need_rust=$MIN_RUST
[ "$NOTARY" -eq 0 ] || need_rust=$NOTARY_MIN_RUST
CARGO=""
if command -v cargo >/dev/null 2>&1; then
    have=$(rustc --version 2>/dev/null | awk '{print $2}')
    if [ -n "$have" ] && version_ge "$have" "$need_rust"; then
        CARGO=$(command -v cargo)
        info "using system Rust $have"
    fi
fi
if [ -z "$CARGO" ]; then
    export RUSTUP_HOME="$OPT_DIR/rustup" CARGO_HOME="$OPT_DIR/cargo"
    if [ -x "$CARGO_HOME/bin/rustup" ]; then
        "$CARGO_HOME/bin/rustup" update stable --no-self-update >/dev/null 2>&1 || true
    else
        target=$(rust_target)
        info "installing Rust ($target) into $OPT_DIR (not on anyone's PATH)"
        mkdir -p "$OPT_DIR"
        tmp=$(mktemp -d)
        base="https://static.rust-lang.org/rustup/dist/$target"
        curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/rustup-init" "$base/rustup-init"
        want=$(curl --proto '=https' --tlsv1.2 -fsSL "$base/rustup-init.sha256" | awk '{print $1}')
        got=$(sha256sum "$tmp/rustup-init" | awk '{print $1}')
        if [ -z "$want" ] || [ "$want" != "$got" ]; then die "rustup-init checksum mismatch"; fi
        chmod +x "$tmp/rustup-init"
        "$tmp/rustup-init" -y -q --profile minimal --default-toolchain stable --no-modify-path >/dev/null
        rm -rf "$tmp"
    fi
    CARGO="$CARGO_HOME/bin/cargo"
    have=$("$CARGO_HOME/bin/rustc" --version | awk '{print $2}')
    version_ge "$have" "$need_rust" || die "Rust $have is older than the required $need_rust"
    info "using Rust $have"
fi

# ------------------------------------------------------------------ source

step "Getting the source"
if [ -z "$SOURCE" ]; then
    here=""
    if cd "$(dirname "$0")" 2>/dev/null; then here=$(pwd); cd - >/dev/null; fi
    if [ -n "$here" ] && [ -f "$here/../crates/keepword-node/Cargo.toml" ]; then
        SOURCE=$(cd "$here/.." && pwd)
    fi
fi
if [ -n "$SOURCE" ]; then
    [ -f "$SOURCE/crates/keepword-node/Cargo.toml" ] || die "$SOURCE is not a Keepword checkout"
    SOURCE=$(cd "$SOURCE" && pwd)
    info "building from $SOURCE"
else
    SOURCE="$OPT_DIR/src"
    if [ -d "$SOURCE/.git" ]; then
        git -C "$SOURCE" fetch -q --depth 1 origin "$REPO_REF"
        git -C "$SOURCE" checkout -q --force FETCH_HEAD
    else
        mkdir -p "$OPT_DIR"
        git clone -q --depth 1 --branch "$REPO_REF" "$REPO_URL" "$SOURCE"
    fi
    info "$REPO_URL @ $REPO_REF ($(git -C "$SOURCE" rev-parse --short HEAD))"
fi

# ------------------------------------------------------------------- build

step "Building (this takes a few minutes the first time)"
export CARGO_TARGET_DIR="$OPT_DIR/target"
mkdir -p "$CARGO_TARGET_DIR"
features=""
[ "$RENDER" -eq 0 ] || features="--features render"
# shellcheck disable=SC2086
(cd "$SOURCE" && "$CARGO" build --release --locked -q -p keepword-node $features)
install -d "$BIN"
install -m 0755 "$CARGO_TARGET_DIR/release/keepword" "$BIN/keepword.new"
mv -f "$BIN/keepword.new" "$BIN/keepword"
info "installed $BIN/keepword ($("$BIN/keepword" --version))"
if [ "$NOTARY" -eq 1 ]; then
    (cd "$SOURCE/crates/keepword-tlsn" && CARGO_TARGET_DIR="$OPT_DIR/target-tlsn" "$CARGO" build --release --locked -q)
    install -m 0755 "$OPT_DIR/target-tlsn/release/keepword-tlsn" "$BIN/keepword-tlsn.new"
    mv -f "$BIN/keepword-tlsn.new" "$BIN/keepword-tlsn"
    info "installed $BIN/keepword-tlsn"
fi

# -------------------------------------------------------------- user, data

step "Setting up the $SVC_USER user and $DATA_DIR"
if ! id "$SVC_USER" >/dev/null 2>&1; then
    nologin=$(command -v nologin || printf '/sbin/nologin')
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home \
            --shell "$nologin" --comment "Keepword node" "$SVC_USER"
    else
        addgroup -S "$SVC_USER"
        adduser -S -D -H -h "$DATA_DIR" -s "$nologin" -G "$SVC_USER" -g "Keepword node" "$SVC_USER"
    fi
    info "created system user $SVC_USER"
fi
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
# The CLI finds /var/lib/keepword by itself; anywhere else is recorded here.
if [ "$DATA_DIR" = /var/lib/keepword ]; then
    rm -f /etc/keepword/data-dir
    rmdir /etc/keepword 2>/dev/null || true
else
    install -d /etc/keepword
    printf '%s\n' "$DATA_DIR" >/etc/keepword/data-dir
fi

# Helper for refreshing the IP-to-ASN table, used now and by the timer.
install -d "$LIBEXEC"
cat >"$LIBEXEC/update-asn-db" <<EOF
#!/bin/sh
# Refresh the IP-to-ASN table (iptoasn.com, public domain data).
set -eu
dir=\${1:-$DATA_DIR}
tmp=\$(mktemp "\$dir/.ip2asn.XXXXXX")
trap 'rm -f "\$tmp"' EXIT
curl -fsSL --retry 3 "$ASN_DB_URL" | gzip -dc >"\$tmp"
# Sanity check: a real table has hundreds of thousands of ranges.
[ "\$(wc -l <"\$tmp")" -gt 100000 ] || { echo "downloaded ASN table looks truncated" >&2; exit 1; }
chmod 0640 "\$tmp"
mv -f "\$tmp" "\$dir/ip2asn-combined.tsv"
trap - EXIT
EOF
chmod 0755 "$LIBEXEC/update-asn-db"

if [ "$UPGRADE" -eq 0 ]; then
    set -- --retain "${RETAIN:-full}"
    [ -z "$ASN" ] || set -- "$@" --asn "$ASN"
    [ -z "$COUNTRY" ] || set -- "$@" --country "$COUNTRY"
    keepword init "$@" | sed 's/^/    /'
else
    info "keeping the existing node and key ($(keepword id | head -n1))"
    [ -z "$RETAIN" ] || keepword config set content.retain "$RETAIN"
    [ -z "$ASN" ] || keepword config set vantage.asn "$ASN"
    [ -z "$COUNTRY" ] || keepword config set vantage.country "$COUNTRY"
fi

# --------------------------------------------------------------- ASN table

if [ "$ASN_DB" -eq 1 ]; then
    step "Fetching the IP-to-ASN table"
    if as_keepword "$LIBEXEC/update-asn-db" "$DATA_DIR"; then
        keepword config set quorum.asn_db "$DATA_DIR/ip2asn-combined.tsv"
        info "$(wc -l <"$DATA_DIR/ip2asn-combined.tsv") ranges; refreshed weekly"
    else
        warn "could not download $ASN_DB_URL; verdicts stay 'insufficient' until"
        warn "you run: $LIBEXEC/update-asn-db && keepword config set quorum.asn_db $DATA_DIR/ip2asn-combined.tsv"
    fi
fi

if [ "$DETECT" -eq 1 ] && [ -z "$ASN" ] && [ -z "$(keepword config get vantage.asn)" ] \
    && [ -f "$DATA_DIR/ip2asn-combined.tsv" ]; then
    step "Detecting this node's network"
    ip=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    if [ -n "$ip" ] && found=$(keepword net lookup "$ip" 2>/dev/null); then
        det_asn=${found% *}; det_cc=${found#* }
        keepword config set vantage.asn "$det_asn"
        case "$det_cc" in [A-Z][A-Z]) keepword config set vantage.country "$det_cc" ;; esac
        info "public IP $ip is in AS$det_asn ($det_cc)"
    else
        warn "could not detect the ASN; set it with: keepword config set vantage.asn N"
    fi
fi

# ---------------------------------------------------------------- network

step "Configuring the network"
if [ -n "$ENDPOINT" ]; then
    keepword config set network.endpoint "$ENDPOINT"
    info "advertising $ENDPOINT"
fi
if [ -n "$DOMAIN" ]; then
    # Behind our own reverse proxy the client address arrives in
    # X-Forwarded-For; observation receipts depend on it being right.
    keepword config set network.trust_forwarded_for true
fi
if [ -n "$PEERS" ]; then
    list=""
    for p in $PEERS; do list="$list${list:+, }\"$p\""; done
    keepword config set network.peers "[$list]"
    info "bootstrap peers:$PEERS"
fi
if [ "$SEEDS" -eq 0 ]; then
    keepword config set network.seeds false
    info "not joining through the default seeds"
fi
if [ -z "$(keepword config get network.endpoint)" ]; then
    if [ -n "$PUBLIC_API" ]; then
        warn "the API listens on $PUBLIC_API, but no endpoint is advertised, so peers"
        warn "can't mirror this node and it is never assigned requests. Re-run with"
        warn "  --endpoint https://your.domain:${PUBLIC_API##*:}   (public network)"
        warn "  --endpoint http://this-node-ip:${PUBLIC_API##*:}   (private test network)"
    elif [ -z "$PEERS" ] && [ "$UPGRADE" -eq 0 ]; then
        info "standalone node (no endpoint or peers); join a network later with"
        info "  keepword config set network.endpoint https://your.domain"
        info "  keepword config set network.peers '[\"https://a.peer.example\"]'"
    fi
fi
if [ "$RENDER" -eq 1 ]; then
    for c in chromium chromium-browser google-chrome; do
        if path=$(command -v "$c" 2>/dev/null); then
            keepword config set capture.chrome "$path"
            info "headless capture uses $path"
            break
        fi
    done
fi

# ---------------------------------------------------------------- services

serve_args="serve --addr $UI_ADDR --api-addr $API_ADDR --watch --anchor"

write_systemd() {
    # V8 needs writable+executable memory; keep that protection unless the
    # headless browser is in use.
    mdwe="MemoryDenyWriteExecute=yes"
    [ "$RENDER" -eq 0 ] || mdwe="# MemoryDenyWriteExecute is off: Chromium's JIT needs it"
    hardening="NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
UMask=0027"

    cat >/etc/systemd/system/keepword.service <<EOF
[Unit]
Description=Keepword node
Documentation=https://github.com/aelthorim/keepword
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
Environment=KEEPWORD_DIR=$DATA_DIR
Environment=HOME=$DATA_DIR
ExecStart=$BIN/keepword $serve_args
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
$mdwe
$hardening

[Install]
WantedBy=multi-user.target
EOF

    cat >/etc/systemd/system/keepword-asn-update.service <<EOF
[Unit]
Description=Refresh the Keepword IP-to-ASN table
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$SVC_USER
Group=$SVC_USER
ExecStart=$LIBEXEC/update-asn-db $DATA_DIR
# The node loads the table at start-up.
ExecStartPost=+/bin/systemctl try-restart keepword.service
MemoryDenyWriteExecute=yes
$hardening
EOF

    cat >/etc/systemd/system/keepword-asn-update.timer <<'EOF'
[Unit]
Description=Weekly refresh of the Keepword IP-to-ASN table

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    if [ "$NOTARY" -eq 1 ]; then
        cat >/etc/systemd/system/keepword-notary.service <<EOF
[Unit]
Description=Keepword TLSNotary notary
After=network-online.target keepword.service
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
Environment=KEEPWORD_DIR=$DATA_DIR
Environment=HOME=$DATA_DIR
ExecStart=$BIN/keepword-tlsn serve --addr $NOTARY_ADDR
Restart=on-failure
RestartSec=5
MemoryDenyWriteExecute=yes
$hardening

[Install]
WantedBy=multi-user.target
EOF
    fi
    [ "$LIVE_INIT" -eq 0 ] || systemctl daemon-reload
}

write_openrc() {
    install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" /var/log/keepword
    cat >/etc/init.d/keepword <<EOF
#!/sbin/openrc-run
name="keepword"
description="Keepword node"
command="$BIN/keepword"
command_args="$serve_args"
command_user="$SVC_USER:$SVC_USER"
supervisor="supervise-daemon"
respawn_delay=5
output_log="/var/log/keepword/keepword.log"
error_log="/var/log/keepword/keepword.log"
export KEEPWORD_DIR="$DATA_DIR"
export HOME="$DATA_DIR"

depend() {
    need net
}
EOF
    chmod 0755 /etc/init.d/keepword
    if [ "$NOTARY" -eq 1 ]; then
        cat >/etc/init.d/keepword-notary <<EOF
#!/sbin/openrc-run
name="keepword-notary"
description="Keepword TLSNotary notary"
command="$BIN/keepword-tlsn"
command_args="serve --addr $NOTARY_ADDR"
command_user="$SVC_USER:$SVC_USER"
supervisor="supervise-daemon"
output_log="/var/log/keepword/notary.log"
error_log="/var/log/keepword/notary.log"
export KEEPWORD_DIR="$DATA_DIR"
export HOME="$DATA_DIR"

depend() {
    need net
    after keepword
}
EOF
        chmod 0755 /etc/init.d/keepword-notary
    fi
    cron_dir=/etc/periodic/weekly
    [ -d "$cron_dir" ] || cron_dir=/etc/cron.weekly
    install -d "$cron_dir"
    cat >"$cron_dir/keepword-asn-update" <<EOF
#!/bin/sh
su-exec $SVC_USER $LIBEXEC/update-asn-db $DATA_DIR && rc-service keepword restart >/dev/null
EOF
    chmod 0755 "$cron_dir/keepword-asn-update"
}

step "Installing services ($INIT)"
case "$INIT" in
    systemd)
        write_systemd
        svc enable keepword.service
        [ "$ASN_DB" -eq 0 ] || svc enable keepword-asn-update.timer
        [ "$NOTARY" -eq 0 ] || svc enable keepword-notary.service
        info "keepword.service$( [ "$NOTARY" -eq 1 ] && printf ', keepword-notary.service'), keepword-asn-update.timer" ;;
    openrc)
        write_openrc
        svc enable keepword
        [ "$NOTARY" -eq 0 ] || svc enable keepword-notary
        info "/etc/init.d/keepword$( [ "$NOTARY" -eq 1 ] && printf ', /etc/init.d/keepword-notary')" ;;
    *)
        warn "no systemd or OpenRC found; start the node yourself, e.g.:"
        warn "  KEEPWORD_DIR=$DATA_DIR $BIN/keepword $serve_args" ;;
esac

# ------------------------------------------------------------ reverse proxy

if [ "$CADDY" -eq 1 ]; then
    step "Configuring Caddy for $DOMAIN"
    cat >/etc/caddy/keepword.caddy <<EOF
# Managed by the Keepword installer. Only the peer API is public; the web UI
# stays on $UI_ADDR.
$DOMAIN {
	encode zstd gzip
	handle /v1/* {
		reverse_proxy $API_ADDR
	}
	handle {
		respond "Keepword node: see /v1/descriptor" 404
	}
}
EOF
    grep -qx 'import /etc/caddy/keepword.caddy' /etc/caddy/Caddyfile 2>/dev/null \
        || printf '\nimport /etc/caddy/keepword.caddy\n' >>/etc/caddy/Caddyfile
    if [ "$START" -eq 1 ]; then
        svc enable caddy
        svc restart caddy
    fi
    info "https://$DOMAIN/v1/ → $API_ADDR (TLS certificate via Let's Encrypt)"
elif [ -n "$DOMAIN" ]; then
    step "Reverse proxy"
    info "point your proxy for https://$DOMAIN/v1/ at http://$API_ADDR, passing"
    info "X-Forwarded-For (examples in docs/INSTALL.md), or re-run with --caddy"
fi

# ------------------------------------------------------------------- start

if [ "$START" -eq 1 ] && [ "$INIT" != "none" ]; then
    step "Starting"
    svc restart keepword
    [ "$ASN_DB" -eq 0 ] || [ "$INIT" != "systemd" ] || svc start keepword-asn-update.timer
    [ "$NOTARY" -eq 0 ] || svc restart keepword-notary
    api_host=$API_ADDR
    case "$api_host" in 0.0.0.0:*) api_host="127.0.0.1:${api_host#*:}" ;; esac
    tries=0
    until curl -fsS "http://$api_host/v1/descriptor" >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then
            warn "the node did not answer on http://$api_host/v1/descriptor;"
            case "$INIT" in
                systemd) warn "check: journalctl -u keepword -n 50" ;;
                openrc) warn "check: /var/log/keepword/keepword.log" ;;
            esac
            break
        fi
        sleep 1
    done
    [ "$tries" -ge 30 ] || info "node is up: http://$api_host/v1/descriptor"
fi

# ----------------------------------------------------------------- summary

key=$(keepword id | awk '/witness key/ {print $3}')
step "Keepword is installed"
cat <<EOF
    witness key   $key
    data          $DATA_DIR (back up witness.key: it is this witness's identity)
    web UI        http://$UI_ADDR/  (local only; use an SSH tunnel to view it)
    peer API      http://$API_ADDR/v1/$( [ -n "$ENDPOINT" ] && printf '  →  %s/v1/' "$ENDPOINT")
EOF
[ "$NOTARY" -eq 0 ] || printf '    notary        %s (TCP; open it in your firewall)\n' "$NOTARY_ADDR"
cat <<EOF

    Next steps:
      keepword net status          (lists anything keeping this node out of the network)
      keepword watch add https://example.org/terms --every 6h
      keepword config show
    Starting or joining a network: docs/NETWORK.md
    ${DIM}(run keepword commands as root or with sudo; they switch to the $SVC_USER user by themselves)${RESET}
EOF
