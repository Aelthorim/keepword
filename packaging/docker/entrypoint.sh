#!/bin/sh
# First start: create the node from environment variables. Every start:
# apply the network settings and keep the IP-to-ASN table fresh.
#
#   KEEPWORD_ASN, KEEPWORD_COUNTRY   where this node is (self-reported)
#   KEEPWORD_RETAIN                  full | normalized | none (first start only)
#   KEEPWORD_ENDPOINT                public URL of the peer API
#   KEEPWORD_PEERS                   comma-separated bootstrap peer URLs
#   KEEPWORD_SEEDS=0                 don't join through the default seeds
#   KEEPWORD_BEHIND_PROXY=1          trust X-Forwarded-For from your proxy
#   KEEPWORD_CLIENT_IP_HEADER        the header your proxy puts the client
#                                    address in, e.g. X-Real-IP (behind a CDN)
#   KEEPWORD_ASN_DB=0                don't download the IP-to-ASN table
set -eu

dir=${KEEPWORD_DIR:-/data}
cfg() { keepword config set "$1" "$2"; }

if [ ! -f "$dir/keepword.toml" ]; then
    init_args="--retain ${KEEPWORD_RETAIN:-full}"
    [ -z "${KEEPWORD_ASN:-}" ] || init_args="$init_args --asn $KEEPWORD_ASN"
    [ -z "${KEEPWORD_COUNTRY:-}" ] || init_args="$init_args --country $KEEPWORD_COUNTRY"
    # shellcheck disable=SC2086
    keepword init $init_args
fi

[ -z "${KEEPWORD_ENDPOINT:-}" ] || cfg network.endpoint "$KEEPWORD_ENDPOINT"
if [ -n "${KEEPWORD_PEERS:-}" ]; then
    list=$(printf '%s' "$KEEPWORD_PEERS" | awk -F, '{for (i = 1; i <= NF; i++) printf "%s\"%s\"", (i > 1 ? ", " : ""), $i}')
    cfg network.peers "[$list]"
fi
[ "${KEEPWORD_SEEDS:-1}" != "0" ] || cfg network.seeds false
[ "${KEEPWORD_BEHIND_PROXY:-0}" != "1" ] || cfg network.trust_forwarded_for true
[ -z "${KEEPWORD_CLIENT_IP_HEADER:-}" ] || cfg network.client_ip_header "$KEEPWORD_CLIENT_IP_HEADER"

if [ "${KEEPWORD_ASN_DB:-1}" = "1" ]; then
    db="$dir/ip2asn-combined.tsv"
    # Refresh when missing or older than a week.
    if [ ! -f "$db" ] || [ -n "$(find "$db" -mtime +7 2>/dev/null)" ]; then
        tmp="$db.tmp"
        if curl -fsSL --retry 3 https://iptoasn.com/data/ip2asn-combined.tsv.gz | gzip -dc >"$tmp" \
            && [ "$(wc -l <"$tmp")" -gt 100000 ]; then
            mv -f "$tmp" "$db"
        else
            rm -f "$tmp"
            echo "warning: could not refresh the IP-to-ASN table" >&2
        fi
    fi
    [ ! -f "$db" ] || cfg quorum.asn_db "$db"
fi

exec keepword "$@"
