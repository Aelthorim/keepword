#!/bin/sh
# First start: create the node from environment variables. Every start:
# apply the network settings and keep the IP-to-ASN table fresh.
#
#   WITNESS_ASN, WITNESS_COUNTRY   where this node is (self-reported)
#   WITNESS_RETAIN                 full | normalized | none (first start only)
#   WITNESS_ENDPOINT               public URL of the peer API
#   WITNESS_PEERS                  comma-separated bootstrap peer URLs
#   WITNESS_SEEDS=0                don't join through the default seeds
#   WITNESS_BEHIND_PROXY=1         trust X-Forwarded-For from your proxy
#   WITNESS_CLIENT_IP_HEADER       the header your proxy puts the client
#                                  address in, e.g. X-Real-IP (behind a CDN)
#   WITNESS_ASN_DB=0               don't download the IP-to-ASN table
set -eu

dir=${WITNESS_DIR:-/data}
cfg() { witness config set "$1" "$2"; }

if [ ! -f "$dir/witness.toml" ]; then
    init_args="--retain ${WITNESS_RETAIN:-full}"
    [ -z "${WITNESS_ASN:-}" ] || init_args="$init_args --asn $WITNESS_ASN"
    [ -z "${WITNESS_COUNTRY:-}" ] || init_args="$init_args --country $WITNESS_COUNTRY"
    # shellcheck disable=SC2086
    witness init $init_args
fi

[ -z "${WITNESS_ENDPOINT:-}" ] || cfg network.endpoint "$WITNESS_ENDPOINT"
if [ -n "${WITNESS_PEERS:-}" ]; then
    list=$(printf '%s' "$WITNESS_PEERS" | awk -F, '{for (i = 1; i <= NF; i++) printf "%s\"%s\"", (i > 1 ? ", " : ""), $i}')
    cfg network.peers "[$list]"
fi
[ "${WITNESS_SEEDS:-1}" != "0" ] || cfg network.seeds false
[ "${WITNESS_BEHIND_PROXY:-0}" != "1" ] || cfg network.trust_forwarded_for true
[ -z "${WITNESS_CLIENT_IP_HEADER:-}" ] || cfg network.client_ip_header "$WITNESS_CLIENT_IP_HEADER"

if [ "${WITNESS_ASN_DB:-1}" = "1" ]; then
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

exec witness "$@"
