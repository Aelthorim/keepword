# Installing Keepword

There are two supported ways to run a node in production:

- **The installer** (`scripts/install.sh`) builds Keepword from source and sets
  it up as a hardened system service. It supports Debian, Ubuntu, Fedora,
  RHEL-likes, Arch, openSUSE and Alpine, with systemd or OpenRC.
- **The container image** (`Dockerfile`) is for Docker, Podman, NAS boxes and
  Kubernetes.

## Installer

```sh
git clone https://github.com/aelthorim/keepword.git
cd keepword
sudo sh scripts/install.sh --domain witness.example.org --caddy
```

That single command:

1. installs build dependencies with the system package manager (and Caddy
   when you pass `--caddy`). On Arch this is a full `pacman -Syu`, because
   Arch doesn't support partial upgrades; use `--no-packages` to manage
   packages yourself;
2. installs Rust into `/opt/keepword` if the system Rust is missing or too
   old, verifying the `rustup-init` checksum;
3. builds `keepword` in release mode and installs it to `/usr/local/bin`;
4. creates a `keepword` system user and `/var/lib/keepword` (mode 0750);
5. creates the node: key, config and empty log;
6. downloads the IP-to-ASN table from iptoasn.com and schedules a weekly
   refresh;
7. detects the node's ASN and country from its public IP, unless you pass
   `--asn`/`--country` or `--no-detect`;
8. configures the endpoint, peers and reverse-proxy trust;
9. installs and starts a sandboxed service, then checks that the API
   answers.

Re-running the installer **upgrades in place**: it rebuilds, reinstalls and
restarts, and never touches the key or data. Options given on the re-run are
applied to the existing configuration.

### Common setups

```sh
# A public witness behind Caddy with automatic TLS, joining two peers
sudo sh scripts/install.sh --domain witness.example.org --caddy \
    --peer https://witness.one.example --peer https://witness.two.example

# A public witness behind your own reverse proxy
sudo sh scripts/install.sh --domain witness.example.org

# The API directly on a public port (you handle TLS elsewhere)
sudo sh scripts/install.sh --public-api 0.0.0.0:8481 --endpoint https://witness.example.org:8481

# A private watchdog: no network, hashes and diffs only
sudo sh scripts/install.sh --retain normalized --no-asn-db

# Everything: headless rendering and a TLSNotary notary on :8482
sudo sh scripts/install.sh --domain witness.example.org --caddy --render --notary
```

`sh scripts/install.sh --help` lists every option. `--source DIR` builds a
local checkout. Without it, the installer builds the checkout it was run
from, or clones `--repo`/`--ref` into `/opt/keepword/src`.

### What gets installed

| Path | What |
|---|---|
| `/usr/local/bin/keepword`, `keepword-tlsn` | binaries |
| `/usr/local/lib/keepword/update-asn-db` | IP-to-ASN refresh script |
| `/var/lib/keepword/` | key, `keepword.toml`, SQLite index, blobs, ASN table |
| `/opt/keepword/` | Rust toolchain, build cache, cloned source |
| `keepword.service` | the node: `serve --watch --anchor`, UI on 127.0.0.1:8480, API on 127.0.0.1:8481 |
| `keepword-asn-update.timer` | weekly ASN table refresh (cron on OpenRC) |
| `keepword-notary.service` | with `--notary` |
| `/etc/caddy/keepword.caddy` | with `--caddy`; imported from the Caddyfile |

The systemd units run as the unprivileged `keepword` user. Hardening:
read-only system, no home directories, no capabilities, a system-call
allow-list, no new privileges, and memory that can't be both writable and
executable (except with `--render`, because Chromium's JIT needs it).

### Day-to-day

Run `keepword` as root or with sudo. It finds the installed node by itself
and switches to the `keepword` user before touching anything, so file
ownership stays right. No alias or `KEEPWORD_DIR` is needed. As an ordinary
user it tells you to use sudo, since the data directory is private to the
service.

```sh
keepword watch add https://example.org/terms --every 6h
keepword request https://example.org/terms --every 1h --for 7days   # the network watches it
keepword request https://example.org/terms --cancel
keepword net status                     # ends with warnings about anything misconfigured
keepword config show
keepword config set network.peers '["https://witness.one.example"]'
sudo systemctl restart keepword         # after changing the config
journalctl -u keepword -f
```

The web UI shows captured content, so it only listens on localhost. View it
with an SSH tunnel: `ssh -L 8480:127.0.0.1:8480 your-server`, then open
http://localhost:8480.

To start a network or join one, see [NETWORK.md](NETWORK.md).

**Back up `/var/lib/keepword/witness.key`.** It is the witness's identity, and
the log is only verifiable against it. A new key is a new witness.

### Firewall

| Port | Open to | Why |
|---|---|---|
| 443 (and 80 for ACME) | everyone | peer API through the reverse proxy |
| 8481 | everyone, only with `--public-api` | peer API without a proxy |
| 8482 | peers, only with `--notary` | TLSNotary sessions (raw TCP) |
| 8480 | nobody | web UI, localhost only |

### Your own reverse proxy

The proxy must forward `/v1/` to `127.0.0.1:8481` and put the real client
address in `X-Forwarded-For`. The installer turns on
`network.trust_forwarded_for` when you pass `--domain`, because observation
receipts, and with them every peer's corroborated location, depend on it.
The node uses the **last** address in that header, the one your proxy
added. It only reads the header on connections from this machine or a
private network, so the proxy must run there: with the API exposed
directly, clients could otherwise claim any address.

nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name witness.example.org;
    # ssl_certificate ...; ssl_certificate_key ...;

    location /v1/ {
        proxy_pass http://127.0.0.1:8481;
        proxy_set_header X-Forwarded-For $remote_addr;   # replace, don't append
        proxy_set_header Host $host;
    }
    location / { return 404; }
}
```

### Behind Cloudflare or another CDN

Through a CDN, the address your proxy sees, and adds to `X-Forwarded-For`,
is the CDN's, and the node would place every peer in the CDN's network
(`keepword net status` warns when peers seem to connect from Cloudflare).
Have the proxy work out the client's address, as for any site behind a
CDN, and pass it on in a header it sets itself. Caddy:

```caddy
{
    servers {
        trusted_proxies cloudflare     # caddy-cloudflare-ip module; or: static <Cloudflare's ranges>
        client_ip_headers CF-Connecting-IP
    }
}

witness.example.org {
    reverse_proxy 127.0.0.1:8481 {
        header_up X-Real-IP {client_ip}
    }
}
```

With nginx, `set_real_ip_from` Cloudflare's ranges and `real_ip_header
CF-Connecting-IP`, then `proxy_set_header X-Real-IP $remote_addr`. Then
tell the node which header it is:

```sh
keepword config set network.client_ip_header X-Real-IP
sudo systemctl restart keepword
```

The proxy must set that header on every request, replacing any the client
sent (`header_up` and `proxy_set_header` do). Don't name a header the proxy
only passes on, such as `CF-Connecting-IP`: anyone reaching your server
around the CDN could write it. Peers are programs, not browsers: keep the
CDN from challenging requests to `/v1/` (Cloudflare's Bot Fight Mode,
"Under Attack" mode).

### Uninstalling

```sh
sudo sh scripts/install.sh --uninstall           # keeps /var/lib/keepword
sudo sh scripts/install.sh --uninstall --purge   # deletes the key and log too
```

## Container

```sh
docker build -t keepword .
docker run -d --name keepword --restart unless-stopped \
    -v keepword-data:/data \
    -p 127.0.0.1:8480:8480 -p 127.0.0.1:8481:8481 \
    -e KEEPWORD_ENDPOINT=https://witness.example.org \
    -e KEEPWORD_PEERS=https://witness.one.example \
    -e KEEPWORD_BEHIND_PROXY=1 \
    keepword
```

Or `docker compose -f packaging/docker/compose.yaml up -d`. Settings:

| Variable | Meaning |
|---|---|
| `KEEPWORD_ASN`, `KEEPWORD_COUNTRY` | where the node is (first start) |
| `KEEPWORD_RETAIN` | `full`, `normalized` or `none` (first start) |
| `KEEPWORD_ENDPOINT` | public URL of the peer API |
| `KEEPWORD_PEERS` | comma-separated bootstrap peers |
| `KEEPWORD_SEEDS=0` | don't join through the default seeds (a separate network, or a test) |
| `KEEPWORD_BEHIND_PROXY=1` | trust `X-Forwarded-For` from your proxy |
| `KEEPWORD_CLIENT_IP_HEADER` | the header your proxy puts the client address in, e.g. `X-Real-IP` (behind a CDN) |
| `KEEPWORD_ASN_DB=0` | skip the IP-to-ASN table (refreshed at start when older than a week) |

The `/data` volume holds the key: back it up. Run CLI commands with
`docker exec keepword keepword …`. With Docker's userland proxy, peers can
appear to connect from the gateway address. Put a TLS reverse proxy on the
host in front of port 8481 and set `KEEPWORD_BEHIND_PROXY=1`.
