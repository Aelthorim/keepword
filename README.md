# Witness

Independent, verifiable records of what a web page said, and when.

A Witness node fetches a URL, reduces it to its meaningful content, signs a
statement about what it saw, and appends that statement to a
Certificate-Transparency-style Merkle log. It keeps watching, and when the
page changes it tells you what changed and whether the publisher said so.
Every record can be exported as a self-contained **evidence bundle** that
anyone can verify offline, without trusting the node.

Witnesses federate: they mirror and cosign each other's logs, take on
watch requests assigned by public randomness, corroborate each other's
network location, and compare what they saw. When independent networks see
different content at the same moment, the network raises a cloaking alert.
Captures carry a drand beacon, which proves they happened *after* a point
in time. Logs are anchored in Bitcoin through OpenTimestamps, which proves
the captures existed *before* a later point.

The design, threat model and formats are in [docs/DESIGN.md](docs/DESIGN.md).

## Install

On a server (Debian, Ubuntu, Fedora, RHEL-likes, Arch, openSUSE, Alpine):

```sh
git clone https://github.com/aelthorim/witness.git && cd witness
sudo sh scripts/install.sh --domain witness.example.org --caddy
```

This builds Witness, creates a sandboxed `witness` service with its own user,
fetches the IP-to-ASN table and refreshes it weekly, detects the node's
network, and puts the peer API behind Caddy with automatic TLS. Re-run it to
upgrade. There is also a container image (`Dockerfile`,
`packaging/docker/compose.yaml`). Both are described in
[docs/INSTALL.md](docs/INSTALL.md). To start a network or join one, see
[docs/NETWORK.md](docs/NETWORK.md).

## Quick start (from source)

```sh
cargo build --release
alias witness=./target/release/witness

witness init --asn 3320 --country DE        # creates ./witness-data
witness capture https://example.org/privacy
witness watch add https://example.org/privacy --every 6h
witness serve --watch                        # web UI on http://127.0.0.1:8480
```

When the page changes:

```
$ witness capture https://example.org/privacy
attestation 7c1e…
  ...
CHANGED since 3f2a90c1b7d4: silent edit: +1 -1 lines

--- before
+++ after
@@ -3,4 +3,4 @@
 h1: Privacy policy
-p: We never sell your data.
+p: We may share your data with partners.
```

Proving it to someone else:

```sh
witness export https://example.org/privacy --at 2026-05-01 -o evidence.json
# they run, with no node and no network:
witness verify --bundle evidence.json
```

```
  [ok  ] signature      signed by witness 7b757b5c…
  [ok  ] tree head      size 1204 root 3fc10f581373
  [ok  ] log inclusion  leaf 1187 of 1204
  [ok  ] headers        467 bytes, hash 13d3817dd54e
  [ok  ] body           41233 bytes, hash 4b768329a126
  [ok  ] normalized     matches 61a162ac8062
  [ok  ] renormalize    body normalizes to the attested norm hash

VERIFIED
```

## Commands

| Command | What it does |
|---|---|
| `init [--asn N] [--country CC] [--retain full\|normalized\|none]` | Create key, config and empty log |
| `id` | Show witness key and log head |
| `capture URL [--render]` | Fetch now, attest, log, compare with the previous capture |
| `verify URL\|ID [--at TIME]` / `verify --bundle FILE` | Run every check on a stored capture or a bundle |
| `export URL\|ID [--at TIME] [--no-content] [-o FILE]` | Write an evidence bundle |
| `warc URL\|ID -o FILE` | Rebuild a WARC 1.1 file for a capture |
| `history URL` | All captures and detected changes |
| `diff URL` / `diff ID ID` | Diff the last two versions, or two captures |
| `watch add\|rm\|list\|run [--once]` | Manage and run the watchlist |
| `log head\|consistency OLD [NEW]\|audit` | Tree head, consistency proofs, full self-audit |
| `purge URL [--forget]` | Erase stored content (and records); the log stays valid |
| `serve [--addr A] [--api-addr B] [--watch] [--anchor]` | Web UI (private), peer API (public), scheduler, federation and anchoring loops |
| `net add-peer URL\|remove-peer KEY\|peers\|sync\|status\|lookup IP` | Federation with other witnesses; `status` warns about misconfiguration |
| `request URL [--every 1h] [--for 7days]` / `request URL --cancel` | Ask the network to watch a URL (asking again replaces the request), or withdraw it |
| `requests [--mine]` | Active network watch requests |
| `verdict URL` | What independent witnesses agree the URL served |
| `alerts` | Split, silent-edit and equivocation alerts |
| `anchor submit\|upgrade\|list\|export` | Bitcoin anchoring via OpenTimestamps |
| `beacon [ROUND]` | Fetch and verify a drand beacon |
| `config show\|get\|set\|unset` | Read or change `witness.toml`, with validation |

`--at` takes RFC 3339 or `YYYY-MM-DD` (end of that day, UTC). IDs can be
abbreviated. `--json` gives machine-readable output.

## Configuration

`witness-data/witness.toml`; see [docs/witness.example.toml](docs/witness.example.toml).
The important settings:

- `content.retain`: what to keep. `full`, `normalized` (diffs without raw
  bytes) or `none` (hashes only). Attestations and the log never contain
  page content.
- `[[rules]]`: per-site normalization (extra elements to drop, content
  root). Rules are part of the normalizer profile each attestation commits
  to.
- `capture.use_system_proxy`: off by default. A proxy changes your vantage
  point, and a TLS-intercepting one hides the server's certificate.

## Running in a network

```sh
witness init --asn 3320 --country DE
# in witness-data/witness.toml:
#   [network]  endpoint = "https://witness.example.org"   peers = ["https://other.example"]
#   [quorum]   asn_db = "/var/lib/witness/ip2asn-combined.tsv"   (from iptoasn.com)
witness serve --api-addr 0.0.0.0:8481 --watch --anchor
```

Put the API (`/v1/...`) behind TLS on your public endpoint. Keep the web UI
(`--addr`, default `127.0.0.1:8480`) private, because it shows page content.
Peers corroborate each other's location from the addresses they see pushes
come from. Verdicts only count witnesses whose ASN is corroborated this
way, so every node needs an IP-to-ASN table.

## TLSNotary proof tier

For high-value pages, a second witness can notarize the TLS session itself
(MPC-TLS via [TLSNotary](https://tlsnotary.org)). Then even the capturing
witness couldn't have made the content up on its own:

```sh
cd crates/witness-tlsn          # separate workspace, Rust 1.95+
cargo build --release
witness-tlsn serve --addr 0.0.0.0:8482                    # on the notary
witness-tlsn capture https://example.org/terms --verifier notary.example.net:8482 --verifier-key <hex>
```

Bundles then carry the notary's receipt and the transcript, and
`witness verify` checks both.

## Headless rendering

For pages that only exist after JavaScript runs:

```sh
cargo build --release --features render
witness capture --render https://example.org/app
```

This needs Chrome or Chromium; set `capture.chrome` if it isn't on `PATH`.
The browser resolves hosts itself, so the private-address guard only covers
the page's own address, not its sub-resources. Only render URLs you chose;
network requests are rendered only with `network.render_requests`.

## Layout

```
crates/witness-core       protocol: encoding, attestations, Merkle log, bundles, assignment, quorum
crates/witness-normalize  canonicalizer, site rules, diff and silent-edit classifier
crates/witness-capture    HTTP capture, SSRF guard, headless render, WARC export
crates/witness-store      blob store, SQLite index, log, watchlist
crates/witness-node       the `witness` binary: CLI, peer API, federation, web UI
crates/witness-tlsn       TLSNotary proof tier (separate workspace)
docs/DESIGN.md            threat model, formats, network design, roadmap
docs/INSTALL.md           production installation (installer, container)
docs/NETWORK.md           starting or joining a public witness network
scripts/install.sh        the installer
packaging/docker/         container entrypoint and compose file
```

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Integration tests run everything over real HTTP on localhost:

- `e2e.rs`: the single-node lifecycle (capture, noise, silent and disclosed
  edits, bundles, tampering, redirects, audit, erasure)
- `network.rs`: four witnesses in four ASNs (discovery, log mirroring,
  cosigning, observation receipts, assigned watch requests, replacing and
  withdrawing them, dropping gossip from strangers, a cloaking server
  producing a split verdict and alert, equivocation detection)
- `anchoring.rs`: drand beacons and Bitcoin anchoring against mock drand,
  OpenTimestamps and Esplora services
- `witness-normalize/tests/corpus.rs`: the normalizer regression corpus
- `witness-tlsn/tests/notary.rs`: a full MPC-TLS notarization between two
  witnesses against TLSNotary's test server

## License

Not yet chosen.
