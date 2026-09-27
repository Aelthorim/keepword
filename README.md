# Witness

Independent, verifiable records of what a web page said, and when.

A Witness node fetches a URL, reduces it to its meaningful content, signs a
statement about what it saw, and appends that statement to a
Certificate-Transparency-style Merkle log. It keeps watching, and when the
page changes it tells you what changed and whether the publisher said so.
Every record can be exported as a self-contained **evidence bundle** that
anyone can verify offline, without trusting the node.

The goal is a network of independent witnesses that makes three things
expensive: publishers quietly rewriting pages, publishers showing witnesses
something different from what users see, and witnesses lying. Milestones
M0 and M1 are done. Single-node operation, watchlists, edit detection and
the web UI all work. The network layer is designed but not built yet; see
[docs/DESIGN.md](docs/DESIGN.md).

## Quick start

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
| `serve [--addr A] [--watch]` | Read-only web UI, optionally with the scheduler |

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

## Headless rendering

For pages that only exist after JavaScript runs:

```sh
cargo build --release --features render
witness capture --render https://example.org/app
```

This needs Chrome or Chromium; set `capture.chrome` if it isn't on `PATH`.
The browser resolves hosts itself, so the private-address guard doesn't
cover rendered sub-resources. Only render URLs you chose.

## Layout

```
crates/witness-core       protocol: encoding, attestations, Merkle log, bundles, assignment, quorum
crates/witness-normalize  canonicalizer, site rules, diff and silent-edit classifier
crates/witness-capture    HTTP capture, SSRF guard, headless render, WARC export
crates/witness-store      blob store, SQLite index, log, watchlist
crates/witness-node       the `witness` binary and web UI
docs/DESIGN.md            threat model, formats, network design, roadmap
```

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

The end-to-end test (`crates/witness-node/tests/e2e.rs`) runs a local HTTP
server through the whole lifecycle: capture, noise that must *not* count as
a change, a silent edit, a disclosed edit, bundle verification, tampering,
redirects, audit and erasure.

## License

Not yet chosen.
