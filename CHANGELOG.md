# Changelog

All notable changes to Witness. Versions follow [Semantic Versioning](https://semver.org):
from 1.0.0 on, the evidence formats (attestations, logs, bundles) and the
network protocol only change incompatibly in a new major version.

## [1.0.0] - 2026-09-28

The first stable release: a working network of independent witnesses that
record web pages, seal what they saw, catch silent edits and cloaking, and
produce evidence anyone can verify offline.

### Capturing and evidence

- Capture pages over HTTP, or in headless Chromium with `--features render`,
  behind a guard that refuses private and loopback addresses.
- A normalizer that strips ads, cookie banners, trackers, clocks and "posted
  5 minutes ago" noise, with per-site rules and a regression corpus.
- Signed attestations in an append-only, Certificate-Transparency-style
  Merkle log, with inclusion and consistency proofs and a full self-audit.
- Change detection with diffs, and silent-edit detection: a change the page
  doesn't disclose raises an alert.
- Self-contained evidence bundles that `witness verify --bundle` checks
  offline: signature, log inclusion, cosignatures, time bounds, content.
- Time bounds: a drand beacon proves a capture happened after a moment,
  Bitcoin anchoring through OpenTimestamps proves it existed by a later one.
- Retention levels (`full`, `normalized`, `none`), erasure with
  `witness purge` that keeps every proof valid, and WARC export.
- A TLSNotary proof tier (`crates/witness-tlsn`): a second witness
  notarizes the TLS session, so a capture can't be fabricated alone.

### The network

- Federation over HTTPS. Gossip with a random sample of peers; every
  message is signed, and only witnesses in the peer table can send more
  than an announcement.
- Log audits: each log has 16 auditors that check its hourly checkpoints
  with consistency proofs and cosign them. A log that shows two histories
  produces cryptographic proof against itself and is excluded.
- Location corroboration: peers confirm each other's network (ASN) from
  the addresses their connections come from.
- Watch requests assigned by public randomness, at most one witness per
  network, capped per country; requests can be replaced and withdrawn.
- Verdicts that count independent networks: agreed, split (a site showing
  different people different pages) or insufficient, with split alerts.
- Default seed witnesses for joining, with an opt-out for separate
  networks; hourly pruning keeps each node's storage roughly independent
  of the network's size.

### Running it

- A production installer for Debian, Ubuntu, Fedora, RHEL-likes, Arch,
  openSUSE and Alpine, with a hardened systemd or OpenRC service, Caddy
  for automatic TLS, upgrades in place and clean uninstall.
- A container image and compose file.
- `witness net status` names anything that keeps a node out of the
  network. Run as root, `witness` switches to the service user by itself.
- A private web UI with history, diffs, verdicts, alerts and the network.
- Licensed under the GNU AGPL v3.

[1.0.0]: https://github.com/Aelthorim/witness/releases/tag/v1.0.0
