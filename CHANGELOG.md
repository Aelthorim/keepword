# Changelog

All notable changes to Witness. Versions follow [Semantic Versioning](https://semver.org):
from 1.0.0 on, the evidence formats (attestations, logs, bundles) and the
network protocol only change incompatibly in a new major version.

## [Unreleased]

Security and correctness fixes for 1.1.0's location corroboration,
rechecks and fork checks. Nothing changes in the protocol or the stored
data; upgrading is recommended for every witness.

### Fixed

- **Two servers could place any number of keys in any networks.**
  Receipts counted once per observer network, but two observers on two
  real networks could sign receipts putting keys that never connected to
  a node in as many networks as they liked, and assignment, verdicts and
  recheck draws counted each. A node now places another witness only
  where it saw that witness connect itself; receipts only tell a node
  where it is itself. New witnesses count at every node once they have
  pushed to it, within about a day.
- **A forked log could hide behind its own old heads.** Auditors checked
  gossiped heads oldest first, eight per audit, so a log could sign heads
  of the history its forks share (all consistent) and gossip them ahead of
  the ones that exposed it. The biggest heads are now checked first.

## [1.1.0] - 2026-09-28

Disagreements are now settled by reproduction instead of by vote. Upgrade
every witness; 1.0.x witnesses keep working alongside 1.1.0 ones but don't
take part in rechecks.

### Added

- **Rechecks.** When the witnesses assigned to a URL disagree, the round
  is *disputed*, and witnesses drawn at random from the reporters'
  countries, one per network and none of them assigned, capture the page
  again. Only versions they reproduce count: a real regional difference is
  confirmed as a split, and a made-up one is overruled. The draw uses
  drand and a fixed slot of time, so nobody can pick or retry it. New
  verdict: `DISPUTED`, while rechecks run or when nothing could be
  confirmed. See DESIGN.md §6.5.
- **Split alerts need repeated confirmation**: 3 of the last 4 settled
  recheck rounds for the URL (`quorum.split_confirmations`,
  `quorum.split_rounds`).
- **Failed claims.** A version the rechecks could have reproduced and
  didn't counts against the network address it came from; after 5 in a
  week (`quorum.max_failed_claims`) that network is left out of verdicts.
- **Forks of different sizes are detected.** Auditors check the heads
  other auditors report for a log against the one they verified; a log
  that can't prove them consistent is excluded and alerted on.
- **Rate limit on the public API**: 600 requests a minute per address
  (`network.api_requests_per_minute`), answered with HTTP 429 beyond that.

### Changed

- Only the witnesses assigned to a URL count in its verdict.
- Log proofs, bundles and new tree heads cost O(log n) instead of a pass
  over the whole log, so large logs stay fast and the proof endpoints
  can't be used to exhaust a node.
- Verdict JSON has a `groups` list (every version compared) and a
  `rechecks` count.

### Known limitations

- A difference seen only from one country is only confirmed if that
  country has at least 3 witnesses on different networks beyond the ones
  assigned. Small networks show `DISPUTED` where 1.0 showed `SPLIT`.
- A country where one operator runs most witnesses decides what is seen
  from there, and a round whose assigned witnesses are all one operator's
  agrees on whatever they say.

## [1.0.1] - 2026-09-28

Security fixes. Upgrading is recommended for every witness; nothing
changes in the protocol or the stored data.

### Fixed

- **Sybil keys could invent networks.** Location corroboration counted
  observers by key, and keys are free: one server with 20 keys could
  vouch that each of its keys sat in a different network, and verdicts
  and assignment then counted 20 independent witnesses. A node now
  trusts where it saw a witness connect itself, and otherwise counts only
  observers it has seen connect, once per network.
- **One witness could blind a verdict.** The comparison window was
  anchored at the newest attestation, so a single attestation dated in
  the future pushed every honest one out of it. Future-dated attestations
  and ones older than their own drand beacon are now rejected, and the
  window compared is the one covering the most independent networks.
- **Extra keys could crowd out honest witnesses.** When captures used
  different methods or normalizer profiles, the class with the most keys
  was compared. It is now the class with the most networks.
- **`witness verify` claimed more than it proved.** It printed VERIFIED
  whenever no check failed, even for a bare signed attestation. It now
  grades the result (SIGNED ONLY, LOGGED, LOGGED + COSIGNED) and says in
  plain words what the bundle shows and what it doesn't, in the CLI, the
  JSON output and the web UI. Cosignatures are reported as "other keys",
  since a bundle alone can't show whose keys they are.

### Known limitations

- A log that shows different auditors histories of *different* sizes is
  not yet detected; only same-size forks are. The 1.0.0 notes overstated
  this.
- A witness that really connects from many networks (rented servers or
  proxies) still counts as many. Corroborated location shows where a
  witness connects from, not that its captures are independent.
- Reputation is informational only; it doesn't affect assignment or
  verdicts.

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

[Unreleased]: https://github.com/Aelthorim/witness/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Aelthorim/witness/releases/tag/v1.1.0
[1.0.1]: https://github.com/Aelthorim/witness/releases/tag/v1.0.1
[1.0.0]: https://github.com/Aelthorim/witness/releases/tag/v1.0.0
