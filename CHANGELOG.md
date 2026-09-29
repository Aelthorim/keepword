# Changelog

All notable changes to Witness. Versions follow [Semantic Versioning](https://semver.org):
from 1.0.0 on, the evidence formats (attestations, logs, bundles) and the
network protocol only change incompatibly in a new major version.

## [Unreleased]

### Added

- **`network.client_ip_header`: witnesses behind Cloudflare or another
  CDN.** Behind a CDN, the address a witness's reverse proxy sees is the
  CDN's. The proxy can work out the client's address and pass it on in a
  header of its own, e.g. Caddy's `header_up X-Real-IP {client_ip}`; the
  node now takes the address from that header. Container:
  `WITNESS_CLIENT_IP_HEADER`.
- `witness net status` warns when peers seem to connect from Cloudflare.
- The installer's `--no-seeds` and the container's `WITNESS_SEEDS=0` keep a
  node off the public network, for separate networks and tests.

### Fixed

- **Behind a CDN, every peer was placed in the CDN's network.** The node
  took the address its proxy added to X-Forwarded-For, which behind a CDN
  is the CDN's edge. It signed that as every peer's location (AS13335
  behind Cloudflare), told each peer it was there, and nothing warned.
- **CI runs joined the public network.** The installer and container tests
  started nodes with the default seeds, and each run left a few dead
  witnesses in the seed's peer table.
- **Behind a proxy that adds its own X-Forwarded-For line**, such as
  HAProxy, the node read the first line, which the client wrote. It now
  reads the last.
- With the API listening on `[::]`, which takes IPv4 connections too,
  every IPv4 client shared one rate-limit bucket.

## [1.1.1] - 2026-09-28

Security, correctness and stability fixes: location corroboration,
rechecks and fork checks, and what one hostile client or key can make a
witness do. Nothing changes in the protocol or the stored data; upgrading
is recommended for every witness before a network goes public.

### Fixed

- **Two servers could place any number of keys in any networks.**
  Receipts counted once per observer network, but two observers on two
  real networks could sign receipts putting keys that never connected to
  a node in as many networks as they liked, and assignment, verdicts and
  recheck draws counted each. A node now places another witness only
  where it saw that witness connect itself; receipts only tell a node
  where it is itself. New witnesses count at every node once they have
  pushed to it, within about a day.
- **Anyone could spend other witnesses' recheck captures.** A recheck
  request only had to come from a key assigned to the URL, and any key is
  assigned to some URLs (it only has to try enough of them). Drawn
  witnesses now fetch the assigned witnesses' attestations first and only
  capture when they see the round disputed themselves; skipped requests
  don't use up `quorum.max_rechecks_per_hour`.
- **Honest witnesses were charged for page edits.** A witness that
  captured a page just before its publisher edited it failed the rechecks
  made after the edit, and five of those in a week left its network out
  of verdicts. A version other networks saw too, captured before any other
  network saw the version the rechecks confirmed, now costs nothing.
- **Recheck draws were judged by the wrong round.** A draw that completed
  after a newer round had started was settled against the newer round's
  versions, so witnesses could be charged for reporting the current page.
  Each draw is now judged by the versions of the round it was drawn for,
  and settled even when that round is no longer the current one; only
  draws of rounds with the same versions add up in a verdict.
- **A forked log could hide behind its own old heads.** Auditors checked
  gossiped heads oldest first, eight per audit, so a log could sign heads
  of the history its forks share (all consistent) and gossip them ahead of
  the ones that exposed it. The biggest heads are now checked first.
- **Anyone could keep a witness's CPU busy with fake drand beacons.**
  Beacons are accepted from anyone and each check is a BLS pairing
  (about 2.5 ms): one push of 1000 garbage beacons cost 2.5 s of CPU, and
  600 pushes a minute from one address kept about 26 cores busy. A node
  now only checks beacons it can use, at most 20 at once and one every
  three seconds after that, before any signature is checked.
- **One key could fill every node's disk.** Any key gets into the peer
  table with a descriptor and could then push unlimited alerts, tree heads
  or receipts, which every node stored and forwarded. A node now takes an
  hour's worth of each kind from one key at most (10 to 200 messages), and
  2000 an hour in all from keys it has never synced with nor seen push to
  it. Alerts dated ahead, which were never pruned, are refused.
- **Dead peers could crowd working ones out of gossip.** Each round synced
  a random sample of peers, so keys announcing endpoints nobody answers on
  could fill it. Three quarters of each round now go to peers that synced
  within a day.
- **A watch request could be made never to expire.** Its duration was
  checked by subtracting two times that wrap around in release builds; a
  request from 146 million years ago that expires as long from now passed.
- **Rechecks counted captures made for later draws.** Successive draws of
  a URL overlap, and a witness drawn for two of them had its later
  capture, of a page maybe edited since, count for both. Each draw now
  counts each witness's first capture after the round it rechecks.
- **Work that grew with the square of the network.** Locating the peers
  checked every stored receipt about each one (450 ms per lookup at 200
  peers, and it ran per followed URL); every incoming watch request
  recomputed every request's assignment; followed URLs re-downloaded a week
  of attestations from every assigned witness every ten minutes; and
  receipts flooded, one per pair of witnesses. Now: one receipt per peer,
  assignments once per sync, only new attestations after the first fetch,
  and receipts go only to the witness they are about.
- **A failing step stopped the rest of a sync round**, pruning included,
  and one URL that couldn't be evaluated stopped the review of all others.
- **Verdicts counted every key in an epoch whose beacon was missing.**
  Without the beacon nobody can tell who was assigned, so no attestation
  from that epoch counts now.
- **Verdicts dropped captures of witnesses whose clock is a little
  behind.** They allowed no skew between a capture and its drand beacon,
  while bundles allow a minute; both allow a minute now.
- **X-Forwarded-For was taken from any client** with
  `network.trust_forwarded_for` on, say through a published container
  port, and where a peer connects from now decides where it is. The header
  is only taken from connections from this machine or a private network.

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

[1.1.1]: https://github.com/Aelthorim/witness/releases/tag/v1.1.1
[1.1.0]: https://github.com/Aelthorim/witness/releases/tag/v1.1.0
[1.0.1]: https://github.com/Aelthorim/witness/releases/tag/v1.0.1
[1.0.0]: https://github.com/Aelthorim/witness/releases/tag/v1.0.0
