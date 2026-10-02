# Changelog

All notable changes to Keepword, called Witness before 2.0.0. Versions
follow [Semantic Versioning](https://semver.org): from 1.0.0 on, the
evidence formats (attestations, logs, bundles) and the network protocol
only change incompatibly in a new major version.

## [2.1.0] - Pre-release

Fixes from an end-to-end bug hunt, most of them for what a hostile page or
peer could make a witness do, and a logo. 2.0.0 and 2.1.0 witnesses
federate and verify each other's bundles, all but re-running the other
version's normalizer. The normalizer is new, though, and captures only
compare when they were normalized the same way: until every witness runs
2.1.0, verdicts and rechecks draw on fewer witnesses, and a witness
doesn't compare a URL's first capture after the upgrade with the one
before. Upgrade every witness.

### Added

- **A logo:** a gold seal stamped with a quotation mark, for what a page
  said, sealed. `docs/assets` has the seal on its own (`logo.svg`, and
  `logo-512.png` for avatars) and with the name, for light and dark
  backgrounds (`logo-wordmark.svg`, `logo-wordmark-white.svg`). The
  banner and the social preview use it (`social-preview.svg` is the
  source of `social-preview.png`), and the web UI shows it in its header
  and as its tab icon.

### Changed

- **Normalized text is `keepword-norm/3`.** The normalizer has limits for
  hostile pages now, and a link's text leaves out the links nested in it
  (see Fixed), so such pages normalize differently. As every normalized
  text starts with the version, every normalized hash changes.

### Fixed

- **A hostile page could crash a witness or keep it busy for days.** The
  normalizer read pages recursively, so about 25 kB of nested tags
  overflowed its stack and aborted the node. The HTML parser took time in
  the square of how deep a page nests (minutes for a megabyte, days for
  the 32 MiB a capture may have), formatting tags it reopens in every
  paragraph made 160 kB of markup take 3.6 GB, and a link nested in links
  repeated the text of every link inside it: a 1 MB page normalized to
  4 GB. Pages are now read without recursion, tags nested more than 512
  deep are ignored (their text is kept), a page's tree stops growing at
  one node per two bytes, and a link's text leaves out the links inside
  it.
- **Diffs of big rewrites could run for days.** Finding the fewest changes
  between two versions takes time in the square of the lines changed, two
  minutes for 100 000. After a second, the rest now shows as replaced,
  and a line a diff shows as both removed and added, such as an update
  notice the page already had, no longer makes an edit disclosed.
- **Gossip from newer versions could stop a node syncing with a peer.**
  Pulls skip message kinds a node doesn't know, but a page of nothing
  else didn't move the cursor past them, so the node asked for that page
  forever. Pushes carrying them failed authentication, so their sender got
  no observation receipt. Pulls now move past every message, and pushes
  list the IDs of the messages they carry (2.0.0 witnesses ignore them).
- **Watch requests for the longest intervals were due every round.** The
  network takes requests for any interval from ten minutes up. Past
  292 million years, the interval wrapped around in the scheduler, and
  every witness assigned captured the URL every 15 seconds (debug builds
  panicked). Such a watch is now never due again.
- **`keepword log audit` panicked** when leaves were missing under a tree
  head, which is what it is there to find, and took time in the square of
  the log's size. It also ended with "VERIFICATION FAILED" when every
  check passed; it now says whether the audit passed.
- **One bad calendar or explorer answer stopped anchor upgrades.** A
  calendar answering anything but a timestamp failed every upgrade, and a
  failed block lookup discarded the proofs calendars had just completed.
  Each calendar or explorer that fails is now logged, once a round, and
  the rest go ahead.
- **`keepword request` withdrew the old request before checking the new
  one,** so a replacement the network refuses, such as `--every 1m`, left
  the URL with no request at all.
- **`keepword init` wrote configs it can't load,** for instance with
  `--country DEU`. No command worked after that, not even `keepword config`
  or `keepword init`. It now refuses them and writes nothing.
- **`keepword config unset` didn't turn off drand or the block
  explorer.** Left out of the file, `beacon.drand_url` and
  `anchor.esplora_url` loaded as their defaults again, so the node kept
  using api.drand.sh and blockstream.info, and tests meant to run offline
  fetched drand beacons. Unset, they are now saved as "", which turns
  them off. One unset with 2.0.0 is still missing from the file: unset it
  again.
- **A failed round of watches stopped `keepword serve`,** API and gossip
  included, for instance when the database stayed busy for ten seconds.
  It is now logged and retried, like a failed sync.
- **A capture that couldn't be compared with the one before was
  "unchanged"** in `keepword capture` and the watch log, after new site
  rules for instance. They now say it wasn't compared.
- **A bundle's TLSNotary receipt could be dated 292 million years from the
  capture** and pass the check that both happened within ten minutes: the
  subtraction wrapped around. Debug builds panicked on such bundles, and on
  pushes sent at such times.

## [2.0.0] - 2026-09-30

**Witness is now Keepword.** "Witness" is a crowded name, too hard to find
and to tell apart. Keepword turns the problem this project is about, web
pages that don't keep their word, into a promise. "Witness" stays as the
role: you still run a witness, witnesses still testify, and "Keepword is a
network of independent witnesses".

The whole project changes name at once, protocol included, so this is a
clean break: 2.0.0 nodes don't federate with 1.x nodes, and 1.x logs and
bundles don't verify with 2.0.0. Nothing carries over from a 1.x node.

### Changed

- **The command is `keepword`** (and `keepword-tlsn` for the TLSNotary
  tier), and the crates are `keepword` (the node), `keepword-core`,
  `keepword-normalize`, `keepword-capture`, `keepword-store` and
  `keepword-tlsn`. The repository is github.com/keepword-net/keepword.
- **Names on a node:** the data directory is `/var/lib/keepword` (or
  `./keepword-data` for a development node, or `KEEPWORD_DIR`), the config
  file `keepword.toml`, the service user `keepword`, the services
  `keepword.service`, `keepword-asn-update.timer` and
  `keepword-notary.service`, and the installer also uses `/opt/keepword`,
  `/usr/local/lib/keepword`, `/etc/keepword/data-dir` and
  `/etc/caddy/keepword.caddy`. The key file is still `witness.key`: it is
  the witness's identity.
- **Container:** the image is `keepword`, with a `keepword-data` volume, and
  it is configured with `KEEPWORD_ASN`, `KEEPWORD_COUNTRY`,
  `KEEPWORD_RETAIN`, `KEEPWORD_ENDPOINT`, `KEEPWORD_PEERS`,
  `KEEPWORD_SEEDS`, `KEEPWORD_BEHIND_PROXY`, `KEEPWORD_CLIENT_IP_HEADER`
  and `KEEPWORD_ASN_DB`.
- **Protocol and evidence formats (incompatible):** every signing domain
  and hash tag starts with `keepword` instead of `witness`
  (`keepword/attestation/v2`, `keepword/tree-head/v1`,
  `keepword url-key v1`, …), evidence bundles are `keepword-bundle/1`,
  normalized text starts with `keepword-norm/2`, so normalized hashes
  change too, and a WARC export's attestation record is
  `application/vnd.keepword.attestation+json`.
- The default User-Agent is `Mozilla/5.0 (compatible; Keepword/2.0.0;
  +https://github.com/keepword-net/keepword)`, and peers see `keepword/2.0.0`.
- Release archives are `keepword-vX.Y.Z-TARGET.tar.gz`. The web UI, the
  banner and the social preview say Keepword.

### Upgrading from Witness 1.x

Start every node over. On each one, remove Witness with its own installer
(`sudo sh scripts/install.sh --uninstall --purge` in a 1.x checkout), then
install Keepword. Upgrade the default seed first: new nodes join through
it.

## [1.2.0] - 2026-09-29

Witnesses behind Cloudflare or another CDN, and CI kept off the public
network. Nothing changes in the protocol or the stored data; 1.1.x and
1.2.0 witnesses work together. A witness behind a CDN places every peer in
the CDN's network until its proxy passes on client addresses: see
`network.client_ip_header` below and docs/INSTALL.md.

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

[2.1.0]: https://github.com/keepword-net/keepword/releases/tag/v2.1.0
[2.0.0]: https://github.com/keepword-net/keepword/releases/tag/v2.0.0
[1.2.0]: https://github.com/keepword-net/keepword/releases/tag/v1.2.0
[1.1.1]: https://github.com/keepword-net/keepword/releases/tag/v1.1.1
[1.1.0]: https://github.com/keepword-net/keepword/releases/tag/v1.1.0
[1.0.1]: https://github.com/keepword-net/keepword/releases/tag/v1.0.1
[1.0.0]: https://github.com/keepword-net/keepword/releases/tag/v1.0.0
