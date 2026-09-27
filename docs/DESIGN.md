# Witness: design

Witness produces independent, verifiable records of what a web page served,
and when. A node fetches a URL, reduces it to its meaningful content, signs a
statement about both, and commits that statement to an append-only log. Anyone
holding an evidence bundle can check the claim without trusting the node's
operator or its server.

This document is the working spec. Where it says **implemented**, the code in
this repository does it and has tests. Everything else is design for the
milestones ahead.

## 1. Threat model

| Attacker | Attack | Primary defence |
|---|---|---|
| Publisher | Edits a page and denies the earlier version | Signed attestations in append-only logs; timestamps anchored externally |
| Publisher | Serves witnesses a clean version and real users something else (cloaking) | Many witnesses from independent networks at the same moment; rendered captures; disagreement is itself evidence |
| Malicious witness | Fabricates a snapshot to frame a site | Quorum across independent operators; TLSNotary proofs for high-value captures; logs make lies permanent and attributable |
| Sybil | Spins up many keys to fake consensus | Trust counts networks, not keys; assignment by unpredictable per-epoch randomness; reputation that takes time to build |
| Log operator | Rewrites or forks their own history | Consistency proofs, tree-head gossip, cosigning, Bitcoin anchoring |
| Requester | Uses witnesses as a proxy to attack LANs or other sites | Public-address-only resolver (**implemented**), rate limits, assignment instead of free choice |
| Everyone | Legal exposure from hosting content | Hashes by default, opt-in retention, erasure that leaves logs intact (**implemented**) |

The last two rows were not in the original plan. The requester attack
becomes live as soon as watch requests arrive over gossip. Section 7 covers
the legal row.

## 2. Changes from the original plan

The original plan was sound. These are the places I changed it, and why.

1. **`raw_hash` split into `headers_hash` + `body_hash`.** A single hash over
   the whole response defeats deduplication, because headers carry `Date`
   and `Set-Cookie`, which change on every request. Two hashes let identical
   bodies share one blob. They also allow *selective disclosure*: you can
   prove the headers (e.g. a `Last-Modified`) without handing over the body,
   or erase the body while the header evidence survives.

2. **The normalizer is versioned and committed to.** Every attestation
   carries `norm.profile`, a digest of the normalizer version plus the exact
   site rules applied. The canonicalizer *will* keep changing (the plan
   rightly calls it the hardest part). Without a profile, every tweak would
   silently make old and new hashes incomparable, or worse, falsely equal.
   Captures are only compared within one profile.

3. **Signatures are over a canonical binary encoding, not JSON.** JSON has
   no canonical form, so two implementations would disagree on the signed
   bytes. The encoding (`witness-core/src/encoding.rs`) is ~60 lines,
   domain-separated, and easy to reimplement.

4. **Log leaves are attestation IDs, not attestations.** The log commits to
   `BLAKE3(attestation ‖ signature)`. Deleting an attestation, for example
   because its URL contains personal data, leaves the leaf in place and
   every other inclusion proof valid. The original design would have made
   GDPR erasure and an append-only log contradict each other.

5. **Assignment uses rendezvous hashing keyed by an epoch beacon, not
   Kademlia distance.** Kademlia node IDs are self-generated keys. Grinding
   keys until several land next to `hash(url)` costs an attacker minutes.
   With `weight = H(epoch_seed ‖ url_key ‖ node_key)`, where the seed is
   public randomness published per epoch (drand, or a Bitcoin block hash),
   the grinding has to be redone each epoch after the seed appears. Per-ASN
   and per-country caps apply at selection time. Kademlia stays as the
   routing and discovery layer. **Implemented:** `witness-core/src/assign.rs`.

6. **Vantage is self-reported, so it doesn't count until corroborated.**
   A node can claim any ASN. See §6.2 for corroboration. A related
   correction: faking many network locations is *not* hard. Residential
   proxy networks sell access to thousands of ASNs. ASN diversity raises
   the cost of a Sybil attack but doesn't remove it. That is why reputation
   (time-weighted) and TLSNotary still matter.

7. **Time needs a lower bound too.** Log inclusion plus OpenTimestamps
   gives an *upper* bound: the capture existed by then. A witness could
   still pre-date a capture. Putting a fresh drand beacon value in the
   attestation proves it was made *after* that round. Together they
   sandwich the capture time (v2 attestation field, M3).

8. **WARC is an export format, not the storage format.** WARC records carry
   per-capture IDs and dates, which also defeats dedup. Nodes store
   content-addressed blobs and rebuild a deterministic WARC on demand.
   Record IDs derive from the attestation ID.

9. **SQLite, not Postgres, for a node.** A node is one binary with zero
   operational dependencies. Postgres belongs in an aggregator/indexer that
   ingests many logs (M2+), and that component can use your existing setup.

10. **Adopt C2SP transparency-log formats for M2.** C2SP `tlog-tiles` for
    serving logs and `tlog-cosignature` for witness cosigning already
    exist, with independent implementations (Go's checksum database
    witnesses, Sigsum). Reusing them gets auditing tooling for free. The
    current Merkle code follows RFC 9162 exactly, so moving over means
    changing the hash function label and the serving format, not the tree.

11. **The default User-Agent is honest.** It identifies Witness. Cloaking
    detection mostly comes from rendered captures (a real browser) and from
    comparing witnesses, not from disguise. Operators can override the UA
    per node. §9 discusses the trade-off.

12. **Requests never go to private addresses.** The DNS resolver drops
    loopback, RFC 1918, link-local (cloud metadata), CGNAT and similar
    ranges, so DNS rebinding can't bypass the check. IP-literal URLs are
    checked before connecting.

## 3. Formats (implemented)

### 3.1 Canonical URL and URL key

`canonical_url`: WHATWG parse; http/https only; no credentials; fragment and
empty query removed. `url_key = BLAKE3-derive-key("witness url-key v1", len‖url)`.

### 3.2 Attestation (v1)

| Field | Meaning |
|---|---|
| `url` | Canonical requested URL |
| `final_url`, `redirects` | Where redirects led, and every hop before it |
| `fetched_at_ms` | Unix ms when the response arrived (witness's clock) |
| `method` | `http` (raw bytes) or `rendered` (DOM after JS) |
| `status`, `content_type` | From the response (`0` = not observed, for rendered) |
| `headers_hash` | BLAKE3 of the status line + end-to-end headers, CRLF-framed. Hop-by-hop headers (`Connection`, `Transfer-Encoding`, …) are excluded because the body is recorded de-chunked |
| `body_hash`, `body_len` | BLAKE3 and length of the body exactly as served. No `Accept-Encoding` is sent, so this is the identity encoding |
| `norm.profile`, `norm.hash` | Normalizer profile digest and BLAKE3 of the normalized text |
| `cert_sha256` | SHA-256 of the leaf certificate DER, the fingerprint crt.sh indexes |
| `server_ip` | Peer address, omitted when fetching through a proxy |
| `vantage.asn`, `vantage.country` | Self-reported (§6.2) |
| `witness` | Ed25519 public key |

Signing bytes: `str("witness/attestation/v1")` followed by the fields in the
order above. Integers are big-endian, variable data is prefixed with a `u32`
length, optionals have a `0/1` tag, and IPs are `4|6` plus octets. The
signature is Ed25519 with strict verification, so it can't be malleated into
a second valid signature for the same statement.
`id = BLAKE3-derive-key("witness attestation-id v1", len‖signing_bytes ‖ len‖signature)`.

### 3.3 Log

RFC 9162 Merkle tree over BLAKE3. `leaf = H(0x00 ‖ id)`, `node = H(0x01 ‖ l ‖ r)`,
and the empty root is `H("")`. Inclusion and consistency proofs use the RFC
algorithms and are tested exhaustively for every size up to 40. Each append
produces a signed tree head:
`str("witness/tree-head/v1") ‖ log_key ‖ u64 size ‖ root ‖ i64 timestamp_ms`.
Two valid heads with the same size and different roots are a portable proof
of equivocation (`SignedTreeHead::is_equivocation_with`).

### 3.4 Evidence bundle (`witness-bundle/1`)

JSON carrying the signed attestation, an inclusion proof against a signed
tree head, and optionally the header bytes, body bytes, normalized text and
the site rules behind the profile. Verification checks, independently:

1. attestation signature
2. tree-head signature, and that it belongs to the same witness
3. Merkle inclusion
4. tree head not older than the capture
5. headers/body/normalized text against their hashes (each optional)
6. **renormalize**: re-run the normalizer on the body and compare with
   `norm.hash`. This only runs when the verifier's normalizer produces the
   same profile. Otherwise it is skipped with the reason stated.

Any piece can be withheld (after an erasure, say) without affecting the
other checks. `witness verify --bundle FILE` needs no node, key or network.

## 4. Normalization (v1, implemented)

The output is line-oriented text, one block per line, which makes it
diffable, readable and cheap to hash:

```
witness-norm/1 html
title: Minister resigns
modified: 2024-05-01T10:00:00Z
h1: Minister resigns
p: The minister resigned on Monday. More
link: https://news.example/more | More
img: https://news.example/img/photo.jpg | The minister
```

The rules:

- **Content root**: the site rule's `root` selector, else the single
  `<main>`, else the single `<article>`, else `<body>`.
- **Dropped**: script/style/template/iframe/svg/form controls, `hidden`,
  `aria-hidden`, `display:none`, and elements whose class or id *tokens*
  mark ads, consent banners, share widgets, newsletters or recommendation
  rails (`ad-slot` matches, `header` does not). Also anything matched by
  site `remove` selectors.
- **Text**: NFC, invisible characters removed, whitespace collapsed.
  Relative times ("5 minutes ago", "vor 3 Stunden", "il y a 2 jours")
  become `<reltime>`, and live counters ("1,234 views") become `<n> views`.
  `<time datetime>` is replaced by its machine-readable value.
- **Links**: resolved, fragment dropped, tracking parameters (`utm_*`,
  `fbclid`, `gclid`, …) removed.
- **Images**: resolved and compared *without* query string (CDN resize
  parameters and signatures live there). `data:` URIs are replaced by
  their hash.
- **Metadata**: `title`, canonical link, description, published and
  modified dates (Open Graph meta or JSON-LD). A changed `modified:` line
  is how a publisher *discloses* an edit in machine-readable form.
- **Charset**: Content-Type, then BOM, then `<meta charset>`, then UTF-8.
- **JSON** is re-serialized with sorted keys. **Text** has each line
  cleaned. **Everything else** is opaque: the normalized form is the body
  hash.

Site rules (`[[rules]]` in `witness.toml`) add `remove` selectors and a
`root` for a host and its subdomains. The most specific match wins. Rules
are part of the profile.

### Silent-edit classification

A change is **disclosed** if an *added* line is a new `modified:` date, or
matches an update notice ("Update:", "Correction", "Editor's note",
"aktualisiert", "Korrektur", "Anmerkung der Redaktion", "mise à jour", …).
Otherwise it is **silent**. Removing a correction notice does not count as
disclosure. When the normalized text wasn't retained, a change is recorded
but never labelled silent.

### Known gaps (tuning backlog)

- **Absolute "now" clocks.** A JS clock printing the current time looks
  like an edit. Candidate fix: treat an absolute timestamp within a few
  minutes of `fetched_at` as `<now>`. `fetched_at` is signed, so
  verification can still re-run normalization.
- **Personalised and randomised blocks** ("people also read") that don't
  use recognisable class names. For now these need site rules.
- **Image content**: images are compared by URL, not bytes. Hashing image
  bytes is a per-site opt-in for later.
- **A/B tests** look like cloaking to a single witness. The quorum logic
  (§6.3) is what distinguishes them.

## 5. Node (implemented, M0 + M1)

```
witness-core        pure protocol: encoding, attestations, Merkle, tree heads,
                    bundles, assignment, quorum (no I/O)
witness-normalize   canonicalizer, site rules, diff + silent-edit classifier
witness-capture     HTTP capture (cert, IP, redirects, SSRF guard),
                    headless render (feature "render"), WARC export
witness-store       BLAKE3 blob store, SQLite index, log + tree heads,
                    watchlist, change table, purge
witness-node        `witness` CLI, watch scheduler, read-only web UI
```

The capture pipeline is: canonicalize URL → fetch → normalize with the
host's rules → build attestation → sign → store blobs (per retention) → in
one SQLite transaction insert the attestation, append its ID to the log and
sign the new tree head → compare with the previous capture of the same URL
and method → record a change if there is one.

`witness log audit` re-verifies everything: every tree head's signature,
root and consistency with the next; every attestation's signature, ID and
leaf position; and every retained blob's hash.

## 6. Network (M2–M4 design)

### 6.1 Transport

libp2p over QUIC with Noise. Kademlia handles peer discovery and routing
only. Gossipsub carries these topics:

- `witness/req/1`: watch requests (URL, requested method, requester's
  signature and rate-limit token)
- `witness/att/1`: new attestation IDs + tree heads. Bodies are fetched on
  demand, which avoids pushing possibly personal URLs to everyone
- `witness/sth/1`: tree heads for cross-checking and cosigning
- `witness/alert/1`: silent-edit and split-verdict alerts

`iroh` is a reasonable alternative. The protocol messages are
transport-agnostic.

### 6.2 Vantage corroboration

Self-reported ASN is worthless on its own. A node's network location counts
only when at least *m* peers from *m* different ASNs have each signed an
**observation receipt**: "I saw key K connect from IP X at time T". The
libp2p `identify` protocol already reports the observed address. Verifiers
map the IP to an ASN themselves, using a public BGP-derived table pinned
per epoch by hash (e.g. from RouteViews). They don't trust the node's claim.
Receipts expire, so a node that moves has to be re-observed.

This establishes where a node *is*, not where each fetch came *from*. A
malicious node can still fetch through a proxy. No protocol fixes that,
TLSNotary included, because the TLS server sees the prover's egress, not
the notary. What diversity really buys is **independent operators**, and
that is what the quorum should count.

### 6.3 Quorum (logic implemented in `witness-core/src/quorum.rs`)

For one URL, take the latest valid attestation per witness inside a time
window. Compare within the largest class that shares a capture method and
normalizer profile. Group by comparison hash and count *distinct
corroborated ASNs* per group, never keys. The verdict is one of:

- **Agreed**: the top group reaches `min_asns` and no second group reaches
  `min_dissent_asns`. Witnesses outside the top group are listed as
  dissenters, and their reputation suffers.
- **Split**: two or more groups each reach `min_dissent_asns`. The server
  served independent networks different content at the same time, which
  means cloaking, geo-targeting or A/B testing. That is newsworthy either
  way.
- **Insufficient**: anything else.

One lying witness produces a dissenter, never a split. Five keys in one ASN
count once.

### 6.4 Assignment (implemented in `witness-core/src/assign.rs`)

Rendezvous hashing with an epoch seed plus diversity caps (§2.5). The epoch
is one day. The seed is the drand round at the epoch boundary. A URL's
assigned set is public, so everyone knows who *should* have attested, and
silence from an assigned witness is itself a signal. Requests are
rate-limited per requester key and per target host, so a watch request
can't make the network attack a site.

### 6.5 Tree-head gossip and cosigning

Each node fetches its peers' tree heads, verifies consistency with the last
head it saw, and publishes a cosignature (C2SP `tlog-cosignature`). A
verifier can require *k* cosignatures on a tree head before trusting an
inclusion proof. A log that forks must then show different histories to
different cosigners, and the two conflicting signed heads prove it.

### 6.6 Anchoring (M3)

Once an hour, a node submits its latest tree-head root to OpenTimestamps
calendars, stores the pending `.ots` proof, and upgrades it once Bitcoin
confirms. Bundles gain an `anchor` section. The verifier checks the OTS
path to a block header, which gives a timestamp nobody can backdate.

### 6.7 Proof tier: TLSNotary (M4)

For captures marked high-value, a second assigned witness in a different
ASN acts as the TLSNotary verifier during the fetch. The result is a proof
that the bytes came from a TLS session with the named server. It makes
fabrication by a single witness cryptographically impossible, not just
socially costly. It costs an interactive MPC session per capture and
depends on a library that is explicitly not production-ready and breaks
often. So it stays optional and is behind a crate boundary
(`witness-tlsn`), never a dependency of the core.

### 6.8 Reputation

A witness's score is time-weighted agreement with Agreed verdicts, minus
dissent, with a cap on how fast it can grow. Reputation takes weeks to
earn, which is the part of Sybil cost that money for proxies can't buy.

## 7. Storage, retention and law

Not legal advice, and German law in particular deserves a lawyer's review
before public operation. The design aims to leave room for compliance.

- **Retention levels (implemented):** `full` (headers + body + normalized
  text), `normalized` (headers + normalized text; diffs still work), or
  `none` (hashes only; edits detected but not shown). Hashes, attestations
  and the log never contain page content.
- **Erasure (implemented):** `witness purge URL` deletes a URL's blobs
  unless another URL still references the same bytes. `--forget` also
  deletes its attestation rows. The log keeps only opaque IDs, so every
  other proof stays valid. The test suite checks exactly this.
- **Serving to peers (M2)** is off by default and separate from retention.
  A node only serves content for hosts on an opt-in allowlist, e.g. news
  outlets, government pages, and corporate ToS and privacy policies. The
  proof property survives: whoever holds the original can show it matches
  the hash.
- **Points to check with counsel:** §44b UrhG (text-and-data-mining
  exception, including machine-readable opt-outs) and whether retention
  should honour TDM reservations; GDPR Art. 17 and Art. 85 (journalistic
  purposes); DSA hosting obligations if a node serves others' content;
  §51 UrhG (quotation) for publishing diffs.

## 8. Milestones

| | Scope | Status |
|---|---|---|
| M0 | Single node: fetch → normalize → sign → Merkle log → `verify`; bundles; WARC export; audit | **done** |
| M1 | Watchlists, diff engine, silent-edit classification, web UI with edit history | **done** |
| M1.5 | Normalizer tuning against a corpus of real news/ToS pages; "now"-clock heuristic; per-site rule library | next |
| M2 | libp2p transport, gossip topics, tree-head exchange + cosigning, remote bundle fetch, C2SP tiles | design |
| M3 | Epoch beacons, vantage corroboration, quorum verdicts in the UI, reputation, OpenTimestamps anchoring, drand lower bound (attestation v2) | core logic done (assignment, quorum) |
| M4 | TLSNotary proof tier, cross-witness cloaking alerts | design |

## 9. Open questions

- **Honest UA vs. cloaking detection.** A site that cloaks for crawlers will
  cloak for an honest UA, and that's fine: a raw capture that differs from a
  rendered browser capture at the same moment is itself the cloaking signal.
  Operators who want browser-identical requests can set the UA. The project
  shouldn't ship evasion tooling beyond that.
- **Windowing for split verdicts.** Ten minutes is a guess. Fast-moving
  pages (live blogs) need either a shorter window or site rules that
  exclude the live section.
- **Who can request watches in M2**, and how requests are rate-limited
  without a central authority. One option is per-key token buckets, with
  tokens earned by attesting.
