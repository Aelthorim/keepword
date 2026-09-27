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
   and per-country caps apply at selection time. With rendezvous hashing
   there is no need for a DHT at all (§6.1). **Implemented.**

6. **Vantage is self-reported, so it doesn't count until corroborated.**
   A node can claim any ASN. See §6.3 for corroboration. A related
   correction: faking many network locations is *not* hard. Residential
   proxy networks sell access to thousands of ASNs. ASN diversity raises
   the cost of a Sybil attack but doesn't remove it. That is why reputation
   (time-weighted) and TLSNotary still matter.

7. **Time needs a lower bound too.** Log inclusion plus OpenTimestamps
   gives an *upper* bound: the capture existed by then. A witness could
   still pre-date a capture. Putting a fresh drand beacon value in the
   attestation proves it was made *after* that round. Together they
   sandwich the capture time. **Implemented** (§6.6).

8. **WARC is an export format, not the storage format.** WARC records carry
   per-capture IDs and dates, which also defeats dedup. Nodes store
   content-addressed blobs and rebuild a deterministic WARC on demand.
   Record IDs derive from the attestation ID.

9. **SQLite, not Postgres, for a node.** A node is one binary with zero
   operational dependencies. Postgres belongs in an aggregator/indexer that
   ingests many logs (M2+), and that component can use your existing setup.

10. **HTTP federation instead of libp2p** (§6.1), shaped after C2SP
    transparency-log practice (`tlog-tiles`, `tlog-cosignature`). The API
    is not byte-compatible with C2SP yet, because C2SP uses SHA-256 and
    signed notes. The tree follows RFC 9162 exactly, so adding a C2SP view
    means changing the hash label and serving format, not the tree.

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

### 3.2 Attestation (v1, v2)

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
| `vantage.asn`, `vantage.country` | Self-reported (§6.3) |
| `witness` | Ed25519 public key |
| `beacon` | v2 only: drand quicknet round and BLS signature fetched just before the capture |

Signing bytes: `str("witness/attestation/v1")` (or `v2` when a beacon is
present) followed by the fields in the order above, with the beacon's
`u64 round ‖ bytes signature` last. Integers are big-endian, variable data is prefixed with a `u32`
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
6. **not before**: the drand beacon's BLS signature, and that its round was
   published before the claimed capture time
7. **cosignatures**: other witnesses' signatures over the same tree head
8. **anchor**: an inclusion proof into an anchored tree head and its
   OpenTimestamps proof; with `--esplora`, the block's Merkle root
9. **renormalize**: re-run the normalizer on the body and compare with
   `norm.hash`. This only runs when the verifier's normalizer produces the
   same profile. Otherwise it is skipped with the reason stated.

Any piece can be withheld (after an erasure, say) without affecting the
other checks. `witness verify --bundle FILE` needs no node, key or network.

## 4. Normalization (v2, implemented)

The output is line-oriented text, one block per line, which makes it
diffable, readable and cheap to hash:

```
witness-norm/2 html
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
  rails (`ad-slot` matches, `header` does not), consent-management and ad
  vendors by prefix (OneTrust, Usercentrics, Cookiebot, Sourcepoint,
  Didomi, GPT slots, Taboola, Outbrain…), and user comments. Also anything
  matched by site `remove` selectors.
- **Text**: NFC, invisible characters removed, whitespace collapsed.
  Relative times ("5 minutes ago", "vor 3 Stunden", "il y a 2 jours")
  become `<reltime>`, and live counters ("1,234 views") become `<n> views`.
  `<time datetime>` is replaced by its machine-readable value.
- **Live clocks**: an absolute timestamp equal to the signed capture time
  becomes `<now>` (zoned: within 120 s; zone-less: only with seconds,
  within 90 s modulo whole hours). `fetched_at` is signed, so verifiers get
  the same result.
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
matches an update notice ("Update:", "Last updated", "Correction",
"Editor's note", "Stand:", "aktualisiert", "Korrektur", "Anmerkung der
Redaktion", "mise à jour", …).
Otherwise it is **silent**. Removing a correction notice does not count as
disclosure. When the normalized text wasn't retained, a change is recorded
but never labelled silent.

### Regression corpus

`crates/witness-normalize/tests/corpus/` holds pages modelled on common
publishing stacks: a German public broadcaster's article, WordPress with
Jetpack and Cloudflare email obfuscation, a SaaS privacy policy behind
OneTrust, GOV.UK, and a JS-rendered status page. Each has variants that
reproduce what changes between two real requests (rotated tokens, counters,
ad slots, consent text, cache busters, re-keyed email obfuscation, clocks),
which must normalize identically, and edits that must be caught and
classified as silent or disclosed. The fixtures are hand-built because this
development environment couldn't reach live sites. Growing it from real
captures is the most valuable next step.

### Known gaps

- **Personalised and randomised blocks** ("people also read") that don't
  use recognisable class names still need site rules.
- **Image content**: images are compared by URL, not bytes.
- **A/B tests** look like cloaking to a single witness. The quorum logic
  (§6.5) is what distinguishes them.

## 5. Node (implemented)

```
witness-core        pure protocol: encoding, attestations, Merkle, tree heads,
                    bundles, signed statements and gossip messages, drand
                    beacons, OpenTimestamps, assignment, quorum (no I/O)
witness-normalize   canonicalizer, site rules, diff + silent-edit classifier
witness-capture     HTTP capture (cert, IP, redirects, SSRF guard),
                    headless render (feature "render"), WARC export
witness-store       BLAKE3 blob store, SQLite index, log + tree heads,
                    watchlist, change table, purge; peers, mirrored logs,
                    gossip outbox, requests, cosignatures, observations,
                    alerts, beacons, anchors, reputation
witness-node        `witness` CLI, peer API, federation, verdicts,
                    anchoring, watch scheduler, web UI
```

The capture pipeline is: canonicalize URL → take a recent drand beacon →
fetch → normalize with the host's rules → build attestation → sign → store
blobs (per retention) → in one fully durable SQLite transaction insert the
attestation, append its ID to the log and sign the new tree head → compare
with the previous capture of the same URL and method → record a change, and
raise a silent-edit alert if the publisher didn't disclose it.

`witness log audit` re-verifies everything: every tree head's signature,
root and consistency with the next; every attestation's signature, ID and
leaf position; and every retained blob's hash.

## 6. Network (implemented)

### 6.1 Transport: HTTP, not libp2p

The first plan said libp2p with Kademlia and gossipsub. The implementation
uses plain HTTPS between nodes instead:

- **Rendezvous assignment needs the full membership list anyway.** A DHT is
  for finding *a few* nodes among millions without knowing them all.
  Assignment ranks *every* eligible witness, and a witness network of
  hundreds to low thousands fits in a table.
- **Transparency logs already live on HTTP.** CT, C2SP `tlog-tiles` and the
  Sigsum/Go checksum-database witnesses are all plain HTTP. An HTTP log is
  auditable with `curl`, cacheable, and runs behind any reverse proxy or CDN.
- **NAT is handled by push *and* pull.** Every exchange is started by the
  syncing node: it pulls a peer's outbox and pushes its own. A node without
  a public endpoint still sends and receives everything; it just can't be
  mirrored.
- **Smaller attack surface and dependency tree.** libp2p remains an option
  as a second transport. All messages are transport-agnostic signed
  statements.

The API (`/v1`, see `crates/witness-node/src/api.rs`) serves the node's
descriptor, known peers, tree head, leaf IDs, attestations, inclusion and
consistency proofs, bundles, and its gossip outbox, and accepts pushes. It
never serves page content, except blobs for hosts on
`network.serve_content_hosts`. The web UI, which shows content, listens
separately on localhost.

### 6.2 Sync and gossip

Each round, for each peer with an endpoint, a node:

1. refreshes the peer's descriptor (it must still be the same key) and
   learns the peers it knows;
2. fetches its tree head and any new leaf IDs, then recomputes the root over
   **every leaf it has ever mirrored from that peer**. A peer can extend its
   history but never rewrite what it has shown; a mismatch is rejected;
3. two validly signed heads of the same size with different roots are an
   **equivocation proof**, stored, gossiped and alerted on. Equivocating
   logs are excluded from assignment;
4. fetches the new attestations and verifies signature, signer and ID;
5. **cosigns** the head: "consistent with everything I have seen";
6. pulls the peer's outbox, pushes its own, and receives an observation
   receipt (§6.3).

Gossip messages (descriptors, watch requests, tree heads, cosignatures,
observations, alerts, equivocation proofs, drand beacons) are all signed
statements with content-derived IDs. They are deduplicated by ID, validated
(signature, clock skew, rate limits), stored and forwarded.

### 6.3 Vantage corroboration

Self-reported ASN is worthless on its own. Pushes carry a signed envelope
(`from`, `to`, time, hash of the message IDs), protected against replay.
The receiver answers with an **observation receipt**: "I saw key K connect
from IP X at time T", which floods like any gossip. A verifier maps each IP
to an ASN with its own copy of a public IP→ASN table (iptoasn.com format,
`quorum.asn_db`). A location counts once at least `min_observers` distinct
observers (not K itself) agree on the same ASN. Without an ASN table nothing
is corroborated. `quorum.trust_self_reported` exists for test networks
only.

This establishes where a node *is* (its egress), not where each fetch came
*from*. A malicious node can still fetch through a proxy, and no protocol
fixes that, TLSNotary included. What diversity really buys is
**independent operators**, and that is what the quorum counts.

### 6.4 Watch requests and assignment

`witness request URL` creates a signed request (interval ≥ 10 min, at most
30 days, at most 50 active per requester). It floods, and every node
computes the same rendezvous assignment:
`weight = H(epoch_seed ‖ url_key ‖ node_key)`, highest first, at most one
witness per ASN and `max_per_country` per country, `replication` in total.
The **epoch seed** is the drand quicknet beacon at the start of the UTC day,
verified offline with BLS. Beacons also travel over gossip, so nodes
without drand access can still use them. Only assigned witnesses add the
URL to their watchlist; the watch disappears when the request expires or
the assignment moves.

Assignment is only as consistent as nodes' views of the membership. After
a few sync rounds they converge. Divergent views mean a URL briefly has
slightly different assignees, never zero.

### 6.5 Quorum, reputation and alerts

For a URL, a node gathers its own and mirrored attestations and takes the
latest per witness inside a time window. It compares them within the
largest class sharing capture method and normalizer profile, groups them by
comparison hash, and counts distinct corroborated ASNs, never keys:

- **Agreed**: the top group reaches `min_asns`, no second group reaches
  `min_dissent_asns`. Group members earn +1 reputation per URL and window;
  dissenters get −3.
- **Split**: two or more groups each reach `min_dissent_asns`. Independent
  networks were served different content at the same moment: cloaking,
  geo-targeting or an A/B test. A **split alert** is raised and flooded.
- **Insufficient**: anything else.

Reputation decays with a 14-day half-life, so it takes sustained agreement
to build. **Silent-edit alerts** are raised by the capturing witness.

### 6.6 Time: drand lower bound, Bitcoin upper bound

Attestations with a beacon use the v2 encoding and embed the latest drand
round the witness had before fetching. Its BLS signature verifies offline,
proving the capture happened *after* that round. Attestations without a
beacon keep the exact v1 bytes.

For the upper bound, `witness anchor submit` (or `serve --anchor`) sends
`SHA-256(tree-head signing bytes)` to OpenTimestamps calendars. `anchor
upgrade` fetches the Bitcoin path once it confirms and checks the block's
Merkle root with an Esplora API. The stored proof is an ordinary detached
`.ots` file (`witness anchor export`), so the standard `ots verify` tool
also works. Bundles include the smallest confirmed anchored head covering
the attestation. `witness verify --bundle F --esplora URL` checks it
against the chain.

### 6.7 Proof tier: TLSNotary (implemented, `crates/witness-tlsn`)

A plain attestation means "trust the witness". For high-value captures a
second witness, ideally an assigned one in another ASN, acts as the
**TLSNotary verifier**:

1. The prover opens a session on the verifier's notarization port with a
   signed hello: prover key, verifier key, nonce, time. By default the
   verifier only serves known peers.
2. Prover and verifier run MPC-TLS: the TLS session keys are split between
   them, so the prover cannot forge server responses on its own. The prover
   fetches the page (`Accept-Encoding: identity`, `Connection: close`) and
   reveals the full transcript and the server identity.
3. The verifier checks the certificate chain against Mozilla's roots and
   the server name, then signs a **`TlsnReceipt`**: prover, server name,
   BLAKE3 of the sent and received plaintext, time. It keeps the receipt for
   the prover to collect and floods it over gossip.
4. The prover builds the attestation from the same transcript. Header block
   and body come from the raw response via `witness_core::httpmsg`, so the
   derivation is identical on both sides. It stores the receipt, and with
   full retention the transcript.

A bundle's **tls notary** check verifies the receipt signature. It also
checks that the receipt names this witness as prover and another witness as
verifier, that the server name equals the URL's host, and that the times
match. It then re-derives status, header block and body from the transcript
and compares them with the attestation. Fabricating a capture now needs two
colluding witnesses.

Costs and limits: an MPC-TLS session takes about a second locally for a
small page, and grows with size (default cap 256 KiB received). TLS 1.2
only, no compression, no redirects. The crate is a **separate Cargo
workspace** pinned to a tlsn git revision: tlsn is pre-1.0, changes its API
often, needs Rust 1.95+ and pulls a large MPC stack from git. The main
workspace never builds it; the receipt format and its verification live in
`witness-core` and have no tlsn dependency.

```sh
witness-tlsn serve --addr 0.0.0.0:8482                   # on the notary witness
witness-tlsn capture https://example.org/terms \
    --verifier notary.example.net:8482 --verifier-key <hex>  # on the prover
witness verify https://example.org/terms                 # includes "tls notary"
```

### 6.8 Bundles, cosigned

Bundles are built against the largest tree head that other witnesses have
cosigned, and carry those cosignatures. For a log to lie to one verifier,
it must then have lied consistently to every cosigner, and any two
conflicting heads prove it.

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
| M1.5 | Normalizer v2: live-clock masking, consent/ad vendors, regression corpus | **done** (corpus is hand-built; grow it from real captures) |
| M2 | HTTP federation, log mirroring, cosigning, equivocation proofs, gossip, watch requests with assignment | **done** |
| M3 | drand epoch seeds and capture lower bound, observation receipts + ASN corroboration, verdicts, reputation, OpenTimestamps anchoring | **done** |
| M4 | TLSNotary proof tier, cross-witness cloaking (split) alerts | **done** |
| next | Real-world corpus; C2SP-compatible log view; automatic notary selection from assignment; tile-based log serving for large logs; Postgres indexer across many logs | |

## 9. Open questions

- **Honest UA vs. cloaking detection.** A site that cloaks for crawlers will
  cloak for an honest UA, and that's fine: a raw capture that differs from a
  rendered browser capture at the same moment is itself the cloaking signal.
  Operators who want browser-identical requests can set the UA. The project
  shouldn't ship evasion tooling beyond that.
- **Windowing for split verdicts.** Ten minutes is a guess. Fast-moving
  pages (live blogs) need either a shorter window or site rules that
  exclude the live section.
- **Who can request watches.** Today it is any key, capped at 50 active
  requests each, with intervals ≥ 10 min. That is cheap to Sybil. Per-key
  token buckets with tokens earned by attesting would be better.
- **Membership consistency.** Assignment depends on each node's view of the
  witness set. Views converge through gossip, but a signed, epoch-pinned
  membership snapshot would make assignment exactly reproducible for
  auditors.
- **ASN table provenance.** Verifiers should agree on the IP→ASN table.
  Pinning its hash per epoch (and gossiping it) is straightforward, but not
  built.
