# Keepword: design

Keepword produces independent, verifiable records of what a web page served,
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
| Malicious witness | Fabricates a snapshot to frame a site, or dissents to fake a split | Quorum across independent networks; disagreements settled by rechecks from witnesses drawn at random, so only reproducible versions count (§6.5); TLSNotary proofs for high-value captures; logs make lies permanent and attributable |
| Sybil | Spins up many keys to fake consensus | Trust counts networks, not keys, and a network is only counted from what a node saw itself (§6.3); assignment by unpredictable per-epoch randomness. **Not** defended: one operator who really connects from many networks (§6.3) |
| Log operator | Rewrites or forks their own history | Consistency proofs, checkpoint gossip, cosigning, Bitcoin anchoring. Same-size forks are proven to anyone; forks of different sizes are caught by each auditor that checks the other auditors' heads (§6.2) |
| Requester | Uses witnesses as a proxy to attack LANs or other sites | Public-address-only resolver, per-address API rate limits, assignment instead of free choice (**implemented**) |
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
   bytes. The encoding (`keepword-core/src/encoding.rs`) is ~60 lines,
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
   the cost of a Sybil attack but doesn't remove it. That is why TLSNotary
   and rechecks by randomly drawn witnesses (§6.5) still matter.
   Reputation is computed but only shown; it is not a defence (§6.5).

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

11. **The default User-Agent is honest.** It identifies Keepword. Cloaking
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
empty query removed. `url_key = BLAKE3-derive-key("keepword url-key v1", len‖url)`.

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

Signing bytes: `str("keepword/attestation/v1")` (or `v2` when a beacon is
present) followed by the fields in the order above, with the beacon's
`u64 round ‖ bytes signature` last. Integers are big-endian, variable data is prefixed with a `u32`
length, optionals have a `0/1` tag, and IPs are `4|6` plus octets. The
signature is Ed25519 with strict verification, so it can't be malleated into
a second valid signature for the same statement.
`id = BLAKE3-derive-key("keepword attestation-id v1", len‖signing_bytes ‖ len‖signature)`.

### 3.3 Log

RFC 9162 Merkle tree over BLAKE3. `leaf = H(0x00 ‖ id)`, `node = H(0x01 ‖ l ‖ r)`,
and the empty root is `H("")`. Inclusion and consistency proofs use the RFC
algorithms and are tested exhaustively for every size up to 40. A running
node keeps the hash of every complete subtree (`merkle::MerkleCache`, about
two hashes per leaf), so appends and proofs cost O(log n), not a pass over
the whole log. Each append produces a signed tree head:
`str("keepword/tree-head/v1") ‖ log_key ‖ u64 size ‖ root ‖ i64 timestamp_ms`.
Two valid heads with the same size and different roots are a portable proof
of equivocation (`SignedTreeHead::is_equivocation_with`).

### 3.4 Evidence bundle (`keepword-bundle/1`)

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
other checks. `keepword verify --bundle FILE` needs no node, key or network.

## 4. Normalization (v2, implemented)

The output is line-oriented text, one block per line, which makes it
diffable, readable and cheap to hash:

```
keepword-norm/2 html
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

Site rules (`[[rules]]` in `keepword.toml`) add `remove` selectors and a
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

`crates/keepword-normalize/tests/corpus/` holds pages modelled on common
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
keepword-core       pure protocol: encoding, attestations, Merkle, tree heads,
                    bundles, signed statements and gossip messages, drand
                    beacons, OpenTimestamps, assignment, quorum (no I/O)
keepword-normalize  canonicalizer, site rules, diff + silent-edit classifier
keepword-capture    HTTP capture (cert, IP, redirects, SSRF guard),
                    headless render (feature "render"), WARC export
keepword-store      BLAKE3 blob store, SQLite index, log + tree heads,
                    watchlist, change table, purge; peers, audited heads,
                    gossip outbox, requests, cosignatures, observations,
                    alerts, beacons, anchors, reputation
keepword            `keepword` CLI, peer API, federation, verdicts,
                    anchoring, watch scheduler, web UI
```

The capture pipeline is: canonicalize URL → take a recent drand beacon →
fetch → normalize with the host's rules → build attestation → sign → store
blobs (per retention) → in one fully durable SQLite transaction insert the
attestation, append its ID to the log and sign the new tree head → compare
with the previous capture of the same URL and method → record a change, and
raise a silent-edit alert if the publisher didn't disclose it.

`keepword log audit` re-verifies everything: every tree head's signature,
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
  audited or asked for its attestations, and, since nobody pushes to it,
  it can't place other witnesses in networks (§6.3), so it can't compute
  verdicts itself.
- **Smaller attack surface and dependency tree.** libp2p remains an option
  as a second transport. All messages are transport-agnostic signed
  statements.

The API (`/v1`, see `crates/keepword/src/api.rs`) serves the node's
descriptor, known peers, tree head, leaf IDs, attestations, inclusion and
consistency proofs, bundles, and its gossip outbox, and accepts pushes. It
never serves page content, except blobs for hosts on
`network.serve_content_hosts`. The web UI, which shows content, listens
separately on localhost.

### 6.2 Sync and gossip

Nothing in a round grows with the size of the network, so the per-node
cost stays about the same at 20 witnesses or 1000. Each round (every
minute) a node:

0. while it knows fewer peers than its gossip sample, dials its configured
   peers and the built-in **seed witnesses** (`DEFAULT_SEEDS`, unless
   `network.seeds = false` or the network is private);
1. exchanges gossip with a **random sample** of peers
   (`network.gossip_fanout`, 16): refreshes each one's descriptor, pulls
   its outbox, pushes its own and gets an observation receipt (§6.3).
   Three quarters of the sample are peers that synced within a day, the
   rest others, to find new peers and notice ones that are back, so keys
   announcing endpoints nobody answers on can't crowd the working ones out.
   Messages still reach every node, over a few hops. The full peer list is
   only fetched while a node knows few peers, and daily from its bootstrap
   peers;
2. **audits** the logs it is an auditor of, when due (below);
3. fetches other witnesses' attestations for the URLs it follows (§6.5);
4. prunes old data, at most hourly (§7).

**Audits.** Each log has `network.audit_logs` (16) auditors: the witnesses
ranked highest for it by `H("keepword audit v1" ‖ log ‖ witness)`. Every
node computes the same set, so each log gets 16 auditors and each witness
audits about 16 logs, whatever the network's size. Once per
`network.cosign_interval_secs` (an hour), an auditor:

1. fetches the log's **checkpoint**: the latest head the log signed before
   the start of the current hour (`network.checkpoint_interval_secs`), so
   every auditor coming by in that hour sees the same head;
2. checks with a consistency proof that it extends the last checkpoint it
   verified (or is a prefix of it, for a lagging checkpoint). A log can
   extend its history but never rewrite what an auditor has seen. The log
   isn't copied: the proof is a few dozen hashes;
3. **cosigns** it ("consistent with everything I have seen") and delivers
   the cosignature to the log, which puts it in its bundles (§6.8). It is
   not gossiped;
4. gossips the checkpoint. Auditors that saw the same checkpoint send
   byte-identical messages, which gossip deduplicates. Two validly signed
   heads of the same log and size with different roots are an
   **equivocation proof**, whoever holds them: stored, gossiped and alerted
   on. Equivocating logs are excluded from assignment;
5. checks the heads *other* auditors gossiped for the log against the one
   it verified itself: the log must prove each consistent with it. A log
   that showed different auditors histories that never share a size can't.
   One that serves a proof that fails, refuses one (HTTP 4xx), or can't
   serve one for a day is treated like an equivocating log by this node.
   Unlike a same-size fork, this isn't a proof others can check offline,
   so every auditor establishes it for itself. The biggest heads are
   checked first: a forked log can sign any number of honest heads of the
   history its forks share, and checking oldest first would let those
   crowd out the heads that expose it.

This is how Certificate Transparency's witnesses work. The earlier design
mirrored every peer's log and attestations and gossiped every
cosignature, which cost each node nodes² × rounds of storage: a few
hundred MB a day at 20 witnesses, over a terabyte at 1000.

Gossip messages (descriptors, watch requests and cancellations, tree heads,
alerts, equivocation proofs, drand beacons, TLSNotary receipts) are all
signed statements with content-derived IDs. (Cosignatures go to the log they
cover, and observation receipts to the node they are about; neither floods.)
They are deduplicated by ID, validated (signature, clock skew, rate
limits), stored and forwarded. Message kinds a node doesn't know are
skipped, not fatal, so nodes can be upgraded one at a time.

Keys cost nothing, so a node limits what strangers can make it store:

- **Only descriptors and beacons are accepted from anyone.** Every other
  message must be signed by a witness in the peer table (or by the node
  itself). The table is capped (`network.max_peers`), so flooding alerts,
  requests or receipts first means getting into it.
- **Every key may only make a node take so much.** Getting into the peer
  table is free, so a node takes at most an hour's worth of each kind of
  message from one key: 10 descriptors or equivocation proofs, 60 tree
  heads, 100 requests or cancellations, 200 of anything else, well above
  what an honest witness sends. Keys the node has never synced with nor
  seen push to it share 2000 messages an hour between them, except the
  peer lists of its bootstrap peers. These checks come before any
  signature is checked. Alerts dated ahead, which would never be pruned,
  are refused.
- **A full peer table evicts the least useful peer** to admit a new one
  with an endpoint: an equivocating log first, then peers without an
  endpoint, then peers that never synced within an hour of being learned
  or haven't synced for a day. Healthy peers are never evicted. Descriptors older than seven days are ignored.
- **Beacons older than three days are refused.** Every historical drand
  beacon verifies, and there are millions. Checking one is a BLS pairing,
  milliseconds of CPU, and anyone may send them, so a node only checks a
  beacon it can use (newer than any it holds, or a day's epoch seed it
  lacks), at most 20 at once and one every three seconds after that.
- Peers are synced eight at a time, and a peer whose last sync failed is
  retried after ten minutes, so dead peers can't stall a round.

Peer endpoints come from untrusted descriptors, so the peer client refuses
private and loopback addresses, including IP literals and redirect targets,
unless `network.allow_private_peers` is set for a closed LAN network.

### 6.3 Vantage corroboration

Self-reported ASN is worthless on its own. Pushes carry a signed envelope
(`from`, `to`, time, hash of the message IDs), protected against replay.
The receiver answers with an **observation receipt**: "I saw key K connect
from IP X at time T", which K keeps. Receipts don't flood: a node only uses
its own receipts and the ones about itself (below). A verifier maps each IP
to an ASN with its own copy of a public IP→ASN table (iptoasn.com format,
`quorum.asn_db`).

Keys are free, so a verifier never counts observers as such. One server
with twenty keys could otherwise sign receipts vouching that each of its
keys sits in a different network, and verdicts would count twenty
independent witnesses. Counting observers once per network isn't enough
either: two servers on two real networks could sign receipts placing any
number of keys that never connect to the verifier in any networks they
like, each one counted. So a verifier decides where K is like this:

1. **Another witness is where the verifier saw it connect.** If K has
   pushed to the verifier, the address the verifier saw is K's location
   (behind the verifier's own reverse proxy or CDN, the address they pass
   on). Receipts from other observers never place K.
2. **The verifier itself is where its peers saw it.** Receipts about the
   verifier count once per network their observers connect from, as the
   verifier saw those observers itself, and `min_observers` (2) networks
   must agree. Twenty keys on one server are one observer network.

With peer sampling every witness pushes to every other within about a day
(sooner in small networks), so a new witness counts at every node within
about a day, and all honest nodes see the same location. A node without a
public endpoint receives no pushes, so it can't place other witnesses and
its own verdicts stay insufficient; it still captures, requests and
relays. An observer issues a new receipt for the same witness at
the same address at most weekly, and hands back the existing one
otherwise, so receipts don't grow with sync rounds. Without an ASN table
nothing is corroborated. `quorum.trust_self_reported` exists for test networks
only.

What remains is the expensive version of the attack, and no protocol
closes it: really connecting from many networks, through proxies or rented
servers at many providers. Observations prove where a witness *pushes
gossip from*, not where it *captures from*. One server could push through
twenty cheap proxies in twenty networks and do every capture from its own
address, and it would count as twenty networks. So a corroborated location
is not proof of independent evidence. It raises the cost per fake network;
rechecks (§6.5) limit what the fake networks can decide, and real
independence comes from real, separate operators.

This establishes where a node *is* (its egress), not where each fetch came
*from*. A malicious node can still fetch through a proxy, and no protocol
fixes that, TLSNotary included. What diversity really buys is
**independent operators**, and that is what the quorum counts.

### 6.4 Watch requests and assignment

`keepword request URL` creates a signed request (interval ≥ 10 min, at most
30 days, at most 50 active per requester). It floods, and every node
computes the same rendezvous assignment:
`weight = H(epoch_seed ‖ url_key ‖ node_key)`, highest first, at most one
witness per ASN and `max_per_country` per country, `replication` in total.
The **epoch seed** is the drand quicknet beacon at the start of the UTC day,
verified offline with BLS. Beacons also travel over gossip, so nodes
without drand access can still use them. Only assigned witnesses add the
URL to their watchlist, at their next sync; the watch disappears when the
request expires or the assignment moves. Several requests for one URL share
one watch at the shortest interval any of them asks for. Without an
epoch's beacon nobody can tell who was assigned in it, so a verdict counts
no attestation from that epoch rather than every one.

A requester can withdraw a request with a signed **cancellation**
(`keepword request URL --cancel`). Nodes drop the request and remember the
cancellation until the request would have expired, so a peer re-sending it
can't revive it. Asking again for a URL you already requested replaces
your earlier request, which is how the interval changes. Captures already
made stay in the witnesses' logs.

Operators keep control of what their node fetches for others:
`network.decline_hosts` lists hosts it never captures for requests (they
are still relayed), `network.max_request_watches` caps how many URLs it
captures for the network, and rendered requests are only rendered with
`network.render_requests`, because Chromium resolves sub-resources itself,
past the node's public-address checks. Without it the node captures such
requests over plain HTTP.

Assignment is only as consistent as nodes' views of the membership. After
a few sync rounds they converge. Divergent views mean a URL briefly has
slightly different assignees, never zero.

### 6.5 Quorum, rechecks, reputation and alerts

Attestations aren't copied around the network. A node that needs a verdict
on a URL asks the witnesses assigned to it (this epoch and the last) for
their recent attestations of it (`GET /v1/attestations?url=`). Nodes do
this every quorum window for the URLs they capture for the network and the
ones they requested, and `keepword verdict` and the web UI do it on demand.

For a URL, a node gathers its own and fetched attestations, drops any
dated in the future or before their own drand beacon, and takes the latest
per witness inside a time window. The window compared is the one covering
the most distinct networks, not the one ending at the newest attestation,
so a single witness can't steer it with a false timestamp. It compares them within the
class sharing capture method and normalizer profile that spans the most
networks, groups them by
comparison hash, and counts distinct corroborated ASNs, never keys:

Only the witnesses assigned to the URL count; any other key's
attestations are ignored, so extra keys can't join a round. If they all
agree:

- **Agreed**: the group reaches `min_asns`. Members earn +1 reputation per
  URL and window.
- **Insufficient**: fewer networks than that.

**Rechecks.** If two located versions appear, the round is **disputed**,
and a vote among the assigned witnesses would let whoever holds more of
them decide. Instead, any assigned witness asks for a **recheck** (a signed
`recheck` gossip message naming up to three of the reporters' countries).
For each named country, public randomness draws `quorum.recheck_size` (5)
witnesses located there, one per network and none assigned to the URL:
the draw is keyed by the epoch's drand seed, the URL and a fixed slot of
time (the comparison window), so every node computes the same recheckers,
and neither the requester nor anyone else can retry until a draw suits
them. A drawn witness first fetches the assigned witnesses' attestations
and only captures the page again if it sees their round disputed itself
(at most `quorum.max_rechecks_per_hour` captures each): any key is assigned
to some URLs, since it only has to try enough of them, so a request alone
must not be able to spend other witnesses' captures. A version is
**confirmed** if, in a
country it was reported from, at least `quorum.recheck_quorum` (3) of the
rechecking networks saw it and they are at least three quarters of the
networks that rechecked there. Each draw is judged by the versions of the
round it was drawn for, the one ending in its slot, even if a later round
is current by the time it completes, and by each drawn witness's first
capture after that round: a witness drawn again for a later slot captures
again, maybe after the page changed, and that capture must not stand in for
the earlier one. Then:

- two or more versions confirmed: **Split**. Independent networks really
  are served different content. A split is an observation, not an
  accusation: localization, A/B tests, a rollout in progress and bot
  blocking all cause them, as does cloaking. People decide which by
  comparing the versions;
- one confirmed: **Agreed** on it, the rechecks joining its group. The
  dissenters get −3 reputation, and if the rechecks sampled their countries
  well enough to have reproduced their version and didn't, a **failed
  claim** is recorded against the network prefix (/24, /48) this node saw
  each dissenter connect from. Networks with `quorum.max_failed_claims` (5)
  in a week are left out of verdicts: keys are free, addresses aren't.
  Pages change, though, and a witness that captured a page a minute before
  its publisher edited it saw a real version. So a version other networks
  saw too, captured before any other network had seen the confirmed one,
  is the page before an edit and costs nothing. A made-up version was
  never served to anyone else; replaying an old one passes only in the
  round right after a real change;
- none confirmed: **Disputed**, and while rechecks may still arrive,
  Disputed (pending). A dissent from `min_dissent_asns` networks whose
  countries had too few witnesses to recheck also leaves the round
  Disputed rather than overruled.

A **split alert** is raised only when `quorum.split_confirmations` (3) of
the last `quorum.split_rounds` (4) settled recheck draws for the URL found
a split. Each draw is an independent sample, settled once.

What this costs an attacker: with a fifth of the network's networks,
making up a version and getting it confirmed needs most of a five-witness
draw in one country (about 1 in 300 per round), and an alert needs that
three times in four rounds; getting an honest version overruled needs the
same. Meanwhile each failed claim counts against the attacker's
addresses. What it doesn't cover: a country where one operator runs most
witnesses decides what is "seen from" that country, and a round whose
assigned witnesses are all one operator's agrees on whatever they say.

Reputation decays with a 14-day half-life, so it takes sustained agreement
to build. **Silent-edit alerts** are raised by the capturing witness. Reputation is **informational only**: it
is shown in `keepword net peers` and the web UI, but assignment and verdicts
don't use it. Each node computes its own, so using it in assignment would
break the agreement on who is assigned, and a lone honest witness that sees
a localized page would be penalized.

### 6.6 Time: drand lower bound, Bitcoin upper bound

Attestations with a beacon use the v2 encoding and embed the latest drand
round the witness had before fetching. Its BLS signature verifies offline,
proving the capture happened *after* that round. Attestations without a
beacon keep the exact v1 bytes.

For the upper bound, `keepword anchor submit` (or `serve --anchor`) sends
`SHA-256(tree-head signing bytes)` to OpenTimestamps calendars. `anchor
upgrade` fetches the Bitcoin path once it confirms and checks the block's
Merkle root with an Esplora API. The stored proof is an ordinary detached
`.ots` file (`keepword anchor export`), so the standard `ots verify` tool
also works. Bundles include the smallest confirmed anchored head covering
the attestation. `keepword verify --bundle F --esplora URL` checks it
against the chain.

### 6.7 Proof tier: TLSNotary (implemented, `crates/keepword-tlsn`)

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
   and body come from the raw response via `keepword_core::httpmsg`, so the
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
`keepword-core` and have no tlsn dependency.

```sh
keepword-tlsn serve --addr 0.0.0.0:8482                  # on the notary witness
keepword-tlsn capture https://example.org/terms \
    --verifier notary.example.net:8482 --verifier-key <hex>  # on the prover
keepword verify https://example.org/terms                # includes "tls notary"
```

### 6.8 Bundles, cosigned

Bundles are built against the largest checkpoint that the log's auditors
have cosigned, and carry those cosignatures. For a log to lie to one
verifier, it must then have lied consistently to every auditor, and any two
conflicting heads prove it. A capture is covered from the first checkpoint
after it, so within about an hour.

## 7. Storage, retention and law

Not legal advice, and German law in particular deserves a lawyer's review
before public operation. The design aims to leave room for compliance.

- **Retention levels (implemented):** `full` (headers + body + normalized
  text), `normalized` (headers + normalized text; diffs still work), or
  `none` (hashes only; edits detected but not shown). Hashes, attestations
  and the log never contain page content.
- **Erasure (implemented):** `keepword purge URL` deletes a URL's blobs
  unless another URL still references the same bytes. `--forget` also
  deletes its attestation rows. The log keeps only opaque IDs, so every
  other proof stays valid. The test suite checks exactly this.
- **Serving to peers (M2)** is off by default and separate from retention.
  A node only serves content for hosts on an opt-in allowlist, e.g. news
  outlets, government pages, and corporate ToS and privacy policies. The
  proof property survives: whoever holds the original can show it matches
  the hash.
- **Network data is pruned hourly.** Cosignatures superseded by a newer
  one from the same auditor (after two days), observations after 30 days,
  fetched attestations after 90, reputation events after 60, alerts after
  180, beacons after 7, and gossip after 7 (31 for requests). A node never
  deletes what it signed itself: its log, attestations and anchors.
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
| M2 | HTTP federation, log audits, cosigning, equivocation proofs, gossip, watch requests with assignment | **done** |
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
  exclude the live section. Since 1.1.0 they also cost a recheck draw
  every round: the assigned witnesses rarely capture the same version. A
  round whose versions are cleanly ordered in time (every capture of one
  before every capture of the other) looks like an edit, not a
  disagreement, and could skip rechecks.
- **Pages that aren't the same for everyone in a country.** Failed claims
  assume rechecks in a country can reproduce what an honest witness there
  saw. A/B tests with a small variant, and bot walls that challenge some
  addresses but not others, break that: the witness that drew the variant
  or the challenge is charged like a liar. Edits are exempt (§6.5), but
  these aren't yet. Charging only versions no other network has seen
  within the lookback would exempt them, at the price of letting two
  colluding networks dispute forever; a per-URL backoff for rechecks would
  bound that.
- **Many keys behind one server.** The per-key caps (§6.2) bound what one
  key can make a node store, and keys with nothing behind them share one
  budget. Keys whose endpoints all answer from one server still get a cap
  each, and count as working peers when gossip picks whom to talk to.
  Capping peers per network prefix of their endpoint (as failed claims are
  counted per /24 and /48) would make each such key cost an address.
- **Nodes without a public endpoint.** Nobody pushes to them, so they
  can't place other witnesses (§6.3) or compute verdicts. Recording where
  a node reached each peer's endpoint would give every node a first-hand
  location for every candidate, at the same cost per fake network as a
  push (one real address in that network).
- **Who can request watches.** Today it is any witness in the peer table,
  capped at 50 active requests each, with intervals ≥ 10 min, and each node
  captures at most `max_request_watches` URLs. Running many witnesses is
  still cheap. Per-key token buckets with tokens earned by attesting, or
  requests counted per corroborated ASN, would be better.
- **Membership consistency.** Assignment depends on each node's view of the
  witness set. Views converge through gossip, but a signed, epoch-pinned
  membership snapshot would make assignment exactly reproducible for
  auditors.
- **ASN table provenance.** Verifiers should agree on the IP→ASN table.
  Pinning its hash per epoch (and gossiping it) is straightforward, but not
  built.
- **A list of known witnesses (not planned).** Offline verifiers can't
  tell independent cosigners from keys one operator controls, and
  corroborated location can't tell independent operators from one operator
  behind many proxies. A curated list of operators, like Certificate
  Transparency's log list, would fix that, but it would also make the
  project a gatekeeper, and the network is meant to grow without one.
  Rechecks (§6.5) bound what extra keys and networks buy instead.
- **Bundles that carry the verdict.** A bundle holds one witness's
  attestation. A second format carrying the other witnesses' matching
  attestations with their inclusion proofs would let the agreement itself
  be verified offline.
