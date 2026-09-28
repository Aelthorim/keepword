//! Federation with other witnesses over HTTP (docs/DESIGN.md §6).
//!
//! Each sync round, for every peer with a public endpoint, a node:
//!
//! 1. refreshes the peer's descriptor and learns the peers it knows;
//! 2. fetches its signed tree head and any new leaf IDs, recomputes the root
//!    over the whole mirrored log and rejects anything that doesn't match,
//!    so a peer can never rewrite history it has already shown us;
//! 3. fetches the new attestations and verifies each one;
//! 4. cosigns the head;
//! 5. pulls the peer's gossip outbox and pushes its own, receiving an
//!    observation receipt of its own address in return.
//!
//! Gossip messages are self-authenticating, so they flood through any peer.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use witness_core::assign::{self, Candidate, DiversityPolicy};
use witness_core::beacon::{self, epoch_of};
use witness_core::net::{
    Alert, AlertKind, Cosignature, Descriptor, Gossip, Observation, PushEnvelope, WatchCancel,
    WatchRequest, payload_digest,
};
use witness_core::statement::Signed;
use witness_core::{Digest, SignedAttestation, SignedTreeHead, WitnessKey, merkle, now_ms, target};
use witness_store::net::{Peer, RequestWatch};

use crate::Node;
use crate::httpc::{join, status_of};
use crate::vantage::{self, Location};

/// Longest a watch request may run.
pub const MAX_REQUEST_MS: i64 = 30 * 86_400_000;
/// Shortest interval a watch request may ask for.
pub const MIN_REQUEST_EVERY_SECS: u64 = 600;
/// Allowed clock skew for timestamps in messages.
pub const SKEW_MS: i64 = 5 * 60_000;
/// Descriptors older than this are stale; nodes re-issue theirs every run
/// and re-announce it every sync.
const DESCRIPTOR_TTL_MS: i64 = 7 * 86_400_000;
const DESCRIPTOR_REFRESH_MS: i64 = 86_400_000;
/// Beacons older than this aren't needed for assignment or captures, and
/// accepting all of drand's history would let anyone flood the store.
const BEACON_MAX_AGE_MS: i64 = 3 * 86_400_000;
/// Peers synced at once.
const SYNC_CONCURRENCY: usize = 8;
/// How long to wait before retrying a peer whose last sync failed.
const RETRY_MS: i64 = 10 * 60_000;
const PAGE: usize = 1000;
const GOSSIP_PAGE: u32 = 500;

#[derive(Debug, Serialize, Deserialize)]
pub struct GossipPage {
    #[serde(deserialize_with = "skip_unknown")]
    pub messages: Vec<(i64, Gossip)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushRequest {
    pub envelope: Signed<PushEnvelope>,
    #[serde(deserialize_with = "skip_unknown")]
    pub messages: Vec<Gossip>,
}

/// Message kinds from newer versions are skipped instead of failing the
/// whole page, so nodes can be upgraded one at a time.
fn skip_unknown<'de, D, T>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let raw = Vec::<serde_json::Value>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushResponse {
    pub accepted: usize,
    /// The receiver's receipt of where this push came from.
    pub observation: Option<Signed<Observation>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdList {
    pub ids: Vec<Digest>,
}

#[derive(Debug, Default, Serialize)]
pub struct SyncReport {
    pub peers: usize,
    pub synced: usize,
    pub new_leaves: u64,
    pub new_attestations: usize,
    pub gossip_in: usize,
    pub gossip_out: usize,
    pub errors: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct PeerStats {
    new_leaves: u64,
    new_attestations: usize,
    gossip_in: usize,
    gossip_out: usize,
}

impl Node {
    /// This node's signed descriptor for the current run.
    pub fn build_descriptor(&self) -> Result<Signed<Descriptor>> {
        Ok(Signed::sign(
            Descriptor {
                key: self.key.public(),
                endpoint: self.config.network.endpoint.clone(),
                vantage: self.config.vantage(),
                issued_at_ms: now_ms(),
                software: concat!("witness/", env!("CARGO_PKG_VERSION")).into(),
            },
            &self.key,
        )?)
    }

    /// This node's descriptor, re-signed once a day: peers ignore
    /// descriptors older than `DESCRIPTOR_TTL_MS`, and a long-running node
    /// must not age out of their tables.
    pub fn descriptor(&self) -> Signed<Descriptor> {
        let mut d = self.descriptor.lock().unwrap_or_else(|p| p.into_inner());
        if now_ms() - d.body.issued_at_ms > DESCRIPTOR_REFRESH_MS {
            if let Ok(fresh) = self.build_descriptor() {
                *d = fresh;
            }
        }
        d.clone()
    }

    /// Add a message this node created to its outbox.
    pub fn publish(&self, g: Gossip) -> Result<bool> {
        Ok(self.store.gossip_insert(&g, now_ms())?.is_some())
    }

    /// Validate and store one gossip message; returns whether it was new and
    /// accepted (and so will be forwarded).
    pub fn ingest(&self, g: Gossip) -> Result<bool> {
        let now = now_ms();
        if self.store.gossip_seen(&g.id())? {
            return Ok(false);
        }
        if g.verify().is_err() {
            return Ok(false);
        }
        let me = self.key.public();
        // Keys are free, so everything but descriptors must come from a
        // witness in the peer table, whose size is capped. Otherwise anyone
        // could flood alerts, requests and receipts from throwaway keys.
        let signer = match &g {
            Gossip::Descriptor(_) | Gossip::Beacon(_) => None,
            Gossip::Request(r) => Some(r.body.requester),
            Gossip::Cancel(c) => Some(c.body.requester),
            Gossip::TreeHead(h) => Some(h.head.log),
            Gossip::Cosignature(c) => Some(c.body.cosigner),
            Gossip::Observation(o) => Some(o.body.observer),
            Gossip::Alert(a) => Some(a.body.issuer),
            Gossip::Equivocation { a, .. } => Some(a.head.log),
            Gossip::TlsnReceipt(r) => Some(r.body.verifier),
        };
        if let Some(k) = signer {
            if k != me && self.store.peer(&k)?.is_none() {
                return Ok(false);
            }
        }
        let accept = match &g {
            Gossip::Descriptor(d) => self.accept_descriptor(d, now)?,
            Gossip::Request(r) => self.accept_request(r, now)?,
            Gossip::Cancel(c) => self.accept_cancel(c, now)?,
            Gossip::TreeHead(h) => {
                if let Some(p) = self.store.peer(&h.head.log)? {
                    if let Some(known) = &p.head {
                        if known.is_equivocation_with(h) {
                            self.record_equivocation(known, h)?;
                        }
                    }
                }
                true
            }
            Gossip::Cosignature(c) => {
                self.store.cosig_insert(c)?;
                true
            }
            Gossip::Observation(o) => {
                if o.body.observed_at_ms > now + SKEW_MS {
                    false
                } else {
                    self.store.observation_upsert(o)?;
                    true
                }
            }
            Gossip::Alert(a) => {
                self.store.alert_insert(a)?;
                true
            }
            Gossip::Equivocation { a, b } => {
                self.store.equivocation_insert(a, b, now)?;
                true
            }
            Gossip::Beacon(b) => {
                let t = b.time_ms();
                if t > now + SKEW_MS || t < now - BEACON_MAX_AGE_MS {
                    false
                } else {
                    self.store.beacon_insert(b)?;
                    true
                }
            }
            // Receipts travel for transparency; provers store their own.
            Gossip::TlsnReceipt(r) => r.body.verified_at_ms <= now + SKEW_MS,
        };
        if accept {
            self.store.gossip_insert(&g, now)?;
        }
        Ok(accept)
    }

    fn accept_descriptor(&self, d: &Signed<Descriptor>, now: i64) -> Result<bool> {
        let b = &d.body;
        let endpoint_ok = b.endpoint.as_deref().is_none_or(|e| {
            url::Url::parse(e).is_ok_and(|u| u.scheme() == "http" || u.scheme() == "https")
        });
        if b.issued_at_ms > now + SKEW_MS
            || b.issued_at_ms < now - DESCRIPTOR_TTL_MS
            || !endpoint_ok
        {
            return Ok(false);
        }
        if b.key == self.key.public() {
            return Ok(true);
        }
        if self.store.peer(&b.key)?.is_none()
            && self.store.peers()?.len() >= self.config.network.max_peers
        {
            // Only a reachable witness is worth evicting a dead one for.
            if b.endpoint.is_none() || !self.store.peer_evict_one(now)? {
                return Ok(false);
            }
        }
        self.store.peer_upsert(d, now)?;
        Ok(true)
    }

    fn accept_request(&self, r: &Signed<WatchRequest>, now: i64) -> Result<bool> {
        let b = &r.body;
        let canonical = match target::canonical_url(&b.url) {
            Ok(u) => u,
            Err(_) => return Ok(false),
        };
        let ok = canonical.as_str() == b.url
            && b.every_secs >= MIN_REQUEST_EVERY_SECS
            && b.issued_at_ms <= now + SKEW_MS
            && b.expires_at_ms > now
            && b.expires_at_ms - b.issued_at_ms <= MAX_REQUEST_MS
            && !self.store.request_cancelled(&r.id(), &b.requester)?
            && self.store.requests_active_by(&b.requester, now)?
                < self.config.network.max_requests_per_requester;
        if !ok {
            return Ok(false);
        }
        self.store.request_insert(r)?;
        // Take it on right away if this node is assigned.
        if let Ok((seed, _)) = self.epoch_seed_cached(epoch_of(now)) {
            self.apply_requests(&seed, now)?;
        }
        Ok(true)
    }

    fn accept_cancel(&self, c: &Signed<WatchCancel>, now: i64) -> Result<bool> {
        let b = &c.body;
        if b.issued_at_ms > now + SKEW_MS {
            return Ok(false);
        }
        // Keep the cancellation as long as the request could still be live.
        let expires = match self.store.request(&b.request)? {
            Some(r) if r.body.requester != b.requester => return Ok(false),
            Some(r) => r.body.expires_at_ms,
            None => b.issued_at_ms + MAX_REQUEST_MS,
        };
        if !self
            .store
            .request_cancel(&b.request, &b.requester, expires)?
        {
            return Ok(false);
        }
        if let Ok((seed, _)) = self.epoch_seed_cached(epoch_of(now)) {
            self.apply_requests(&seed, now)?;
        }
        Ok(true)
    }

    fn record_equivocation(&self, a: &SignedTreeHead, b: &SignedTreeHead) -> Result<()> {
        if self.store.equivocation_insert(a, b, now_ms())? {
            self.publish(Gossip::Equivocation {
                a: a.clone(),
                b: b.clone(),
            })?;
            let alert = Signed::sign(
                Alert {
                    kind: AlertKind::Equivocation,
                    url: None,
                    summary: format!(
                        "witness {} signed two different logs of size {}",
                        a.head.log.short(),
                        a.head.size
                    ),
                    evidence: vec![a.head.root, b.head.root],
                    issued_at_ms: now_ms(),
                    issuer: self.key.public(),
                },
                &self.key,
            )?;
            self.store.alert_insert(&alert)?;
            self.publish(Gossip::Alert(alert))?;
        }
        Ok(())
    }

    /// Where a witness is, as far as this node will trust: corroborated by
    /// observation receipts, or self-reported if the config allows it.
    pub fn location_of(&self, key: &WitnessKey, now: i64) -> Result<Option<Location>> {
        if let Some(db) = &self.asn_db {
            let obs = self.store.observations_of(key, now - 30 * 86_400_000)?;
            if let Some(loc) = vantage::corroborate(key, &obs, db, self.config.quorum.min_observers)
            {
                return Ok(Some(loc));
            }
        }
        if self.config.quorum.trust_self_reported {
            let v = if *key == self.key.public() {
                self.config.vantage()
            } else {
                match self.store.peer(key)? {
                    Some(p) => p.descriptor.body.vantage,
                    None => return Ok(None),
                }
            };
            if let Some(asn) = v.asn {
                return Ok(Some(Location {
                    asn,
                    country: v.country.unwrap_or_else(|| "??".into()),
                    observers: 0,
                }));
            }
        }
        Ok(None)
    }

    /// Witnesses eligible for assignment: this node and recently seen,
    /// reachable, non-equivocating peers with a known location.
    pub fn candidates(&self, now: i64) -> Result<Vec<Candidate>> {
        let bad = self.store.equivocating_logs()?;
        let mut keys = vec![self.key.public()];
        for p in self.store.peers()? {
            if p.endpoint.is_some()
                && p.descriptor.body.issued_at_ms >= now - DESCRIPTOR_TTL_MS
                && !bad.contains(&p.key)
            {
                keys.push(p.key);
            }
        }
        let mut out = Vec::new();
        for k in keys {
            if let Some(loc) = self.location_of(&k, now)? {
                out.push(Candidate {
                    key: k,
                    asn: loc.asn,
                    country: loc.country,
                });
            }
        }
        Ok(out)
    }

    pub fn policy(&self) -> DiversityPolicy {
        DiversityPolicy {
            k: self.config.network.replication,
            max_per_asn: 1,
            max_per_country: self.config.network.max_per_country,
        }
    }

    pub fn assigned(&self, seed: &Digest, url: &url::Url, now: i64) -> Result<Vec<Candidate>> {
        Ok(self.assigned_among(seed, url, &self.candidates(now)?))
    }

    fn assigned_among(&self, seed: &Digest, url: &url::Url, cands: &[Candidate]) -> Vec<Candidate> {
        assign::assign(seed, &target::url_key(url), cands, &self.policy())
    }

    /// Seed for an epoch from stored beacons only (no network). The bool is
    /// false when falling back to the insecure seed.
    pub fn epoch_seed_cached(&self, epoch: u64) -> Result<(Digest, bool)> {
        match self.store.beacon(beacon::epoch_round(epoch))? {
            Some(b) => Ok((beacon::epoch_seed(epoch, Some(&b)), true)),
            None if self.config.beacon.allow_insecure_seed => {
                Ok((beacon::epoch_seed(epoch, None), false))
            }
            None => bail!("no drand beacon for epoch {epoch} yet"),
        }
    }

    /// Re-evaluate which active requests this node is assigned to.
    pub async fn reconcile_requests(&self) -> Result<usize> {
        let now = now_ms();
        let seed = match self.epoch_seed(epoch_of(now)).await {
            Ok((s, _)) => s,
            Err(_) => return Ok(0),
        };
        self.store.requests_prune(now)?;
        self.apply_requests(&seed, now)
    }

    /// Set this node's request-driven watches to exactly the URLs it is
    /// assigned for, each at the shortest interval any active request asks
    /// for. Returns how many URLs it watches for the network.
    fn apply_requests(&self, seed: &Digest, now: i64) -> Result<usize> {
        let me = self.key.public();
        let cands = self.candidates(now)?;
        let net = &self.config.network;
        let mut by_url: std::collections::BTreeMap<String, RequestWatch> = Default::default();
        let mut not_mine = HashSet::new();
        let mut requests = self.store.requests_active(now)?;
        // Oldest first, so a flood of new requests can't displace them.
        requests.sort_by_key(|r| r.body.issued_at_ms);
        for r in requests {
            let Ok(url) = target::canonical_url(&r.body.url) else {
                continue;
            };
            if crate::host_listed(&net.decline_hosts, &url) {
                continue;
            }
            let render = r.body.render && net.render_requests;
            if let Some(w) = by_url.get_mut(url.as_str()) {
                w.every_secs = w.every_secs.min(r.body.every_secs);
                w.expires_at_ms = w.expires_at_ms.max(r.body.expires_at_ms);
                w.render |= render;
                continue;
            }
            if by_url.len() >= net.max_request_watches || not_mine.contains(url.as_str()) {
                continue;
            }
            if self
                .assigned_among(seed, &url, &cands)
                .iter()
                .any(|c| c.key == me)
            {
                by_url.insert(
                    url.to_string(),
                    RequestWatch {
                        url: url.to_string(),
                        every_secs: r.body.every_secs,
                        render,
                        request: r.id(),
                        expires_at_ms: r.body.expires_at_ms,
                    },
                );
            } else {
                not_mine.insert(url.to_string());
            }
        }
        for w in by_url.values() {
            self.store.watch_for_request(w, now)?;
        }
        let keep: Vec<String> = by_url.into_keys().collect();
        self.store.watch_drop_requested(&keep, now)?;
        Ok(keep.len())
    }

    /// Create and publish a watch request.
    pub fn request_watch(
        &self,
        url: &str,
        every_secs: u64,
        duration_ms: i64,
        render: bool,
    ) -> Result<Signed<WatchRequest>> {
        let url = target::canonical_url(url)?;
        if every_secs < MIN_REQUEST_EVERY_SECS {
            bail!(
                "the network accepts intervals of at least {} minutes",
                MIN_REQUEST_EVERY_SECS / 60
            );
        }
        if duration_ms > MAX_REQUEST_MS {
            bail!("requests can run for at most 30 days");
        }
        let now = now_ms();
        let r = Signed::sign(
            WatchRequest {
                url: url.to_string(),
                every_secs,
                render,
                requester: self.key.public(),
                issued_at_ms: now,
                expires_at_ms: now + duration_ms,
            },
            &self.key,
        )?;
        if !self.ingest(Gossip::Request(r.clone()))? {
            bail!("request rejected (too many active requests?)");
        }
        Ok(r)
    }

    /// Withdraw this node's active requests for a URL. Returns how many.
    pub fn cancel_requests(&self, url: &str) -> Result<usize> {
        let url = target::canonical_url(url)?;
        let now = now_ms();
        let mut n = 0;
        for r in self.store.requests_by(&self.key.public(), now)? {
            if r.body.url != url.as_str() {
                continue;
            }
            let c = Signed::sign(
                WatchCancel {
                    request: r.id(),
                    requester: self.key.public(),
                    issued_at_ms: now,
                },
                &self.key,
            )?;
            if self.ingest(Gossip::Cancel(c))? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Fetch a peer's descriptor from its endpoint and add it.
    pub async fn add_peer(&self, endpoint: &str) -> Result<Signed<Descriptor>> {
        let d: Signed<Descriptor> = self.net.get_json(&join(endpoint, "/v1/descriptor")).await?;
        d.verify().context("peer descriptor signature")?;
        if d.body.key == self.key.public() {
            bail!("{endpoint} is this node");
        }
        if d.body.endpoint.is_none() {
            bail!("{endpoint} does not advertise a public endpoint");
        }
        self.store.peer_upsert(&d, now_ms())?;
        self.store
            .gossip_insert(&Gossip::Descriptor(d.clone()), now_ms())?;
        Ok(d)
    }

    /// One federation round with every reachable peer.
    pub async fn sync(&self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        self.publish(Gossip::Descriptor(self.descriptor()))?;
        if let Some(h) = self.store.latest_tree_head()? {
            self.publish(Gossip::TreeHead(h))?;
        }
        let known: HashSet<String> = self
            .store
            .peers()?
            .into_iter()
            .filter_map(|p| p.endpoint)
            .map(|e| e.trim_end_matches('/').to_string())
            .collect();
        for boot in &self.config.network.peers {
            if !known.contains(boot.trim_end_matches('/')) {
                if let Err(e) = self.add_peer(boot).await {
                    report.errors.push((boot.clone(), format!("{e:#}")));
                }
            }
        }
        let bad = self.store.equivocating_logs()?;
        let now = now_ms();
        let due: Vec<Peer> = self
            .store
            .peers()?
            .into_iter()
            .filter(|p| p.endpoint.is_some() && !bad.contains(&p.key))
            // Back off from peers whose last attempt failed.
            .filter(|p| p.last_error.is_none() || p.last_sync.is_none_or(|t| now - t >= RETRY_MS))
            .collect();
        report.peers = due.len();
        use futures::StreamExt;
        let mut results = futures::stream::iter(due)
            .map(|peer| async move {
                let r = self.sync_peer(&peer).await;
                (peer, r)
            })
            .buffer_unordered(SYNC_CONCURRENCY);
        while let Some((peer, r)) = results.next().await {
            match r {
                Ok(s) => {
                    report.synced += 1;
                    report.new_leaves += s.new_leaves;
                    report.new_attestations += s.new_attestations;
                    report.gossip_in += s.gossip_in;
                    report.gossip_out += s.gossip_out;
                    self.store.peer_mark_sync(&peer.key, now_ms(), None)?;
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    self.store.peer_mark_sync(&peer.key, now_ms(), Some(&msg))?;
                    report.errors.push((peer.key.short(), msg));
                }
            }
        }
        self.reconcile_requests().await?;
        self.review_verdicts()?;
        let now = now_ms();
        self.store
            .gossip_prune(now - 7 * 86_400_000, now - MAX_REQUEST_MS - 86_400_000)?;
        Ok(report)
    }

    async fn sync_peer(&self, peer: &Peer) -> Result<PeerStats> {
        let ep = peer
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow!("peer has no endpoint"))?;
        let mut stats = PeerStats::default();

        let d: Signed<Descriptor> = self.net.get_json(&join(ep, "/v1/descriptor")).await?;
        d.verify().context("descriptor signature")?;
        if d.body.key != peer.key {
            bail!("endpoint now serves a different witness key");
        }
        if self.ingest(Gossip::Descriptor(d))? {
            stats.gossip_in += 1;
        }

        let others: Vec<Signed<Descriptor>> = self.net.get_json(&join(ep, "/v1/peers")).await?;
        for o in others.into_iter().take(self.config.network.max_peers) {
            if self.ingest(Gossip::Descriptor(o))? {
                stats.gossip_in += 1;
            }
        }

        self.mirror_log(peer, ep, &mut stats).await?;

        // Pull their outbox.
        let mut after = peer.pulled_seq;
        for _ in 0..20 {
            let page: GossipPage = self
                .net
                .get_json(&join(
                    ep,
                    &format!("/v1/gossip?after={after}&limit={GOSSIP_PAGE}"),
                ))
                .await?;
            let n = page.messages.len();
            for (seq, g) in page.messages {
                after = after.max(seq);
                if self.ingest(g)? {
                    stats.gossip_in += 1;
                }
            }
            if n < GOSSIP_PAGE as usize {
                break;
            }
        }
        self.store.peer_set_cursors(&peer.key, None, Some(after))?;

        // Push ours.
        let mut sent_to = peer.pushed_seq;
        for _ in 0..20 {
            let batch = self.store.gossip_since(sent_to, GOSSIP_PAGE)?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().map(|(s, _)| *s).unwrap_or(sent_to);
            let messages: Vec<Gossip> = batch.into_iter().map(|(_, g)| g).collect();
            let n = messages.len();
            let envelope = Signed::sign(
                PushEnvelope {
                    from: self.key.public(),
                    to: peer.key,
                    sent_at_ms: now_ms(),
                    payload: payload_digest(&messages),
                },
                &self.key,
            )?;
            let resp: PushResponse = self
                .net
                .post_json(&join(ep, "/v1/gossip"), &PushRequest { envelope, messages })
                .await?;
            stats.gossip_out += resp.accepted;
            if let Some(o) = resp.observation {
                if o.body.subject == self.key.public() && o.body.observer == peer.key {
                    self.ingest(Gossip::Observation(o))?;
                }
            }
            sent_to = last;
            self.store
                .peer_set_cursors(&peer.key, Some(sent_to), None)?;
            if n < GOSSIP_PAGE as usize {
                break;
            }
        }
        Ok(stats)
    }

    /// Mirror a peer's log and attestations, verifying the tree head covers
    /// exactly the leaves we hold plus the new ones; then cosign it.
    async fn mirror_log(&self, peer: &Peer, ep: &str, stats: &mut PeerStats) -> Result<()> {
        let head: SignedTreeHead = match self.net.get_json(&join(ep, "/v1/log/head")).await {
            Ok(h) => h,
            Err(e) if status_of(&e) == Some(404) => return Ok(()),
            Err(e) => return Err(e),
        };
        head.verify().context("tree head signature")?;
        if head.head.log != peer.key {
            bail!("tree head is for a different log");
        }
        let mut ids = self.store.peer_leaf_ids(&peer.key)?;
        let have = ids.len() as u64;
        if let Some(known) = &peer.head {
            if known.is_equivocation_with(&head) {
                self.record_equivocation(known, &head)?;
                bail!(
                    "peer equivocated: two different logs of size {}",
                    head.head.size
                );
            }
            if head.head.size < known.head.size {
                bail!(
                    "peer's log shrank from {} to {}",
                    known.head.size,
                    head.head.size
                );
            }
        }
        if head.head.size < have {
            bail!("peer's log is shorter than what it showed us before");
        }
        let mut new_ids = Vec::new();
        let mut start = have;
        while start < head.head.size {
            let end = (start + PAGE as u64).min(head.head.size);
            let page: Vec<Digest> = self
                .net
                .get_json(&join(
                    ep,
                    &format!("/v1/log/leaves?start={start}&end={end}"),
                ))
                .await?;
            if page.is_empty() || page.len() as u64 > end - start {
                bail!("bad leaf page {start}..{end}");
            }
            start += page.len() as u64;
            new_ids.extend(page);
        }
        ids.extend_from_slice(&new_ids);
        let leaves: Vec<Digest> = ids
            .iter()
            .map(|id| merkle::leaf_hash(id.as_bytes()))
            .collect();
        if merkle::root(&leaves) != head.head.root {
            bail!(
                "tree head does not match the log's leaves; the peer rewrote history or served bad leaves"
            );
        }
        if !new_ids.is_empty() {
            self.store.peer_extend_log(&peer.key, &new_ids, &head)?;
            stats.new_leaves = new_ids.len() as u64;
        } else if peer.head.as_ref() != Some(&head) {
            self.store.peer_extend_log(&peer.key, &[], &head)?;
        }

        for chunk in new_ids.chunks(200) {
            let wanted: HashSet<Digest> = chunk.iter().copied().collect();
            let got: Vec<SignedAttestation> = self
                .net
                .post_json(
                    &join(ep, "/v1/attestations"),
                    &IdList {
                        ids: chunk.to_vec(),
                    },
                )
                .await?;
            for sa in got {
                if sa.attestation.witness == peer.key
                    && sa.verify().is_ok()
                    && wanted.contains(&sa.id())
                    && self.store.foreign_insert(&sa)?
                {
                    stats.new_attestations += 1;
                }
            }
        }

        if head.head.size > 0 {
            let c = Signed::sign(
                Cosignature {
                    log: head.head.log,
                    size: head.head.size,
                    root: head.head.root,
                    timestamp_ms: now_ms(),
                    cosigner: self.key.public(),
                },
                &self.key,
            )?;
            if self.store.cosig_insert(&c)? {
                self.publish(Gossip::Cosignature(c))?;
            }
        }
        Ok(())
    }

    /// Handle a push: ingest the messages and, if the envelope proves who
    /// sent them, return a receipt of the address they came from.
    pub fn receive_push(&self, req: PushRequest, from_ip: IpAddr) -> Result<PushResponse> {
        let now = now_ms();
        let env = &req.envelope;
        let authentic = env.verify().is_ok()
            && env.body.to == self.key.public()
            && env.body.from != self.key.public()
            && (env.body.sent_at_ms - now).abs() <= SKEW_MS
            && env.body.payload == payload_digest(&req.messages)
            && self.fresh_envelope(env.id(), now);
        let mut accepted = 0;
        for g in req.messages {
            if self.ingest(g)? {
                accepted += 1;
            }
        }
        let observation = if authentic {
            let o = Signed::sign(
                Observation {
                    subject: env.body.from,
                    ip: from_ip,
                    observed_at_ms: now,
                    observer: self.key.public(),
                },
                &self.key,
            )?;
            self.ingest(Gossip::Observation(o.clone()))?;
            Some(o)
        } else {
            None
        };
        Ok(PushResponse {
            accepted,
            observation,
        })
    }

    /// Replay protection for push envelopes.
    fn fresh_envelope(&self, id: Digest, now: i64) -> bool {
        let mut seen = self
            .seen_envelopes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, t| now - *t <= 2 * SKEW_MS);
        seen.insert(id, now).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_resigned_before_peers_drop_it() {
        let t = tempfile::tempdir().unwrap();
        Node::init(t.path(), &crate::config::Config::default()).unwrap();
        let node = Node::open(t.path()).unwrap();
        let mut old = node.descriptor();
        old.body.issued_at_ms = now_ms() - 2 * DESCRIPTOR_REFRESH_MS;
        *node.descriptor.lock().unwrap() = Signed::sign(old.body, &node.key).unwrap();
        let d = node.descriptor();
        assert!(now_ms() - d.body.issued_at_ms < 60_000);
        d.verify().unwrap();
    }

    #[test]
    fn unknown_message_kinds_are_skipped() {
        let json = r#"{"messages": [
            [1, {"type": "from_the_future", "x": 1}],
            [2, {"type": "beacon", "round": 1, "signature": "00"}]
        ]}"#;
        let page: GossipPage = serde_json::from_str(json).unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].0, 2);
    }

    #[test]
    fn host_lists_match_subdomains_only() {
        let hosts = vec!["example.org".to_string(), ".news.example".to_string()];
        let m = |u: &str| crate::host_listed(&hosts, &url::Url::parse(u).unwrap());
        assert!(m("https://example.org/a"));
        assert!(m("https://www.Example.org/a"));
        assert!(m("https://news.example/"));
        assert!(m("https://a.news.example/"));
        assert!(!m("https://notexample.org/"));
        assert!(!m("https://example.org.evil.test/"));
        assert!(!crate::host_listed(
            &[String::new()],
            &url::Url::parse("https://a.b/").unwrap()
        ));
    }
}
