//! Quorum verdicts across witnesses, rechecks of disputed rounds,
//! reputation and alerts (docs/DESIGN.md §6.5).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

use anyhow::Result;
use keepword_core::assign::Candidate;
use keepword_core::net::{Alert, AlertKind, Gossip};
use keepword_core::quorum::{self, Evaluation, Group, QuorumPolicy, RecheckResult, Verdict};
use keepword_core::statement::Signed;
use keepword_core::{Attestation, Digest, SignedAttestation, WitnessKey, now_ms};
use serde::Serialize;

use crate::Node;
use crate::vantage::Location;

/// How far back verdicts look.
pub const LOOKBACK_MS: i64 = 7 * 86_400_000;

/// How long failed recheck claims count against a network.
pub const FAILED_CLAIMS_MS: i64 = 7 * 86_400_000;

#[derive(Debug, Serialize)]
pub struct VerdictView {
    pub url: String,
    pub evaluation: Evaluation,
    /// Witnesses compared (latest attestation of each inside the window).
    pub considered: usize,
    /// Recheck captures counted for a disputed round.
    pub rechecks: usize,
    /// Every witness involved and where it is, if known.
    pub witnesses: Vec<(String, Option<crate::vantage::Location>)>,
}

/// One version of a round: what some of its witnesses saw.
#[derive(Clone, Debug)]
pub struct Version {
    pub hash: Digest,
    /// Countries it was reported from.
    pub countries: BTreeSet<String>,
    /// The witnesses that reported it, and their networks.
    pub reporters: Vec<WitnessKey>,
    pub asns: BTreeSet<u32>,
    /// When the last of them captured it in the round.
    pub seen_at_ms: i64,
}

/// A round in which the assigned witnesses disagreed.
#[derive(Debug)]
pub struct Disagreement {
    /// Start of the round's slot (see `Node::round_slot`).
    pub slot: i64,
    /// Each version, most networks first.
    pub versions: Vec<Version>,
    /// Versions reproduced by the recent draws of rounds with these same
    /// versions, together.
    pub confirmed: BTreeSet<Digest>,
    /// Rechecks may still change the verdict.
    pub pending: bool,
}

/// The rechecks of one disputed slot.
#[derive(Debug)]
pub struct Draw {
    pub slot: i64,
    /// The versions of the round it rechecks, the one ending in its slot:
    /// a draw is judged by what it was drawn to recheck, not by whatever
    /// round is current when it completes.
    pub versions: Vec<Version>,
    pub results: Vec<(WitnessKey, RecheckResult)>,
    /// Every drawn witness reported, or the time for it is over.
    pub complete: bool,
}

/// The recent recheck draws of a URL.
#[derive(Debug, Default)]
pub struct Rechecks {
    /// Draws of rounds that had at least two versions.
    pub draws: Vec<Draw>,
    /// When each version was captured in the lookback, and from which
    /// network (located witnesses that aren't discredited).
    sightings: HashMap<Digest, Vec<(i64, u32)>>,
}

impl Rechecks {
    /// Whether `v` is what the page served before it changed: other
    /// networks saw it too, and its reporters captured it before any other
    /// network had captured one of the `confirmed` versions. A made-up
    /// version was never served to anyone else, and a liar replaying an old
    /// one can only pass for honest in the round right after a real change.
    fn predates(&self, v: &Version, confirmed: &BTreeSet<Digest>) -> bool {
        let elsewhere = |h: &Digest| {
            self.sightings
                .get(h)
                .into_iter()
                .flatten()
                .filter(|(_, asn)| !v.asns.contains(asn))
        };
        elsewhere(&v.hash).next().is_some()
            && confirmed
                .iter()
                .flat_map(elsewhere)
                .map(|(t, _)| *t)
                .min()
                .is_none_or(|first| v.seen_at_ms < first)
    }
}

/// What this node knows about one URL: its attestations with a believable
/// time, where their witnesses are, and which of them count in rounds.
pub(crate) struct Rounds {
    url: url::Url,
    policy: QuorumPolicy,
    /// Length of a round's slot (`Node::window_ms`).
    slot_ms: i64,
    atts: Vec<SignedAttestation>,
    locs: HashMap<WitnessKey, Option<Location>>,
    discredited: HashSet<WitnessKey>,
    /// The attestations of assigned witnesses that aren't discredited.
    base: Vec<SignedAttestation>,
    cands: Arc<Vec<Candidate>>,
}

impl Rounds {
    fn location(&self, k: &WitnessKey) -> Option<&Location> {
        self.locs.get(k).and_then(|l| l.as_ref())
    }

    /// The round compared among the windows that end in `ends`.
    fn evaluate(&self, ends: Range<i64>) -> Evaluation {
        quorum::evaluate_ending_in(
            self.url.as_str(),
            &self.base,
            |a: &Attestation| self.location(&a.witness).map(|l| l.asn),
            &self.policy,
            ends,
        )
    }

    /// The versions of the round of the slot starting at `slot`, and when
    /// its window ended.
    pub(crate) fn round_at(&self, slot: i64) -> (Vec<Version>, Option<i64>) {
        let e = self.evaluate(slot..slot + self.slot_ms);
        (self.versions(&e), e.window_end_ms)
    }

    /// A round's versions seen by located witnesses, most networks first.
    fn versions(&self, e: &Evaluation) -> Vec<Version> {
        let Some(end) = e.window_end_ms else {
            return vec![];
        };
        e.groups
            .iter()
            .filter(|g| !g.asns.is_empty())
            .map(|g| Version {
                hash: g.hash,
                countries: g
                    .witnesses
                    .iter()
                    .filter_map(|k| self.location(k))
                    .map(|l| l.country.clone())
                    .collect(),
                reporters: g.witnesses.clone(),
                asns: g.asns.clone(),
                seen_at_ms: self
                    .base
                    .iter()
                    .map(|a| &a.attestation)
                    .filter(|a| {
                        g.witnesses.contains(&a.witness)
                            && a.comparison_hash() == g.hash
                            && a.fetched_at_ms <= end
                            && end - a.fetched_at_ms <= self.policy.window_ms
                    })
                    .map(|a| a.fetched_at_ms)
                    .max()
                    .unwrap_or(end),
            })
            .collect()
    }

    fn sightings(&self) -> HashMap<Digest, Vec<(i64, u32)>> {
        let mut out: HashMap<Digest, Vec<(i64, u32)>> = HashMap::new();
        for a in self.atts.iter().map(|a| &a.attestation) {
            if self.discredited.contains(&a.witness) {
                continue;
            }
            if let Some(l) = self.location(&a.witness) {
                out.entry(a.comparison_hash())
                    .or_default()
                    .push((a.fetched_at_ms, l.asn));
            }
        }
        out
    }
}

fn hashes(vs: &[Version]) -> BTreeSet<Digest> {
    vs.iter().map(|v| v.hash).collect()
}

impl Node {
    pub fn quorum_policy(&self) -> QuorumPolicy {
        let q = &self.config.quorum;
        QuorumPolicy {
            window_ms: q.window_secs as i64 * 1000,
            min_asns: q.min_asns,
            min_dissent_asns: q.min_dissent_asns,
        }
    }

    /// All attestations of `url` this node knows: its own and fetched ones.
    pub fn attestations_for(&self, url: &str, since_ms: i64) -> Result<Vec<SignedAttestation>> {
        let mut v: Vec<SignedAttestation> = self
            .store
            .history(url)?
            .into_iter()
            .filter(|r| r.signed.attestation.fetched_at_ms >= since_ms)
            .map(|r| r.signed)
            .collect();
        v.extend(self.store.foreign_for_url(url, since_ms)?);
        Ok(v)
    }

    pub fn verdict(&self, url: &str) -> Result<VerdictView> {
        Ok(self.resolve_verdict(url)?.0)
    }

    /// The verdict on `url`, the disagreement behind it, if any, and the
    /// recent recheck draws.
    ///
    /// Only the witnesses public randomness assigned to the URL are
    /// compared, minus networks whose claims keep failing rechecks. If they
    /// disagree, the verdict comes from rechecks (see `recheck.rs`):
    /// versions that witnesses drawn at random didn't reproduce don't count.
    pub fn resolve_verdict(
        &self,
        url: &str,
    ) -> Result<(VerdictView, Option<Disagreement>, Rechecks)> {
        let now = now_ms();
        let r = self.rounds(url, now)?;
        let policy = r.policy;
        let mut evaluation = r.evaluate(i64::MIN..i64::MAX);
        let mut involved: HashSet<WitnessKey> = HashSet::new();
        if let Some(end) = evaluation.window_end_ms {
            involved.extend(
                r.base
                    .iter()
                    .map(|a| &a.attestation)
                    .filter(|a| a.fetched_at_ms <= end && end - a.fetched_at_ms <= policy.window_ms)
                    .map(|a| a.witness),
            );
        }
        // Every recent draw, with the versions of the round it rechecks.
        let mut rc = Rechecks {
            draws: Vec::new(),
            sightings: r.sightings(),
        };
        for (slot, countries) in self.store.disputes_for(url, self.recheck_since(now))? {
            if let (versions, Some(end)) = r.round_at(slot) {
                if versions.len() >= 2 {
                    rc.draws
                        .push(self.draw(&r, slot, end, &countries, versions, now));
                }
            }
        }

        let groups = evaluation.groups.clone();
        let versions = r.versions(&evaluation);
        let mut disagreement = None;
        let mut rechecks = 0;
        if let (Some(end), true) = (evaluation.window_end_ms, versions.len() >= 2) {
            let slot = self.round_slot(end);
            // The draws of rounds with these same versions confirm them
            // together; a draw of another round rechecked another question.
            let same = |d: &&Draw| hashes(&d.versions) == hashes(&versions);
            // By key, so which report of a network counts is the same everywhere.
            let mut seen: BTreeMap<WitnessKey, RecheckResult> = BTreeMap::new();
            for d in rc.draws.iter().filter(same) {
                for (k, res) in &d.results {
                    seen.insert(*k, res.clone());
                }
            }
            rechecks = seen.len();
            involved.extend(seen.keys().copied());
            let vs: Vec<(Digest, BTreeSet<String>)> = versions
                .iter()
                .map(|v| (v.hash, v.countries.clone()))
                .collect();
            let all: Vec<RecheckResult> = seen.values().cloned().collect();
            let recheck_quorum = self.config.quorum.recheck_quorum;
            let confirmed = quorum::confirmed_versions(&vs, &all, recheck_quorum);
            let all_confirmed = versions.iter().all(|v| confirmed.contains(&v.hash));
            let this_round_asked = rc.draws.iter().any(|d| d.slot == slot);
            let pending = !all_confirmed
                && (rc.draws.iter().filter(same).any(|d| !d.complete)
                    || (!this_round_asked && now <= self.recheck_deadline(slot)));

            // Each confirmed version, joined by the rechecks that saw it.
            let confirmed_groups: Vec<Group> = groups
                .iter()
                .filter(|g| confirmed.contains(&g.hash))
                .map(|g| {
                    let mut g = g.clone();
                    for (k, r) in &seen {
                        if r.hash == g.hash {
                            if !g.witnesses.contains(k) {
                                g.witnesses.push(*k);
                            }
                            g.asns.insert(r.asn);
                        }
                    }
                    g.witnesses.sort();
                    g
                })
                .collect();
            evaluation.verdict = if confirmed_groups.len() >= 2 {
                Verdict::Split {
                    groups: confirmed_groups,
                }
            } else if pending {
                Verdict::Disputed {
                    groups: groups.clone(),
                    pending: true,
                }
            } else if let [group] = confirmed_groups.as_slice() {
                // Dissent the rechecks couldn't check (too few witnesses in
                // its countries) is only overruled if it is a lone network.
                let unchecked = groups.iter().any(|g| {
                    !confirmed.contains(&g.hash)
                        && g.asns.len() >= policy.min_dissent_asns
                        && versions.iter().any(|v| {
                            v.hash == g.hash && !quorum::sampled(&v.countries, &all, recheck_quorum)
                        })
                });
                if unchecked {
                    Verdict::Disputed {
                        groups: groups.clone(),
                        pending: false,
                    }
                } else if group.asns.len() >= policy.min_asns {
                    let mut dissenters: Vec<WitnessKey> = groups
                        .iter()
                        .filter(|g| g.hash != group.hash)
                        .flat_map(|g| g.witnesses.clone())
                        .collect();
                    dissenters.sort();
                    Verdict::Agreed {
                        group: group.clone(),
                        dissenters,
                    }
                } else {
                    Verdict::Insufficient {
                        groups: groups.clone(),
                    }
                }
            } else {
                Verdict::Disputed {
                    groups: groups.clone(),
                    pending: false,
                }
            };
            disagreement = Some(Disagreement {
                slot,
                versions,
                confirmed,
                pending,
            });
        }

        let mut witnesses: Vec<(String, Option<Location>)> = r
            .locs
            .into_iter()
            .filter(|(k, _)| involved.contains(k))
            .map(|(k, l)| (k.to_hex(), l))
            .collect();
        witnesses.sort_by(|a, b| a.0.cmp(&b.0));
        Ok((
            VerdictView {
                url: url.to_string(),
                considered: evaluation.considered,
                rechecks,
                evaluation,
                witnesses,
            },
            disagreement,
            rc,
        ))
    }

    /// What this node knows about `url`'s rounds.
    pub(crate) fn rounds(&self, url: &str, now: i64) -> Result<Rounds> {
        let parsed = keepword_core::target::canonical_url(url)?;
        // Future-dated attestations, and ones claiming to predate their own
        // drand beacon, can't be honest.
        let atts: Vec<SignedAttestation> = self
            .attestations_for(url, now - LOOKBACK_MS)?
            .into_iter()
            .filter(|a| plausible_time(&a.attestation, now))
            .collect();
        let mut locs: HashMap<WitnessKey, Option<Location>> = HashMap::new();
        let mut discredited: HashSet<WitnessKey> = HashSet::new();
        for a in &atts {
            let k = a.attestation.witness;
            if let std::collections::hash_map::Entry::Vacant(e) = locs.entry(k) {
                e.insert(self.location_of(&k, now)?);
                if self.discredited(&k, now)? {
                    discredited.insert(k);
                }
            }
        }
        let cands = self.candidates_snapshot(now)?;

        // Rounds: only witnesses assigned to the URL count.
        let mut assigned_cache: HashMap<u64, Option<HashSet<WitnessKey>>> = HashMap::new();
        let mut base: Vec<SignedAttestation> = Vec::new();
        for a in &atts {
            if discredited.contains(&a.attestation.witness) {
                continue;
            }
            let epoch = keepword_core::beacon::epoch_of(a.attestation.fetched_at_ms);
            let assigned = assigned_cache.entry(epoch).or_insert_with(|| {
                self.assigned_near(&parsed, a.attestation.fetched_at_ms, &cands)
            });
            // Without the epoch's beacon nobody can tell who was assigned,
            // so nobody counts: counting everyone would let any key in,
            // for instance by dating its captures in such an epoch.
            if assigned
                .as_ref()
                .is_some_and(|set| set.contains(&a.attestation.witness))
            {
                base.push(a.clone());
            }
        }
        Ok(Rounds {
            url: parsed,
            policy: self.quorum_policy(),
            slot_ms: self.window_ms(),
            atts,
            locs,
            discredited,
            base,
            cands,
        })
    }

    /// The rechecks drawn for the round of the slot starting at `slot`
    /// (whose window ended at `round_end`), in `countries`, as far as this
    /// node has fetched them.
    fn draw(
        &self,
        r: &Rounds,
        slot: i64,
        round_end: i64,
        countries: &[String],
        versions: Vec<Version>,
        now: i64,
    ) -> Draw {
        let deadline = self.recheck_deadline(slot);
        // A capture counts as a recheck only if it is comparable with the
        // round (same method and normalizer profile).
        let sample = r
            .base
            .iter()
            .map(|a| &a.attestation)
            .find(|a| versions.iter().any(|v| v.hash == a.comparison_hash()));
        let mut drawn = 0;
        let mut results = Vec::new();
        for c in countries {
            for k in self.recheckers(&r.url, slot, c, &r.cands) {
                drawn += 1;
                let Some(l) = r.location(&k) else {
                    continue;
                };
                // Its first capture after the round: the one made for this
                // draw. A witness drawn again for a later slot captures
                // again, and that capture, maybe of a page edited since, must
                // not stand in for this one: deadlines of successive draws
                // overlap.
                let first = r
                    .atts
                    .iter()
                    .map(|a| &a.attestation)
                    .filter(|a| {
                        a.witness == k
                            && a.fetched_at_ms > round_end
                            && a.fetched_at_ms <= deadline
                            && sample.is_some_and(|s| quorum::comparable(s, a))
                    })
                    .min_by_key(|a| a.fetched_at_ms);
                if let Some(a) = first {
                    let res = RecheckResult {
                        country: l.country.clone(),
                        asn: l.asn,
                        hash: a.comparison_hash(),
                    };
                    results.push((k, res));
                }
            }
        }
        Draw {
            slot,
            versions,
            complete: results.len() >= drawn || now > deadline,
            results,
        }
    }

    /// After a sync: ask for rechecks of disputed rounds, settle each
    /// recheck draw once it is complete, update reputation and raise split
    /// alerts.
    pub fn review_verdicts(&self) -> Result<()> {
        let now = now_ms();
        let window = self.window_ms();
        let since = now - (2 * window).max(self.recheck_deadline(0) + window);
        let mut failed = Vec::new();
        for url in self.store.foreign_urls_since(since)? {
            // One URL that can't be reviewed (a damaged stored row, say)
            // must not hold up the others.
            if let Err(e) = self.review_url(&url, now) {
                failed.push(format!("{url}: {e:#}"));
            }
        }
        if !failed.is_empty() {
            anyhow::bail!("{} URLs not reviewed: {}", failed.len(), failed.join("; "));
        }
        Ok(())
    }

    fn review_url(&self, url: &str, now: i64) -> Result<()> {
        let q = &self.config.quorum;
        let window = self.window_ms();
        let me = self.key.public();
        let (v, dis, rc) = self.resolve_verdict(url)?;
        // Each draw is an independent sample; settle each on its own, once,
        // by the round it rechecked (whether or not that round is still the
        // current one), so repeated alerts need repeated independent
        // evidence.
        for draw in rc.draws.iter().filter(|x| x.complete) {
            self.settle_draw(url, &rc, draw, now)?;
        }
        let Some(end) = v.evaluation.window_end_ms else {
            return Ok(());
        };
        let Some(d) = dis else {
            // An undisputed agreement: reputation, once per slot.
            if let Verdict::Agreed { group, dissenters } = &v.evaluation.verdict {
                let slot = end / window;
                for w in &group.witnesses {
                    self.store.reputation_record(w, url, slot, 1.0, now)?;
                }
                for w in dissenters {
                    self.store.reputation_record(w, url, slot, -3.0, now)?;
                }
            }
            return Ok(());
        };
        if !rc.draws.iter().any(|x| x.slot == d.slot) {
            self.maybe_request_recheck(url, &d)?;
        }
        if let Verdict::Split { groups } = &v.evaluation.verdict {
            let recent = self.store.round_outcomes(url, q.split_rounds as u32)?;
            let splits = recent.iter().filter(|o| *o == "split").count();
            if splits >= q.split_confirmations
                && !self
                    .store
                    .alert_exists("split", url, &me, now - 86_400_000)?
            {
                let summary = format!(
                    "confirmed by rechecks in {splits} of the last {} disputed rounds: {}",
                    recent.len(),
                    groups
                        .iter()
                        .map(|g| format!("{} networks saw {}", g.asns.len(), g.hash.short()))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                self.raise_alert(
                    AlertKind::Split,
                    Some(url),
                    summary,
                    groups.iter().map(|g| g.hash).collect(),
                )?;
            }
        }
        Ok(())
    }

    /// Record the outcome of one complete recheck draw: which versions of
    /// the round it rechecked it reproduced. Versions it sampled well enough
    /// and didn't reproduce, while it did reproduce another, count against
    /// the networks that reported them, unless they are just the page from
    /// before an edit.
    fn settle_draw(&self, url: &str, rc: &Rechecks, draw: &Draw, now: i64) -> Result<()> {
        let q = &self.config.quorum;
        let vs: Vec<(Digest, BTreeSet<String>)> = draw
            .versions
            .iter()
            .map(|v| (v.hash, v.countries.clone()))
            .collect();
        let results: Vec<RecheckResult> = draw.results.iter().map(|r| r.1.clone()).collect();
        let confirmed = quorum::confirmed_versions(&vs, &results, q.recheck_quorum);
        let outcome = match confirmed.len() {
            0 => "disputed",
            1 => "agreed",
            _ => "split",
        };
        if !self.store.round_outcome_set(url, draw.slot, outcome, now)? {
            return Ok(());
        }
        if confirmed.len() != 1 {
            return Ok(());
        }
        let window = self.window_ms();
        let slot = draw.slot / window;
        for v in &draw.versions {
            if confirmed.contains(&v.hash) {
                for w in &v.reporters {
                    self.store.reputation_record(w, url, slot, 1.0, now)?;
                }
                continue;
            }
            // Only a claim the rechecks could have reproduced and didn't:
            // in every country it came from, enough networks rechecked.
            if !quorum::sampled(&v.countries, &results, q.recheck_quorum) {
                continue;
            }
            // Pages change: what a witness captured before anyone else saw
            // the new version is the page before an edit.
            if rc.predates(v, &confirmed) {
                continue;
            }
            for w in &v.reporters {
                self.store.reputation_record(w, url, slot, -3.0, now)?;
                if let Some(p) = self.prefix_of(w)? {
                    self.store.failed_claim_add(&p, url, draw.slot, now)?;
                }
            }
        }
        Ok(())
    }

    /// Ask for a recheck of a disputed round, if this node may and hasn't
    /// yet.
    fn maybe_request_recheck(&self, url: &str, d: &Disagreement) -> Result<()> {
        let me = self.key.public();
        let now = now_ms();
        if now > self.recheck_deadline(d.slot) || self.store.dispute_by(url, d.slot, &me)? {
            return Ok(());
        }
        let parsed = keepword_core::target::canonical_url(url)?;
        let cands = self.candidates_snapshot(now)?;
        let eligible = self
            .assigned_near(&parsed, d.slot, &cands)
            .is_some_and(|a| a.contains(&me));
        if !eligible {
            return Ok(());
        }
        // Fewest reporters first: the dissent's countries matter most.
        let mut versions: Vec<&Version> = d.versions.iter().collect();
        versions.sort_by_key(|v| v.reporters.len());
        let mut countries: Vec<String> = Vec::new();
        for v in &versions {
            if let Some(c) = v.countries.iter().next() {
                if !countries.contains(c) {
                    countries.push(c.clone());
                }
            }
        }
        for v in &versions {
            for c in &v.countries {
                if !countries.contains(c) {
                    countries.push(c.clone());
                }
            }
        }
        countries.truncate(crate::recheck::MAX_RECHECK_COUNTRIES);
        if !countries.is_empty() {
            self.publish_recheck(url, d.slot, countries)?;
        }
        Ok(())
    }

    /// Whether `key` connects from a network whose claims failed rechecks
    /// `quorum.max_failed_claims` times in the last week.
    fn discredited(&self, key: &WitnessKey, now: i64) -> Result<bool> {
        let Some(p) = self.prefix_of(key)? else {
            return Ok(false);
        };
        Ok(self.store.failed_claims(&p, now - FAILED_CLAIMS_MS)?
            >= self.config.quorum.max_failed_claims)
    }

    /// The network prefix this node saw `key` connect from itself: /24 for
    /// IPv4, /48 for IPv6.
    fn prefix_of(&self, key: &WitnessKey) -> Result<Option<String>> {
        let Some(o) = self.store.observation(key, &self.key.public())? else {
            return Ok(None);
        };
        Ok(Some(match o.body.ip {
            std::net::IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                format!("{a}.{b}.{c}.0/24")
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        }))
    }

    pub fn raise_alert(
        &self,
        kind: AlertKind,
        url: Option<&str>,
        summary: String,
        evidence: Vec<Digest>,
    ) -> Result<()> {
        let a = Signed::sign(
            Alert {
                kind,
                url: url.map(str::to_string),
                summary,
                evidence,
                issued_at_ms: now_ms(),
                issuer: self.key.public(),
            },
            &self.key,
        )?;
        self.store.alert_insert(&a)?;
        self.publish(Gossip::Alert(a))?;
        Ok(())
    }
}

/// Whether an attestation's claimed fetch time is believable: not in the
/// future, and not before the drand round it embeds (with the clock skew
/// bundles allow, so a witness whose clock is a little behind isn't
/// silently left out of verdicts).
pub fn plausible_time(a: &keepword_core::Attestation, now_ms: i64) -> bool {
    a.fetched_at_ms <= now_ms + crate::federation::SKEW_MS
        && a.beacon.as_ref().is_none_or(|b| {
            b.time_ms()
                <= a.fetched_at_ms
                    .saturating_add(keepword_core::beacon::SKEW_MS)
        })
}
