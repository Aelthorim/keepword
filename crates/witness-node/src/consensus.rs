//! Quorum verdicts across witnesses, rechecks of disputed rounds,
//! reputation and alerts (docs/DESIGN.md §6.5).

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::Result;
use serde::Serialize;
use witness_core::net::{Alert, AlertKind, Gossip};
use witness_core::quorum::{self, Evaluation, Group, QuorumPolicy, RecheckResult, Verdict};
use witness_core::statement::Signed;
use witness_core::{Digest, SignedAttestation, WitnessKey, now_ms};

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

/// A round in which the assigned witnesses disagreed.
#[derive(Debug)]
pub struct Disagreement {
    /// Start of the round's slot (see `Node::round_slot`).
    pub slot: i64,
    /// Each version, the countries it was reported from, and its reporters.
    pub versions: Vec<(Digest, BTreeSet<String>, Vec<WitnessKey>)>,
    /// Recent recheck draws, each settled on its own.
    pub draws: Vec<Draw>,
    /// Versions reproduced by the recent draws together.
    pub confirmed: BTreeSet<Digest>,
    /// Rechecks may still change the verdict.
    pub pending: bool,
}

/// The rechecks of one disputed slot.
#[derive(Debug)]
pub struct Draw {
    pub slot: i64,
    pub results: Vec<(WitnessKey, RecheckResult)>,
    /// Every drawn witness reported, or the time for it is over.
    pub complete: bool,
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

    /// The verdict on `url`, and the disagreement behind it, if any.
    ///
    /// Only the witnesses public randomness assigned to the URL are
    /// compared, minus networks whose claims keep failing rechecks. If they
    /// disagree, the verdict comes from rechecks (see `recheck.rs`):
    /// versions that witnesses drawn at random didn't reproduce don't count.
    pub fn resolve_verdict(&self, url: &str) -> Result<(VerdictView, Option<Disagreement>)> {
        let now = now_ms();
        let policy = self.quorum_policy();
        let parsed = witness_core::target::canonical_url(url)?;
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
        let country = |k: &WitnessKey| {
            locs.get(k)
                .and_then(|l| l.as_ref())
                .map(|l| l.country.clone())
        };
        let cands = self.candidates(now)?;

        // The round: only witnesses assigned to the URL count.
        let mut assigned_cache: HashMap<u64, Option<HashSet<WitnessKey>>> = HashMap::new();
        let mut base: Vec<SignedAttestation> = Vec::new();
        for a in &atts {
            if discredited.contains(&a.attestation.witness) {
                continue;
            }
            let epoch = witness_core::beacon::epoch_of(a.attestation.fetched_at_ms);
            let assigned = assigned_cache.entry(epoch).or_insert_with(|| {
                self.assigned_near(&parsed, a.attestation.fetched_at_ms, &cands)
            });
            // Without a beacon nobody can be assigned; count everyone.
            if assigned
                .as_ref()
                .is_none_or(|set| set.contains(&a.attestation.witness))
            {
                base.push(a.clone());
            }
        }
        let asn_of = |a: &witness_core::Attestation| {
            locs.get(&a.witness).and_then(|l| l.as_ref()).map(|l| l.asn)
        };
        let mut evaluation = quorum::evaluate(url, &base, asn_of, &policy);
        let mut involved: HashSet<WitnessKey> = HashSet::new();
        if let Some(end) = evaluation.window_end_ms {
            involved.extend(
                base.iter()
                    .map(|a| &a.attestation)
                    .filter(|a| a.fetched_at_ms <= end && end - a.fetched_at_ms <= policy.window_ms)
                    .map(|a| a.witness),
            );
        }

        let groups = evaluation.groups.clone();
        let located: Vec<&Group> = groups.iter().filter(|g| !g.asns.is_empty()).collect();
        let mut disagreement = None;
        let mut rechecks = 0;
        if let (Some(end), true) = (evaluation.window_end_ms, located.len() >= 2) {
            let slot = self.round_slot(end);
            let versions: Vec<(Digest, BTreeSet<String>, Vec<WitnessKey>)> = located
                .iter()
                .map(|g| {
                    let countries = g.witnesses.iter().filter_map(&country).collect();
                    (g.hash, countries, g.witnesses.clone())
                })
                .collect();
            // A capture counts as a recheck only if it is comparable with
            // the round (same method and normalizer profile).
            let sample = base
                .iter()
                .map(|a| &a.attestation)
                .find(|a| versions.iter().any(|v| v.0 == a.comparison_hash()));
            let mut draws = Vec::new();
            let mut seen: HashMap<WitnessKey, RecheckResult> = HashMap::new();
            for (d_slot, countries) in self.store.disputes_for(url, self.recheck_since(now))? {
                let deadline = self.recheck_deadline(d_slot);
                let mut drawn = 0;
                let mut results = Vec::new();
                for c in &countries {
                    for k in self.recheckers(&parsed, d_slot, c, &cands) {
                        drawn += 1;
                        let Some(l) = locs.get(&k).and_then(|l| l.as_ref()) else {
                            continue;
                        };
                        let latest = atts
                            .iter()
                            .map(|a| &a.attestation)
                            .filter(|a| {
                                a.witness == k
                                    && a.fetched_at_ms >= d_slot
                                    && a.fetched_at_ms <= deadline
                                    && sample.is_some_and(|s| quorum::comparable(s, a))
                            })
                            .max_by_key(|a| a.fetched_at_ms);
                        if let Some(a) = latest {
                            let r = RecheckResult {
                                country: l.country.clone(),
                                asn: l.asn,
                                hash: a.comparison_hash(),
                            };
                            seen.insert(k, r.clone());
                            results.push((k, r));
                        }
                    }
                }
                draws.push(Draw {
                    slot: d_slot,
                    complete: results.len() >= drawn || now > deadline,
                    results,
                });
            }
            rechecks = seen.len();
            involved.extend(seen.keys().copied());
            let vs: Vec<(Digest, BTreeSet<String>)> =
                versions.iter().map(|v| (v.0, v.1.clone())).collect();
            let all: Vec<RecheckResult> = seen.values().cloned().collect();
            let recheck_quorum = self.config.quorum.recheck_quorum;
            let confirmed = quorum::confirmed_versions(&vs, &all, recheck_quorum);
            let all_confirmed = versions.iter().all(|v| confirmed.contains(&v.0));
            let this_round_asked = draws.iter().any(|d| d.slot == slot);
            let pending = !all_confirmed
                && (draws.iter().any(|d| !d.complete)
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
                        && versions
                            .iter()
                            .any(|v| v.0 == g.hash && !quorum::sampled(&v.1, &all, recheck_quorum))
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
                draws,
                confirmed,
                pending,
            });
        }

        let mut witnesses: Vec<(String, Option<Location>)> = locs
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
        ))
    }

    /// After a sync: ask for rechecks of disputed rounds, settle each
    /// recheck draw once it is complete, update reputation and raise split
    /// alerts.
    pub fn review_verdicts(&self) -> Result<()> {
        let now = now_ms();
        let q = &self.config.quorum;
        let window = self.window_ms();
        let since = now - (2 * window).max(self.recheck_deadline(0) + window);
        let me = self.key.public();
        for url in self.store.foreign_urls_since(since)? {
            let (v, dis) = self.resolve_verdict(&url)?;
            let Some(end) = v.evaluation.window_end_ms else {
                continue;
            };
            let Some(d) = dis else {
                // An undisputed agreement: reputation, once per slot.
                if let Verdict::Agreed { group, dissenters } = &v.evaluation.verdict {
                    let slot = end / window;
                    for w in &group.witnesses {
                        self.store.reputation_record(w, &url, slot, 1.0, now)?;
                    }
                    for w in dissenters {
                        self.store.reputation_record(w, &url, slot, -3.0, now)?;
                    }
                }
                continue;
            };
            if !d.draws.iter().any(|x| x.slot == d.slot) {
                self.maybe_request_recheck(&url, &d)?;
            }
            // Each draw is an independent sample; settle each on its own,
            // once, so repeated alerts need repeated independent evidence.
            for draw in d.draws.iter().filter(|x| x.complete) {
                self.settle_draw(&url, &d, draw, now)?;
            }
            if let Verdict::Split { groups } = &v.evaluation.verdict {
                let recent = self.store.round_outcomes(&url, q.split_rounds as u32)?;
                let splits = recent.iter().filter(|o| *o == "split").count();
                if splits >= q.split_confirmations
                    && !self
                        .store
                        .alert_exists("split", &url, &me, now - 86_400_000)?
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
                        Some(&url),
                        summary,
                        groups.iter().map(|g| g.hash).collect(),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Record the outcome of one complete recheck draw: which of the
    /// round's versions it reproduced. Versions it sampled well enough and
    /// didn't reproduce, while it did reproduce another, count against the
    /// networks that reported them.
    fn settle_draw(&self, url: &str, d: &Disagreement, draw: &Draw, now: i64) -> Result<()> {
        let q = &self.config.quorum;
        let vs: Vec<(Digest, BTreeSet<String>)> =
            d.versions.iter().map(|v| (v.0, v.1.clone())).collect();
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
        for (hash, countries, reporters) in &d.versions {
            if confirmed.contains(hash) {
                for w in reporters {
                    self.store.reputation_record(w, url, slot, 1.0, now)?;
                }
                continue;
            }
            // Only a claim the rechecks could have reproduced and didn't:
            // in every country it came from, enough networks rechecked.
            let sampled = quorum::sampled(countries, &results, q.recheck_quorum);
            if !sampled {
                continue;
            }
            for w in reporters {
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
        let parsed = witness_core::target::canonical_url(url)?;
        let cands = self.candidates(now)?;
        let eligible = self
            .assigned_near(&parsed, d.slot, &cands)
            .is_some_and(|a| a.contains(&me))
            || self
                .store
                .requests_active(now)?
                .iter()
                .any(|r| r.body.url == url && r.body.requester == me);
        if !eligible {
            return Ok(());
        }
        // Fewest reporters first: the dissent's countries matter most.
        let mut versions: Vec<&(Digest, BTreeSet<String>, Vec<WitnessKey>)> =
            d.versions.iter().collect();
        versions.sort_by_key(|v| v.2.len());
        let mut countries: Vec<String> = Vec::new();
        for v in &versions {
            if let Some(c) = v.1.iter().next() {
                if !countries.contains(c) {
                    countries.push(c.clone());
                }
            }
        }
        for v in &versions {
            for c in &v.1 {
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
/// future, and not before the drand round it embeds.
pub fn plausible_time(a: &witness_core::Attestation, now_ms: i64) -> bool {
    a.fetched_at_ms <= now_ms + crate::federation::SKEW_MS
        && a.beacon
            .as_ref()
            .is_none_or(|b| b.time_ms() <= a.fetched_at_ms)
}
