//! Rechecks: settling disagreements by reproduction, not by vote
//! (docs/DESIGN.md §6.5).
//!
//! When the witnesses assigned to a URL disagree, any of them asks for a
//! recheck. Witnesses drawn by public randomness from
//! the disagreeing witnesses' countries, and not assigned to the URL, capture
//! it again. Only versions they reproduce count. Real regional differences
//! reproduce; a made-up version would need the liar to also control most of
//! a random draw it can't influence.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use keepword_core::assign::{self, Candidate, DiversityPolicy};
use keepword_core::beacon::epoch_of;
use keepword_core::net::{Gossip, RecheckRequest};
use keepword_core::statement::Signed;
use keepword_core::{WitnessKey, now_ms, target};

use crate::Node;
use crate::federation::SKEW_MS;

/// Most countries one recheck request may name.
pub const MAX_RECHECK_COUNTRIES: usize = 3;
/// How long a candidate snapshot is used when no sync refreshes it.
const CANDIDATES_TTL_MS: i64 = 120_000;

impl Node {
    pub(crate) fn recheck_ms(&self) -> i64 {
        self.config.quorum.recheck_secs as i64 * 1000
    }

    /// Candidates for assignment, recomputed at most once a sync: verdicts
    /// and every recheck message need them, and computing them looks up
    /// every peer's location.
    pub(crate) fn candidates_snapshot(&self, now: i64) -> Result<Arc<Vec<Candidate>>> {
        let cached = self
            .sched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cands
            .clone();
        match cached {
            Some((at, c)) if now - at < CANDIDATES_TTL_MS && at <= now => Ok(c),
            _ => self.refresh_candidates(now),
        }
    }

    pub(crate) fn refresh_candidates(&self, now: i64) -> Result<Arc<Vec<Candidate>>> {
        let c = Arc::new(self.candidates(now)?);
        self.sched.lock().unwrap_or_else(|p| p.into_inner()).cands = Some((now, c.clone()));
        Ok(c)
    }

    pub(crate) fn window_ms(&self) -> i64 {
        (self.config.quorum.window_secs as i64 * 1000).max(1)
    }

    /// Start of the fixed slot, one comparison window long, that `t_ms`
    /// falls in. Rechecks are drawn per slot, not per requested time, so a
    /// requester can't try many times until a draw suits it.
    pub(crate) fn round_slot(&self, t_ms: i64) -> i64 {
        t_ms - t_ms.rem_euclid(self.window_ms())
    }

    /// Last moment a recheck capture counts for the slot starting at `slot`.
    pub(crate) fn recheck_deadline(&self, slot: i64) -> i64 {
        slot + self.window_ms() + self.recheck_ms()
    }

    /// Disputes that may still be open, or were until recently.
    pub(crate) fn recheck_since(&self, now: i64) -> i64 {
        now - self.recheck_deadline(0) - SKEW_MS
    }

    /// Witnesses assigned to `url` in the epoch of `t_ms` or the one before
    /// (captures near an epoch boundary may come from either). `None` when
    /// no seed is known, so assignment can't be established.
    pub(crate) fn assigned_near(
        &self,
        url: &url::Url,
        t_ms: i64,
        cands: &[Candidate],
    ) -> Option<HashSet<WitnessKey>> {
        let epoch = epoch_of(t_ms);
        let mut out = HashSet::new();
        let mut any = false;
        for e in [epoch, epoch.saturating_sub(1)] {
            if let Ok((seed, _)) = self.epoch_seed_cached(e) {
                any = true;
                out.extend(
                    self.assigned_among(&seed, url, cands)
                        .into_iter()
                        .map(|c| c.key),
                );
            }
        }
        any.then_some(out)
    }

    /// The witnesses drawn to recheck `url`'s round in the slot starting at
    /// `slot` in `country`: ranked by public randomness, one per network, never
    /// one of the witnesses assigned to the URL.
    pub(crate) fn recheckers(
        &self,
        url: &url::Url,
        slot: i64,
        country: &str,
        cands: &[Candidate],
    ) -> Vec<WitnessKey> {
        let Ok((seed, _)) = self.epoch_seed_cached(epoch_of(slot)) else {
            return vec![];
        };
        let assigned = self.assigned_near(url, slot, cands).unwrap_or_default();
        let pool: Vec<Candidate> = cands
            .iter()
            .filter(|c| c.country == country && !assigned.contains(&c.key))
            .cloned()
            .collect();
        let key = assign::recheck_key(&target::url_key(url), slot, country);
        assign::assign(
            &seed,
            &key,
            &pool,
            &DiversityPolicy {
                k: self.config.quorum.recheck_size,
                max_per_asn: 1,
                max_per_country: usize::MAX,
            },
        )
        .into_iter()
        .map(|c| c.key)
        .collect()
    }

    /// Validate and store a recheck request, and queue a capture if this
    /// node was drawn for it.
    pub(crate) fn accept_recheck(&self, r: &Signed<RecheckRequest>, now: i64) -> Result<bool> {
        let b = &r.body;
        let Ok(url) = target::canonical_url(&b.url) else {
            return Ok(false);
        };
        let countries_ok = !b.countries.is_empty()
            && b.countries.len() <= MAX_RECHECK_COUNTRIES
            && b.countries
                .iter()
                .all(|c| c.len() == 2 && c.chars().all(|x| x.is_ascii_uppercase()));
        let slot = self.round_slot(b.window_end_ms);
        let fresh = b.window_end_ms <= now + SKEW_MS
            && self.recheck_deadline(slot) >= now - SKEW_MS
            && b.issued_at_ms <= now + SKEW_MS;
        if url.as_str() != b.url || !countries_ok || !fresh {
            return Ok(false);
        }
        // Only the URL's assigned witnesses can ask, so the work anyone can
        // cause is bounded by the share of assignments they win: requests,
        // and the keys that make them, are free.
        let me = self.key.public();
        let cands = self.candidates_snapshot(now)?;
        let eligible = self
            .assigned_near(&url, slot, &cands)
            .is_some_and(|a| a.contains(&b.requester));
        if !eligible {
            return Ok(false);
        }
        if !self
            .store
            .dispute_insert(&b.url, slot, &b.requester, &b.countries, now)?
        {
            return Ok(false);
        }
        let drawn = b
            .countries
            .iter()
            .any(|c| self.recheckers(&url, slot, c, &cands).contains(&me));
        if drawn && !crate::host_listed(&self.config.network.decline_hosts, &url) {
            self.store.recheck_job_add(&b.url, slot, now)?;
        }
        Ok(true)
    }

    /// Ask the network to recheck a disputed round (any time in its slot).
    pub(crate) fn publish_recheck(
        &self,
        url: &str,
        window_end: i64,
        countries: Vec<String>,
    ) -> Result<bool> {
        let r = Signed::sign(
            RecheckRequest {
                url: url.to_string(),
                window_end_ms: window_end,
                countries,
                requester: self.key.public(),
                issued_at_ms: now_ms(),
            },
            &self.key,
        )?;
        self.ingest(Gossip::Recheck(r))
    }

    /// Capture the URLs this node was drawn to recheck, within its hourly
    /// budget. Returns how many it captured.
    pub(crate) async fn run_rechecks(&self) -> Result<usize> {
        let now = now_ms();
        let done = self.store.rechecks_done_since(now - 3_600_000)?;
        let budget = self
            .config
            .quorum
            .max_rechecks_per_hour
            .saturating_sub(done);
        if budget == 0 {
            return Ok(0);
        }
        let mut n = 0;
        let requests = self.store.requests_active(now)?;
        for (url, slot) in self.store.recheck_jobs_pending(budget as u32)? {
            // Too late to count, or nothing to settle: skip it, without
            // spending the budget on it.
            if now_ms() > self.recheck_deadline(slot) || !self.round_disputed(&url, slot).await? {
                self.store.recheck_job_drop(&url, slot)?;
                continue;
            }
            // Capture the way the assigned witnesses do, so the results
            // are comparable.
            let render = self.config.network.render_requests
                && requests.iter().any(|r| r.body.url == url && r.body.render);
            if let Err(e) = self.capture(&url, render).await {
                eprintln!("recheck of {url} failed: {e:#}");
            } else {
                n += 1;
            }
            self.store.recheck_job_done(&url, slot, now_ms())?;
        }
        Ok(n)
    }

    /// Whether the witnesses assigned to `url` disagree in the round of the
    /// slot starting at `slot`, as far as this node sees after asking them
    /// for their attestations. Recheck requests are free, and any key is
    /// assigned to some URLs (it only has to try enough of them), so a
    /// capture is only spent on a disagreement this node can see itself.
    pub(crate) async fn round_disputed(&self, url: &str, slot: i64) -> Result<bool> {
        let now = now_ms();
        let parsed = target::canonical_url(url)?;
        let cands = self.candidates_snapshot(now)?;
        let assigned = self
            .assigned_near(&parsed, slot, &cands)
            .unwrap_or_default();
        // A peer that doesn't answer just leaves its attestations out.
        let _ = self
            .fetch_attestations(&parsed, assigned, slot - self.window_ms())
            .await;
        Ok(self.rounds(url, now)?.round_at(slot).0.len() >= 2)
    }
}
