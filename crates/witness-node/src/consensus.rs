//! Quorum verdicts across witnesses, reputation, and alerts
//! (docs/DESIGN.md §6.3, §6.8).

use anyhow::Result;
use serde::Serialize;
use witness_core::net::{Alert, AlertKind, Gossip};
use witness_core::quorum::{self, Evaluation, QuorumPolicy, Verdict};
use witness_core::statement::Signed;
use witness_core::{now_ms, Digest, SignedAttestation};

use crate::Node;

/// How far back verdicts look for attestations.
const LOOKBACK_MS: i64 = 7 * 86_400_000;

#[derive(Debug, Serialize)]
pub struct VerdictView {
    pub url: String,
    pub evaluation: Evaluation,
    /// Attestations considered (latest per witness inside the window).
    pub considered: usize,
    /// Every witness involved and where it is, if known.
    pub witnesses: Vec<(String, Option<crate::vantage::Location>)>,
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

    /// All attestations of `url` this node knows: its own and mirrored ones.
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
        let now = now_ms();
        let atts = self.attestations_for(url, now - LOOKBACK_MS)?;
        let policy = self.quorum_policy();
        let newest = atts
            .iter()
            .map(|a| a.attestation.fetched_at_ms)
            .max()
            .unwrap_or(now);
        let recent: Vec<SignedAttestation> = atts
            .into_iter()
            .filter(|a| newest - a.attestation.fetched_at_ms <= policy.window_ms)
            .collect();
        let mut locs = std::collections::HashMap::new();
        for a in &recent {
            let k = a.attestation.witness;
            if let std::collections::hash_map::Entry::Vacant(e) = locs.entry(k) {
                e.insert(self.location_of(&k, now)?);
            }
        }
        let evaluation = quorum::evaluate(
            url,
            &recent,
            |a| locs.get(&a.witness).and_then(|l| l.as_ref()).map(|l| l.asn),
            &policy,
        );
        let mut witnesses: Vec<(String, Option<crate::vantage::Location>)> =
            locs.into_iter().map(|(k, l)| (k.to_hex(), l)).collect();
        witnesses.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(VerdictView {
            url: url.to_string(),
            evaluation,
            considered: recent.len(),
            witnesses,
        })
    }

    /// After a sync: turn verdicts on recently captured URLs into
    /// reputation events and split alerts.
    pub fn review_verdicts(&self) -> Result<()> {
        let now = now_ms();
        let window = self.config.quorum.window_secs as i64 * 1000;
        for url in self
            .store
            .foreign_urls_since(now - 2 * window.max(60_000))?
        {
            let v = self.verdict(&url)?;
            let newest = self
                .attestations_for(&url, now - LOOKBACK_MS)?
                .iter()
                .map(|a| a.attestation.fetched_at_ms)
                .max()
                .unwrap_or(now);
            let slot = newest / window.max(1);
            match &v.evaluation.verdict {
                Verdict::Agreed { group, dissenters } => {
                    for w in &group.witnesses {
                        self.store.reputation_record(w, &url, slot, 1.0, now)?;
                    }
                    for d in dissenters {
                        self.store.reputation_record(d, &url, slot, -3.0, now)?;
                    }
                }
                Verdict::Split { groups } => {
                    if !self
                        .store
                        .alert_exists("split", &url, &self.key.public(), now - window)?
                    {
                        let summary = format!(
                            "{} independent groups of witnesses saw different content at the same time ({})",
                            groups.len(),
                            groups
                                .iter()
                                .map(|g| format!("{} ASNs saw {}", g.asns.len(), g.hash.short()))
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
                Verdict::Insufficient { .. } => {}
            }
        }
        Ok(())
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
