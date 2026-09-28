//! Turning many witnesses' attestations into one verdict.
//!
//! The unit of trust is distinct networks, not keys: agreement only counts
//! once per ASN, so a thousand keys in one data centre are one vote.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::Digest;
use crate::attestation::{Attestation, SignedAttestation};
use crate::keys::WitnessKey;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// Only attestations this close together in time are compared.
    pub window_ms: i64,
    /// Distinct ASNs needed for an agreed verdict.
    pub min_asns: usize,
    /// Distinct ASNs a *minority* group needs before it counts as evidence
    /// of cloaking rather than one faulty or malicious witness.
    pub min_dissent_asns: usize,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        QuorumPolicy {
            window_ms: 10 * 60 * 1000,
            min_asns: 3,
            min_dissent_asns: 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub hash: Digest,
    pub witnesses: Vec<WitnessKey>,
    pub asns: BTreeSet<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Independent networks saw the same content.
    Agreed {
        group: Group,
        dissenters: Vec<WitnessKey>,
    },
    /// Independent networks saw different content at the same time: the
    /// server is treating clients differently (cloaking, geo-targeting or
    /// A/B testing).
    Split { groups: Vec<Group> },
    /// Not enough independent witnesses to say anything.
    Insufficient { groups: Vec<Group> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    /// Attestations dropped for bad signatures or for naming another URL.
    pub rejected: usize,
    /// Witnesses compared: the latest attestation of each inside the window.
    #[serde(default)]
    pub considered: usize,
    /// End of the compared window (fetch time of its newest attestation).
    #[serde(default)]
    pub window_end_ms: Option<i64>,
}

/// Evaluate attestations of one URL. `asn_of` returns the *corroborated* ASN
/// of an attestation's witness, or `None` if it can't be established;
/// witnesses without one are listed but never counted.
pub fn evaluate(
    url: &str,
    attestations: &[SignedAttestation],
    asn_of: impl Fn(&Attestation) -> Option<u32>,
    policy: &QuorumPolicy,
) -> Evaluation {
    let mut rejected = 0;
    let valid: Vec<&Attestation> = attestations
        .iter()
        .filter(|s| {
            let ok = s.attestation.url == url && s.verify().is_ok();
            if !ok {
                rejected += 1;
            }
            ok
        })
        .map(|s| &s.attestation)
        .collect();

    // Which window to compare: the one covering the most distinct
    // networks (then the most witnesses, then the latest). Anchoring it at
    // the newest attestation would let one witness with a future timestamp
    // push everyone else out of it.
    let mut timed: Vec<(&Attestation, Option<u32>)> =
        valid.iter().map(|a| (*a, asn_of(a))).collect();
    timed.sort_by_key(|(a, _)| a.fetched_at_ms);
    let mut best: Option<(usize, usize, i64)> = None;
    {
        let mut asns: HashMap<u32, usize> = HashMap::new();
        let mut keys: HashMap<WitnessKey, usize> = HashMap::new();
        let mut left = 0;
        for right in 0..timed.len() {
            let (a, asn) = timed[right];
            *keys.entry(a.witness).or_default() += 1;
            if let Some(n) = asn {
                *asns.entry(n).or_default() += 1;
            }
            let end = a.fetched_at_ms;
            while end - timed[left].0.fetched_at_ms > policy.window_ms {
                let (old, old_asn) = timed[left];
                if let Some(c) = keys.get_mut(&old.witness) {
                    *c -= 1;
                    if *c == 0 {
                        keys.remove(&old.witness);
                    }
                }
                if let Some(n) = old_asn {
                    if let Some(c) = asns.get_mut(&n) {
                        *c -= 1;
                        if *c == 0 {
                            asns.remove(&n);
                        }
                    }
                }
                left += 1;
            }
            let score = (asns.len(), keys.len(), end);
            if best.is_none_or(|b| score >= b) {
                best = Some(score);
            }
        }
    }
    let Some((_, _, end)) = best else {
        return Evaluation {
            verdict: Verdict::Insufficient { groups: vec![] },
            rejected,
            considered: 0,
            window_end_ms: None,
        };
    };
    // One (latest) attestation per witness inside the window.
    let mut latest: HashMap<WitnessKey, &Attestation> = HashMap::new();
    for a in valid
        .iter()
        .filter(|a| a.fetched_at_ms <= end && end - a.fetched_at_ms <= policy.window_ms)
    {
        let e = latest.entry(a.witness).or_insert(a);
        if a.fetched_at_ms > e.fetched_at_ms {
            *e = a;
        }
    }
    let considered = latest.len();

    // Hashes are only comparable within one capture method and normalizer
    // profile. Compare within the class with the most distinct networks, so
    // extra keys using another method can't crowd out the others.
    let mut classes: BTreeMap<(u8, Option<Digest>), Vec<&Attestation>> = BTreeMap::new();
    for a in latest.values() {
        classes
            .entry((a.method.code(), a.norm.map(|n| n.profile)))
            .or_default()
            .push(a);
    }
    let Some(class) = classes.into_values().max_by_key(|v| {
        let nets: BTreeSet<u32> = v.iter().filter_map(|a| asn_of(a)).collect();
        (nets.len(), v.len())
    }) else {
        return Evaluation {
            verdict: Verdict::Insufficient { groups: vec![] },
            rejected,
            considered,
            window_end_ms: Some(end),
        };
    };

    let mut by_hash: BTreeMap<Digest, Group> = BTreeMap::new();
    for a in class {
        let g = by_hash.entry(a.comparison_hash()).or_insert_with(|| Group {
            hash: a.comparison_hash(),
            witnesses: vec![],
            asns: BTreeSet::new(),
        });
        g.witnesses.push(a.witness);
        if let Some(asn) = asn_of(a) {
            g.asns.insert(asn);
        }
    }
    let mut groups: Vec<Group> = by_hash.into_values().collect();
    for g in &mut groups {
        g.witnesses.sort();
    }
    groups.sort_by(|a, b| b.asns.len().cmp(&a.asns.len()).then(a.hash.cmp(&b.hash)));

    let substantial = groups
        .iter()
        .filter(|g| g.asns.len() >= policy.min_dissent_asns)
        .count();
    let verdict = if substantial >= 2 {
        Verdict::Split { groups }
    } else if groups[0].asns.len() >= policy.min_asns {
        let mut rest = groups.into_iter();
        let group = rest.next().expect("non-empty");
        let mut dissenters: Vec<WitnessKey> = rest.flat_map(|g| g.witnesses).collect();
        dissenters.sort();
        Verdict::Agreed { group, dissenters }
    } else {
        Verdict::Insufficient { groups }
    };
    Evaluation {
        verdict,
        rejected,
        considered,
        window_end_ms: Some(end),
    }
}

/// Convenience for callers that only have self-reported vantage data, such
/// as a single-node deployment. Never use this for public verdicts.
pub fn self_reported_asn(a: &Attestation) -> Option<u32> {
    a.vantage.asn
}

/// Whether two captures can be compared by `comparison_hash`: same capture
/// method and same normalizer profile.
pub fn comparable(a: &Attestation, b: &Attestation) -> bool {
    a.method == b.method && a.norm.map(|n| n.profile) == b.norm.map(|n| n.profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{CaptureMethod, NormCommitment, Vantage};
    use crate::keys::Keypair;

    fn att(kp: &Keypair, asn: u32, content: &[u8], t: i64) -> SignedAttestation {
        Attestation {
            url: "https://example.com/".into(),
            final_url: "https://example.com/".into(),
            redirects: vec![],
            fetched_at_ms: t,
            method: CaptureMethod::Http,
            status: 200,
            content_type: None,
            headers_hash: Digest::of(b"h"),
            body_hash: Digest::of(content),
            body_len: content.len() as u64,
            norm: Some(NormCommitment {
                profile: Digest::of(b"p1"),
                hash: Digest::of(content),
            }),
            cert_sha256: None,
            server_ip: None,
            vantage: Vantage {
                asn: Some(asn),
                country: None,
            },
            witness: kp.public(),
            beacon: None,
        }
        .sign(kp)
        .unwrap()
    }

    fn keys(n: usize) -> Vec<Keypair> {
        (0..n).map(|_| Keypair::generate().unwrap()).collect()
    }

    const URL: &str = "https://example.com/";

    #[test]
    fn agreement_counts_networks_not_keys() {
        let k = keys(6);
        // Five keys in one ASN plus one elsewhere: two networks, not six votes.
        let mut v: Vec<_> = k[..5].iter().map(|kp| att(kp, 100, b"A", 0)).collect();
        v.push(att(&k[5], 200, b"A", 0));
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        assert!(matches!(e.verdict, Verdict::Insufficient { .. }));

        let v: Vec<_> = k[..3]
            .iter()
            .enumerate()
            .map(|(i, kp)| att(kp, i as u32, b"A", 0))
            .collect();
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        assert!(
            matches!(e.verdict, Verdict::Agreed { ref dissenters, .. } if dissenters.is_empty())
        );
    }

    #[test]
    fn one_liar_is_a_dissenter_not_a_split() {
        let k = keys(4);
        let mut v: Vec<_> = k[..3]
            .iter()
            .enumerate()
            .map(|(i, kp)| att(kp, i as u32, b"A", 0))
            .collect();
        v.push(att(&k[3], 99, b"FRAMED", 0));
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        match e.verdict {
            Verdict::Agreed { dissenters, .. } => assert_eq!(dissenters, vec![k[3].public()]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn independent_disagreement_is_a_split() {
        let k = keys(5);
        let v = vec![
            att(&k[0], 1, b"A", 0),
            att(&k[1], 2, b"A", 0),
            att(&k[2], 3, b"A", 0),
            att(&k[3], 4, b"B", 0),
            att(&k[4], 5, b"B", 0),
        ];
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        assert!(matches!(e.verdict, Verdict::Split { ref groups } if groups.len() == 2));
    }

    #[test]
    fn rejects_forgeries_and_stale() {
        let k = keys(3);
        let mut v: Vec<_> = k
            .iter()
            .enumerate()
            .map(|(i, kp)| att(kp, i as u32, b"A", 1_000_000))
            .collect();
        v[0].attestation.status = 500; // breaks the signature
        let stale = att(&keys(1)[0], 42, b"A", 0);
        v.push(stale);
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        assert_eq!(e.rejected, 1);
        assert!(matches!(e.verdict, Verdict::Insufficient { .. }));
    }

    /// One witness dates its attestation a year ahead. The window must not
    /// follow it and drop everyone else.
    #[test]
    fn a_future_timestamp_cannot_blind_the_verdict() {
        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate().unwrap()).collect();
        let v = vec![
            att(&keys[0], 1, b"page", 1_000_000),
            att(&keys[1], 2, b"page", 1_060_000),
            att(&keys[2], 3, b"page", 1_120_000),
            att(&keys[3], 4, b"other", 1_000_000 + 365 * 86_400_000),
        ];
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        match e.verdict {
            Verdict::Agreed { group, .. } => assert_eq!(group.asns.len(), 3),
            other => panic!("expected agreement, got {other:?}"),
        }
        assert_eq!(e.considered, 3);
    }

    /// Five keys in one network use a different normalizer profile. Their
    /// class has more keys, but fewer networks, so it isn't the one compared.
    #[test]
    fn the_class_with_most_networks_is_compared() {
        let honest: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        let sybils: Vec<Keypair> = (0..5).map(|_| Keypair::generate().unwrap()).collect();
        let mut v: Vec<SignedAttestation> = honest
            .iter()
            .enumerate()
            .map(|(i, k)| att(k, i as u32 + 1, b"page", 1000))
            .collect();
        for k in &sybils {
            let mut a = att(k, 9, b"fake", 1000).attestation;
            a.norm = Some(NormCommitment {
                profile: Digest::of(b"p2"),
                hash: Digest::of(b"fake"),
            });
            v.push(a.sign(k).unwrap());
        }
        let e = evaluate(URL, &v, self_reported_asn, &QuorumPolicy::default());
        match e.verdict {
            Verdict::Agreed { group, .. } => assert_eq!(group.hash, Digest::of(b"page")),
            other => panic!("expected the honest class to be compared, got {other:?}"),
        }
    }
}
