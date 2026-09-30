//! Which witnesses are responsible for a URL.
//!
//! The original plan used Kademlia XOR distance between `hash(url)` and node
//! IDs. Node IDs are self-generated keys, though, so an attacker can grind
//! keys until several of them sit next to a target URL. Instead we use
//! rendezvous (highest-random-weight) hashing keyed by an *epoch seed*: a
//! public randomness value nobody can predict in advance (a drand round or a
//! Bitcoin block hash). Grinding then has to be redone every epoch, after the
//! seed is published, and diversity constraints mean extra keys in the same
//! network buy nothing. Kademlia remains the routing and discovery layer.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::Digest;
use crate::keys::WitnessKey;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub key: WitnessKey,
    /// Corroborated (not merely self-reported) network location.
    pub asn: u32,
    pub country: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiversityPolicy {
    /// How many witnesses to assign.
    pub k: usize,
    /// Never more than this many witnesses from one ASN.
    pub max_per_asn: usize,
    /// Never more than this many witnesses from one country.
    pub max_per_country: usize,
}

impl Default for DiversityPolicy {
    fn default() -> Self {
        DiversityPolicy {
            k: 5,
            max_per_asn: 1,
            max_per_country: 2,
        }
    }
}

/// Deterministic weight of a candidate for a URL in an epoch.
pub fn weight(epoch_seed: &Digest, url_key: &Digest, key: &WitnessKey) -> Digest {
    Digest::tagged(
        "keepword assignment v1",
        &[epoch_seed.as_bytes(), url_key.as_bytes(), &key.0],
    )
}

/// The key rechecks for a disputed URL are ranked by: specific to the
/// comparison window and the country being rechecked, so each dispute gets
/// its own random draw.
pub fn recheck_key(url_key: &Digest, window_end_ms: i64, country: &str) -> Digest {
    Digest::tagged(
        "keepword recheck v1",
        &[
            url_key.as_bytes(),
            &window_end_ms.to_be_bytes(),
            country.as_bytes(),
        ],
    )
}

/// The witnesses that audit `log`: the `k` members ranked highest for it,
/// excluding the log itself. Every node computes the same set from the same
/// membership, so each log gets `k` auditors and, on average, each witness
/// audits `k` logs, however large the network.
pub fn auditors(log: &WitnessKey, members: &[WitnessKey], k: usize) -> Vec<WitnessKey> {
    let mut ranked: Vec<(Digest, WitnessKey)> = members
        .iter()
        .filter(|m| *m != log)
        .map(|m| (Digest::tagged("keepword audit v1", &[&log.0, &m.0]), *m))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranked.dedup_by(|a, b| a.1 == b.1);
    ranked.into_iter().take(k).map(|(_, m)| m).collect()
}

/// Pick up to `policy.k` witnesses for `url_key`, highest weight first,
/// skipping any that would exceed the per-ASN or per-country caps. Returns
/// fewer than `k` when the network isn't diverse enough; callers must treat
/// that as a weaker quorum rather than relaxing the caps.
pub fn assign(
    epoch_seed: &Digest,
    url_key: &Digest,
    candidates: &[Candidate],
    policy: &DiversityPolicy,
) -> Vec<Candidate> {
    let mut ranked: Vec<(Digest, &Candidate)> = candidates
        .iter()
        .map(|c| (weight(epoch_seed, url_key, &c.key), c))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.key.cmp(&b.1.key)));
    ranked.dedup_by(|a, b| a.1.key == b.1.key);

    let mut per_asn: HashMap<u32, usize> = HashMap::new();
    let mut per_country: HashMap<&str, usize> = HashMap::new();
    let mut out = Vec::with_capacity(policy.k);
    for (_, c) in ranked {
        if out.len() == policy.k {
            break;
        }
        let a = per_asn.entry(c.asn).or_default();
        let n = per_country.entry(c.country.as_str()).or_default();
        if *a >= policy.max_per_asn || *n >= policy.max_per_country {
            continue;
        }
        *a += 1;
        *n += 1;
        out.push(c.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn cand(asn: u32, country: &str) -> Candidate {
        Candidate {
            key: Keypair::generate().unwrap().public(),
            asn,
            country: country.into(),
        }
    }

    #[test]
    fn respects_diversity() {
        let mut pool: Vec<_> = (0..50).map(|_| cand(666, "XX")).collect(); // a sybil farm
        pool.extend([
            cand(3320, "DE"),
            cand(8881, "DE"),
            cand(6830, "AT"),
            cand(7922, "US"),
            cand(2856, "GB"),
            cand(3215, "FR"),
        ]);
        let seed = Digest::of(b"epoch 1");
        let url = Digest::of(b"https://example.com/");
        let policy = DiversityPolicy::default();
        let got = assign(&seed, &url, &pool, &policy);
        assert_eq!(got.len(), 5);
        assert!(got.iter().filter(|c| c.asn == 666).count() <= 1);
        assert!(got.iter().filter(|c| c.country == "DE").count() <= 2);
    }

    #[test]
    fn deterministic_and_epoch_dependent() {
        let pool: Vec<_> = (0..30).map(|i| cand(i, &format!("C{i}"))).collect();
        let url = Digest::of(b"u");
        let p = DiversityPolicy {
            k: 3,
            ..Default::default()
        };
        let a = assign(&Digest::of(b"e1"), &url, &pool, &p);
        assert_eq!(a, assign(&Digest::of(b"e1"), &url, &pool, &p));
        // Order of the input doesn't matter.
        let mut rev = pool.clone();
        rev.reverse();
        assert_eq!(a, assign(&Digest::of(b"e1"), &url, &rev, &p));
        // A new epoch reshuffles.
        let b = assign(&Digest::of(b"e2"), &url, &pool, &p);
        assert_ne!(a, b);
    }

    #[test]
    fn every_log_gets_k_auditors() {
        let members: Vec<WitnessKey> = (0..50)
            .map(|_| crate::keys::Keypair::generate().unwrap().public())
            .collect();
        let mut load: HashMap<WitnessKey, usize> = HashMap::new();
        for log in &members {
            let a = auditors(log, &members, 8);
            assert_eq!(a.len(), 8);
            assert!(!a.contains(log));
            // Order of the member list doesn't matter.
            let mut rev = members.clone();
            rev.reverse();
            assert_eq!(auditors(log, &rev, 8), a);
            for m in a {
                *load.entry(m).or_default() += 1;
            }
        }
        assert_eq!(load.values().sum::<usize>(), 50 * 8);
        // Small networks: everyone audits everyone.
        assert_eq!(auditors(&members[0], &members[..4], 8).len(), 3);
    }
}
