//! drand public randomness: unpredictable epoch seeds for assignment, and a
//! lower bound on capture times.
//!
//! Beacons are BLS signatures by the drand League of Entropy threshold
//! network, so they verify offline against a fixed public key and can be
//! passed around by anyone (including over gossip) without trusting the
//! carrier. Keepword uses the `quicknet` chain: unchained, one round every
//! three seconds.

use drand_verify::{G2PubkeyRfc, Pubkey, derive_randomness};
use serde::{Deserialize, Serialize};

use crate::{Digest, Error};

/// quicknet chain hash, as used in drand HTTP API paths.
pub const QUICKNET_CHAIN_HASH: &str =
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
/// quicknet group public key (G2).
const QUICKNET_PUBKEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
/// Unix seconds of round 1.
pub const QUICKNET_GENESIS: i64 = 1_692_803_367;
pub const QUICKNET_PERIOD: i64 = 3;

/// One epoch of assignment lasts a day.
pub const EPOCH_MS: i64 = 86_400_000;

/// Clock skew allowed between a witness and drand: a capture may claim a
/// time up to this much before the round its beacon was published.
pub const SKEW_MS: i64 = 60_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Beacon {
    pub round: u64,
    /// BLS signature (G1, compressed), hex in JSON.
    #[serde(with = "hex_vec")]
    pub signature: Vec<u8>,
}

impl Beacon {
    pub fn verify(&self) -> Result<(), Error> {
        let pk_bytes: [u8; 96] = hex::decode(QUICKNET_PUBKEY)
            .expect("constant is hex")
            .try_into()
            .expect("constant is 96 bytes");
        let pk = G2PubkeyRfc::from_fixed(pk_bytes).map_err(|e| Error::Crypto(e.to_string()))?;
        match pk.verify(self.round, b"", &self.signature) {
            Ok(true) => Ok(()),
            _ => Err(Error::BadSignature),
        }
    }

    pub fn randomness(&self) -> Digest {
        Digest(derive_randomness(&self.signature))
    }

    /// When this round was published (Unix ms).
    pub fn time_ms(&self) -> i64 {
        round_time_ms(self.round)
    }
}

/// Saturates instead of wrapping: rounds come from untrusted messages.
pub fn round_time_ms(round: u64) -> i64 {
    let round = i64::try_from(round).unwrap_or(i64::MAX);
    QUICKNET_GENESIS
        .saturating_add(round.saturating_sub(1).saturating_mul(QUICKNET_PERIOD))
        .saturating_mul(1000)
}

/// The first round published at or after `t_ms`.
pub fn round_at(t_ms: i64) -> u64 {
    let t = t_ms.div_euclid(1000) - QUICKNET_GENESIS;
    if t <= 0 {
        return 1;
    }
    (t + QUICKNET_PERIOD - 1).div_euclid(QUICKNET_PERIOD) as u64 + 1
}

pub fn epoch_of(t_ms: i64) -> u64 {
    t_ms.div_euclid(EPOCH_MS).max(0) as u64
}

/// The beacon round whose randomness seeds `epoch`.
pub fn epoch_round(epoch: u64) -> u64 {
    round_at(epoch as i64 * EPOCH_MS)
}

/// The assignment seed for an epoch. Without a beacon the seed is
/// predictable, so assignment can be ground in advance; callers must label
/// such results as insecure.
pub fn epoch_seed(epoch: u64, beacon: Option<&Beacon>) -> Digest {
    match beacon {
        Some(b) => Digest::tagged(
            "keepword epoch-seed v1",
            &[&epoch.to_be_bytes(), b.randomness().as_bytes()],
        ),
        None => Digest::tagged("keepword epoch-seed insecure v1", &[&epoch.to_be_bytes()]),
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// quicknet round 123, from the drand API.
    pub fn round_123() -> Beacon {
        Beacon {
            round: 123,
            signature: hex::decode("b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92").unwrap(),
        }
    }

    #[test]
    fn verifies_real_beacon() {
        let b = round_123();
        b.verify().unwrap();
        let mut forged = b.clone();
        forged.round = 124;
        assert!(forged.verify().is_err());
        let mut forged = b.clone();
        forged.signature[10] ^= 1;
        assert!(forged.verify().is_err());
    }

    #[test]
    fn round_times() {
        assert_eq!(round_time_ms(1), QUICKNET_GENESIS * 1000);
        for r in [1u64, 2, 123, 5_000_000] {
            assert_eq!(round_at(round_time_ms(r)), r);
            assert_eq!(round_at(round_time_ms(r) - 1000), r);
        }
        assert!(round_time_ms(epoch_round(20_000)) >= 20_000 * EPOCH_MS);
        assert_eq!(round_time_ms(u64::MAX), i64::MAX);
        assert_eq!(round_time_ms(1 << 62), i64::MAX);
    }

    #[test]
    fn seeds_differ() {
        let b = round_123();
        assert_ne!(epoch_seed(1, Some(&b)), epoch_seed(1, None));
        assert_ne!(epoch_seed(1, Some(&b)), epoch_seed(2, Some(&b)));
    }
}
