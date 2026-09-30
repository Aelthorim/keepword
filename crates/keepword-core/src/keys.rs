//! Ed25519 witness identities.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

/// A witness's public key. It is also the witness's log ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WitnessKey(pub [u8; 32]);

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

/// A witness's signing key.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Keypair {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> WitnessKey {
        WitnessKey(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.signing.sign(msg).to_bytes())
    }
}

impl WitnessKey {
    /// Strict verification: rejects small-order keys and non-canonical
    /// signatures, so a signature can't be malleated into a second valid one
    /// (which would give the same statement two attestation IDs).
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| Error::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify_strict(msg, &sig).map_err(|_| Error::BadSignature)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }
}

impl fmt::Debug for WitnessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WitnessKey({})", self.to_hex())
    }
}

impl fmt::Display for WitnessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for WitnessKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let v = hex::decode(s).map_err(|_| Error::Malformed("key is not hex"))?;
        let b: [u8; 32] = v
            .try_into()
            .map_err(|_| Error::Malformed("key must be 32 bytes"))?;
        Ok(WitnessKey(b))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

macro_rules! hex_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                crate::hash::hex_array::serialize(&self.0, s)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                crate::hash::hex_array::deserialize(d).map(Self)
            }
        }
    };
}

hex_serde!(WitnessKey);
hex_serde!(Signature);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign(b"msg");
        kp.public().verify(b"msg", &sig).unwrap();
        assert!(kp.public().verify(b"other", &sig).is_err());
        let kp2 = Keypair::from_seed(&kp.seed());
        assert_eq!(kp2.public(), kp.public());
    }
}
