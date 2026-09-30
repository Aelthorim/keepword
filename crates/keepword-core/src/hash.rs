//! BLAKE3 digests with hex serialization.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte BLAKE3 digest. Every hash in the protocol is one of these,
/// except the TLS certificate fingerprint, which is SHA-256 for crt.sh
/// compatibility.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub const ZERO: Digest = Digest([0; 32]);

    pub fn of(data: &[u8]) -> Self {
        Digest(*blake3::hash(data).as_bytes())
    }

    /// Hash with a domain-separation tag so a digest computed for one purpose
    /// can never be replayed as a digest for another.
    pub fn tagged(tag: &str, parts: &[&[u8]]) -> Self {
        let mut h = blake3::Hasher::new_derive_key(tag);
        for p in parts {
            h.update(&(p.len() as u64).to_be_bytes());
            h.update(p);
        }
        Digest(*h.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 12 hex characters, for display only.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        b.try_into().ok().map(Digest)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Digest {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = hex::decode(s).map_err(|_| crate::Error::Malformed("digest is not hex"))?;
        Digest::from_slice(&v).ok_or(crate::Error::Malformed("digest must be 32 bytes"))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Serde helper for fixed-size byte arrays as hex strings.
pub(crate) mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let d = Digest::of(b"hello");
        let s = serde_json::to_string(&d).unwrap();
        let back: Digest = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
        assert_eq!(d.to_string().parse::<Digest>().unwrap(), d);
    }

    #[test]
    fn tagged_is_unambiguous() {
        // Length prefixes prevent ("ab","c") colliding with ("a","bc").
        let a = Digest::tagged("t", &[b"ab", b"c"]);
        let b = Digest::tagged("t", &[b"a", b"bc"]);
        assert_ne!(a, b);
        assert_ne!(Digest::tagged("t1", &[b"x"]), Digest::tagged("t2", &[b"x"]));
    }
}
