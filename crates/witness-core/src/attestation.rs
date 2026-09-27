//! Attestations: a witness's signed statement about what a URL served.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::beacon::Beacon;
use crate::encoding::Encoder;
use crate::keys::{Keypair, Signature, WitnessKey};
use crate::{Digest, Error};

const SIGNING_DOMAIN_V1: &str = "witness/attestation/v1";
/// v2 = v1 plus a drand beacon, which proves the capture happened after the
/// beacon's round was published. Attestations without a beacon keep the v1
/// encoding, so existing signatures stay valid.
const SIGNING_DOMAIN_V2: &str = "witness/attestation/v2";

/// How the witness obtained the content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMethod {
    /// A plain HTTP(S) request; the body is exactly the bytes served.
    Http,
    /// The DOM serialized by a headless browser after scripts ran.
    Rendered,
}

impl CaptureMethod {
    pub fn code(self) -> u8 {
        match self {
            CaptureMethod::Http => 1,
            CaptureMethod::Rendered => 2,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(CaptureMethod::Http),
            2 => Some(CaptureMethod::Rendered),
            _ => None,
        }
    }
}

/// Commitment to the normalized form of the content.
///
/// `profile` pins the exact normalizer version and site rules that produced
/// `hash`. Two witnesses' `hash` values are only comparable when their
/// profiles are equal; that lets the canonicalizer evolve without silently
/// breaking comparisons against old captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormCommitment {
    pub profile: Digest,
    pub hash: Digest,
}

/// Where the witness claims to have been on the network.
///
/// Self-reported, so it carries no weight on its own; see
/// `docs/DESIGN.md#vantage` for how peers corroborate it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vantage {
    pub asn: Option<u32>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Canonical requested URL.
    pub url: String,
    /// URL of the response that was recorded, after redirects.
    pub final_url: String,
    /// Every URL visited before `final_url`, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<String>,
    /// Unix time in milliseconds when the response was received.
    pub fetched_at_ms: i64,
    pub method: CaptureMethod,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// BLAKE3 of the HTTP status line and end-to-end headers as received.
    pub headers_hash: Digest,
    /// BLAKE3 of the response body exactly as received.
    pub body_hash: Digest,
    pub body_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub norm: Option<NormCommitment>,
    /// SHA-256 of the leaf certificate's DER, the fingerprint crt.sh uses.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
    pub cert_sha256: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    #[serde(default)]
    pub vantage: Vantage,
    pub witness: WitnessKey,
    /// The latest drand beacon the witness knew when it fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<Beacon>,
}

impl Attestation {
    /// The canonical bytes the witness signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let domain = if self.beacon.is_some() {
            SIGNING_DOMAIN_V2
        } else {
            SIGNING_DOMAIN_V1
        };
        let mut e = Encoder::new(domain);
        e.str(&self.url)
            .str(&self.final_url)
            .list(&self.redirects, |e, r| {
                e.str(r);
            })
            .i64(self.fetched_at_ms)
            .u8(self.method.code())
            .u16(self.status)
            .opt(self.content_type.as_deref(), |e, v| {
                e.str(v);
            })
            .fixed(self.headers_hash.as_bytes())
            .fixed(self.body_hash.as_bytes())
            .u64(self.body_len)
            .opt(self.norm.as_ref(), |e, n| {
                e.fixed(n.profile.as_bytes()).fixed(n.hash.as_bytes());
            })
            .opt(self.cert_sha256.as_ref(), |e, c| {
                e.fixed(c);
            })
            .opt(self.server_ip.as_ref(), |e, ip| {
                e.ip(ip);
            })
            .opt(self.vantage.asn, |e, a| {
                e.u32(a);
            })
            .opt(self.vantage.country.as_deref(), |e, c| {
                e.str(c);
            })
            .fixed(&self.witness.0);
        if let Some(b) = &self.beacon {
            e.u64(b.round).bytes(&b.signature);
        }
        e.finish()
    }

    pub fn sign(self, key: &Keypair) -> Result<SignedAttestation, Error> {
        if key.public() != self.witness {
            return Err(Error::Malformed(
                "attestation names a different witness key",
            ));
        }
        let signature = key.sign(&self.signing_bytes());
        Ok(SignedAttestation {
            attestation: self,
            signature,
        })
    }

    /// The hash that captures are compared on: the normalized hash when there
    /// is one, the body hash otherwise.
    pub fn comparison_hash(&self) -> Digest {
        self.norm.map(|n| n.hash).unwrap_or(self.body_hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub attestation: Attestation,
    pub signature: Signature,
}

impl SignedAttestation {
    pub fn verify(&self) -> Result<(), Error> {
        self.attestation
            .witness
            .verify(&self.attestation.signing_bytes(), &self.signature)
    }

    /// Content-derived ID. This is the leaf data appended to the witness's
    /// log, so the log commits to attestations without containing them, and
    /// an attestation can later be erased without breaking the log.
    pub fn id(&self) -> Digest {
        Digest::tagged(
            "witness attestation-id v1",
            &[&self.attestation.signing_bytes(), &self.signature.0],
        )
    }
}

mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        s.map(|s| {
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            v.try_into()
                .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        })
        .transpose()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample(kp: &Keypair) -> Attestation {
        Attestation {
            url: "https://example.com/".into(),
            final_url: "https://example.com/".into(),
            redirects: vec![],
            fetched_at_ms: 1_700_000_000_000,
            method: CaptureMethod::Http,
            status: 200,
            content_type: Some("text/html".into()),
            headers_hash: Digest::of(b"h"),
            body_hash: Digest::of(b"b"),
            body_len: 1,
            norm: Some(NormCommitment {
                profile: Digest::of(b"p"),
                hash: Digest::of(b"n"),
            }),
            cert_sha256: Some([7; 32]),
            server_ip: Some("93.184.216.34".parse().unwrap()),
            vantage: Vantage {
                asn: Some(3320),
                country: Some("DE".into()),
            },
            witness: kp.public(),
            beacon: None,
        }
    }

    #[test]
    fn sign_verify_and_tamper() {
        let kp = Keypair::generate().unwrap();
        let s = sample(&kp).sign(&kp).unwrap();
        s.verify().unwrap();

        let mut t = s.clone();
        t.attestation.status = 404;
        assert!(t.verify().is_err());
        assert_ne!(t.id(), s.id());

        let mut t = s.clone();
        t.attestation.vantage.country = Some("US".into());
        assert!(t.verify().is_err());
    }

    #[test]
    fn json_roundtrip_preserves_signature() {
        let kp = Keypair::generate().unwrap();
        let s = sample(&kp).sign(&kp).unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let back: SignedAttestation = serde_json::from_str(&json).unwrap();
        back.verify().unwrap();
        assert_eq!(back.id(), s.id());
    }

    #[test]
    fn refuses_foreign_key() {
        let kp = Keypair::generate().unwrap();
        let other = Keypair::generate().unwrap();
        assert!(sample(&kp).sign(&other).is_err());
    }
}
