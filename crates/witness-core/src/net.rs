//! Network protocol messages.
//!
//! Nodes exchange these over HTTP (see docs/DESIGN.md §6). All of them are
//! signed statements, so they can be relayed by anyone without trusting the
//! relay; `Gossip` is the envelope for flooding them between peers.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::attestation::Vantage;
use crate::beacon::Beacon;
use crate::encoding::Encoder;
use crate::keys::WitnessKey;
use crate::statement::{Signed, Statement};
use crate::sth::SignedTreeHead;
use crate::{Digest, Error};

/// A node announcing itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    pub key: WitnessKey,
    /// Public base URL of the node's API, or `None` for nodes that can't
    /// accept connections (behind NAT); those push and pull but aren't
    /// mirrored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Self-reported; see `Observation` for how it gets corroborated.
    #[serde(default)]
    pub vantage: Vantage,
    pub issued_at_ms: i64,
    pub software: String,
}

impl Statement for Descriptor {
    const DOMAIN: &'static str = "witness/descriptor/v1";
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.key.0)
            .opt(self.endpoint.as_deref(), |e, v| {
                e.str(v);
            })
            .opt(self.vantage.asn, |e, v| {
                e.u32(v);
            })
            .opt(self.vantage.country.as_deref(), |e, v| {
                e.str(v);
            })
            .i64(self.issued_at_ms)
            .str(&self.software);
    }
    fn signer(&self) -> WitnessKey {
        self.key
    }
}

/// A request for the network to watch a URL. Only the witnesses assigned to
/// the URL in the current epoch act on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchRequest {
    pub url: String,
    pub every_secs: u64,
    #[serde(default)]
    pub render: bool,
    pub requester: WitnessKey,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl Statement for WatchRequest {
    const DOMAIN: &'static str = "witness/watch-request/v1";
    fn encode(&self, e: &mut Encoder) {
        e.str(&self.url)
            .u64(self.every_secs)
            .u8(self.render as u8)
            .fixed(&self.requester.0)
            .i64(self.issued_at_ms)
            .i64(self.expires_at_ms);
    }
    fn signer(&self) -> WitnessKey {
        self.requester
    }
}

/// A witness's statement that it has checked a log's tree head and that it
/// is consistent with every earlier head it has seen from that log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    pub log: WitnessKey,
    pub size: u64,
    pub root: Digest,
    pub timestamp_ms: i64,
    pub cosigner: WitnessKey,
}

impl Statement for Cosignature {
    const DOMAIN: &'static str = "witness/cosignature/v1";
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.log.0)
            .u64(self.size)
            .fixed(self.root.as_bytes())
            .i64(self.timestamp_ms)
            .fixed(&self.cosigner.0);
    }
    fn signer(&self) -> WitnessKey {
        self.cosigner
    }
}

impl Cosignature {
    pub fn covers(&self, head: &SignedTreeHead) -> bool {
        self.log == head.head.log && self.size == head.head.size && self.root == head.head.root
    }
}

/// "I saw `subject` connect to me from `ip`." Receipts from several
/// independent observers establish where a node actually is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub subject: WitnessKey,
    pub ip: IpAddr,
    pub observed_at_ms: i64,
    pub observer: WitnessKey,
}

impl Statement for Observation {
    const DOMAIN: &'static str = "witness/observation/v1";
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.subject.0)
            .ip(&self.ip)
            .i64(self.observed_at_ms)
            .fixed(&self.observer.0);
    }
    fn signer(&self) -> WitnessKey {
        self.observer
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// Independent witnesses saw different content at the same time.
    Split,
    /// A page changed without disclosing it.
    SilentEdit,
    /// A log signed two different histories.
    Equivocation,
}

impl AlertKind {
    fn code(self) -> u8 {
        match self {
            AlertKind::Split => 1,
            AlertKind::SilentEdit => 2,
            AlertKind::Equivocation => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub kind: AlertKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub summary: String,
    /// Attestation IDs (or tree-head digests) that back the alert.
    pub evidence: Vec<Digest>,
    pub issued_at_ms: i64,
    pub issuer: WitnessKey,
}

impl Statement for Alert {
    const DOMAIN: &'static str = "witness/alert/v1";
    fn encode(&self, e: &mut Encoder) {
        e.u8(self.kind.code())
            .opt(self.url.as_deref(), |e, v| {
                e.str(v);
            })
            .str(&self.summary)
            .list(&self.evidence, |e, d| {
                e.fixed(d.as_bytes());
            })
            .i64(self.issued_at_ms)
            .fixed(&self.issuer.0);
    }
    fn signer(&self) -> WitnessKey {
        self.issuer
    }
}

/// Authenticates a push: `from` sent these messages to `to` at `sent_at`.
/// The receiver uses it to issue an `Observation` of the sender's address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushEnvelope {
    pub from: WitnessKey,
    pub to: WitnessKey,
    pub sent_at_ms: i64,
    /// Hash over the IDs of the pushed messages.
    pub payload: Digest,
}

impl Statement for PushEnvelope {
    const DOMAIN: &'static str = "witness/push/v1";
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.from.0)
            .fixed(&self.to.0)
            .i64(self.sent_at_ms)
            .fixed(self.payload.as_bytes());
    }
    fn signer(&self) -> WitnessKey {
        self.from
    }
}

pub fn payload_digest(messages: &[Gossip]) -> Digest {
    let ids: Vec<u8> = messages.iter().flat_map(|m| m.id().0).collect();
    Digest::tagged("witness push-payload v1", &[&ids])
}

/// Everything that floods between peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Gossip {
    Descriptor(Signed<Descriptor>),
    Request(Signed<WatchRequest>),
    TreeHead(SignedTreeHead),
    Cosignature(Signed<Cosignature>),
    Observation(Signed<Observation>),
    Alert(Signed<Alert>),
    /// Two conflicting heads from one log: proof it forked.
    Equivocation {
        a: SignedTreeHead,
        b: SignedTreeHead,
    },
    Beacon(Beacon),
}

impl Gossip {
    pub fn kind(&self) -> &'static str {
        match self {
            Gossip::Descriptor(_) => "descriptor",
            Gossip::Request(_) => "request",
            Gossip::TreeHead(_) => "tree_head",
            Gossip::Cosignature(_) => "cosignature",
            Gossip::Observation(_) => "observation",
            Gossip::Alert(_) => "alert",
            Gossip::Equivocation { .. } => "equivocation",
            Gossip::Beacon(_) => "beacon",
        }
    }

    pub fn id(&self) -> Digest {
        let inner = match self {
            Gossip::Descriptor(s) => s.id(),
            Gossip::Request(s) => s.id(),
            Gossip::TreeHead(h) => Digest::tagged(
                "witness tree-head-id v1",
                &[&h.head.signing_bytes(), &h.signature.0],
            ),
            Gossip::Cosignature(s) => s.id(),
            Gossip::Observation(s) => s.id(),
            Gossip::Alert(s) => s.id(),
            Gossip::Equivocation { a, b } => {
                // Order-independent: the same pair is the same message.
                let (x, y) = if a.head.root <= b.head.root {
                    (a, b)
                } else {
                    (b, a)
                };
                Digest::tagged(
                    "witness equivocation-id v1",
                    &[&x.head.signing_bytes(), &y.head.signing_bytes()],
                )
            }
            Gossip::Beacon(b) => Digest::tagged(
                "witness beacon-id v1",
                &[&b.round.to_be_bytes(), &b.signature],
            ),
        };
        Digest::tagged(
            "witness gossip-id v1",
            &[self.kind().as_bytes(), inner.as_bytes()],
        )
    }

    /// Cryptographic validity only; policy checks (freshness, rate limits)
    /// are the receiver's business.
    pub fn verify(&self) -> Result<(), Error> {
        match self {
            Gossip::Descriptor(s) => s.verify(),
            Gossip::Request(s) => s.verify(),
            Gossip::TreeHead(h) => h.verify(),
            Gossip::Cosignature(s) => s.verify(),
            Gossip::Observation(s) => s.verify(),
            Gossip::Alert(s) => s.verify(),
            Gossip::Equivocation { a, b } => {
                if a.is_equivocation_with(b) {
                    Ok(())
                } else {
                    Err(Error::Malformed("not an equivocation"))
                }
            }
            Gossip::Beacon(b) => b.verify(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::sth::TreeHead;

    #[test]
    fn statements_sign_verify_and_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let d = Signed::sign(
            Descriptor {
                key: kp.public(),
                endpoint: Some("https://w.example".into()),
                vantage: Vantage {
                    asn: Some(3320),
                    country: Some("DE".into()),
                },
                issued_at_ms: 1,
                software: "witness/0.1".into(),
            },
            &kp,
        )
        .unwrap();
        let g = Gossip::Descriptor(d.clone());
        g.verify().unwrap();
        let json = serde_json::to_string(&g).unwrap();
        assert!(json.contains("\"type\":\"descriptor\""));
        let back: Gossip = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id(), g.id());
        back.verify().unwrap();

        let mut forged = d;
        forged.body.endpoint = Some("https://evil.example".into());
        assert!(Gossip::Descriptor(forged).verify().is_err());

        let other = Keypair::generate().unwrap();
        let obs = Observation {
            subject: kp.public(),
            ip: "203.0.113.9".parse().unwrap(),
            observed_at_ms: 5,
            observer: other.public(),
        };
        assert!(
            Signed::sign(obs.clone(), &kp).is_err(),
            "must be signed by the observer"
        );
        Signed::sign(obs, &other).unwrap().verify().unwrap();
    }

    #[test]
    fn equivocation_ids_are_symmetric() {
        let kp = Keypair::generate().unwrap();
        let h = |root: &[u8]| {
            TreeHead {
                log: kp.public(),
                size: 3,
                root: Digest::of(root),
                timestamp_ms: 0,
            }
            .sign(&kp)
            .unwrap()
        };
        let (a, b) = (h(b"a"), h(b"b"));
        let g1 = Gossip::Equivocation {
            a: a.clone(),
            b: b.clone(),
        };
        let g2 = Gossip::Equivocation { a: b, b: a.clone() };
        assert_eq!(g1.id(), g2.id());
        g1.verify().unwrap();
        assert!(Gossip::Equivocation { a: a.clone(), b: a }
            .verify()
            .is_err());
    }
}
