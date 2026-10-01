//! Self-contained evidence bundles.
//!
//! A bundle carries everything a third party needs to check a claim without
//! trusting the witness's server: the signed attestation, its inclusion proof
//! against a signed tree head, and optionally the captured bytes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use sha2::{Digest as _, Sha256};

use crate::attestation::SignedAttestation;
use crate::net::{Cosignature, TlsnReceipt};
use crate::statement::Signed;
use crate::sth::SignedTreeHead;
use crate::{Digest, Error, merkle, ots};

pub const FORMAT: &str = "keepword-bundle/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub attestation: SignedAttestation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion: Option<Inclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Content>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsn: Option<TlsnEvidence>,
}

/// TLSNotary proof tier: a second witness's receipt for the TLS session,
/// and the received plaintext that links it to this attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsnEvidence {
    pub receipt: Signed<TlsnReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inclusion {
    pub leaf_index: u64,
    pub proof: Vec<Digest>,
    pub tree_head: SignedTreeHead,
    /// Other witnesses vouching that `tree_head` is consistent with
    /// everything they have seen from this log.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cosignatures: Vec<Signed<Cosignature>>,
}

/// Proof that the attestation was in the log before a Bitcoin block: an
/// inclusion proof into an anchored tree head, plus the OpenTimestamps proof
/// for that head.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Anchor {
    pub tree_head: SignedTreeHead,
    pub leaf_index: u64,
    pub proof: Vec<Digest>,
    pub ots_b64: String,
}

/// The digest Keepword timestamps for a tree head.
pub fn anchor_digest(head: &SignedTreeHead) -> [u8; 32] {
    Sha256::digest(head.head.signing_bytes()).into()
}

impl Anchor {
    /// Parse the proof and check it is for this tree head. Returns the
    /// attestations it contains (pending calendars, Bitcoin blocks).
    pub fn claims(&self) -> Result<Vec<ots::Claim>, Error> {
        let bytes = B64
            .decode(&self.ots_b64)
            .map_err(|_| Error::Malformed("anchor proof is not base64"))?;
        let d = ots::DetachedTimestamp::from_bytes(&bytes)?;
        if d.digest != anchor_digest(&self.tree_head) {
            return Err(Error::Malformed(
                "anchor proof is for a different tree head",
            ));
        }
        Ok(d.timestamp.claims())
    }
}

/// Captured bytes. Any part may be withheld (for example after an erasure
/// request) without affecting the other checks.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Content {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
    /// Normalized text, as hashed into `norm.hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized: Option<String>,
    /// Site rules that were part of the normalizer profile, so a verifier
    /// can re-run normalization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub norm_rules: Option<serde_json::Value>,
}

impl Content {
    pub fn headers(&self) -> Option<Result<Vec<u8>, base64::DecodeError>> {
        self.headers_b64.as_ref().map(|s| B64.decode(s))
    }

    pub fn body(&self) -> Option<Result<Vec<u8>, base64::DecodeError>> {
        self.body_b64.as_ref().map(|s| B64.decode(s))
    }

    pub fn encode(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn push(&mut self, name: &str, status: Status, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }

    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.status != Status::Fail)
    }

    fn passed(&self, name: &str) -> Option<&Check> {
        self.checks
            .iter()
            .find(|c| c.name == name && c.status == Status::Pass)
    }

    /// How far a bundle that passed every check reaches; `None` if a
    /// check failed. "No check failed" alone says little: a bare signed
    /// attestation passes too.
    pub fn strength(&self) -> Option<Strength> {
        if !self.ok() || self.passed("signature").is_none() {
            return None;
        }
        Some(
            match (
                self.passed("log inclusion").is_some(),
                self.passed("cosignatures").is_some(),
            ) {
                (true, true) => Strength::Cosigned,
                (true, false) => Strength::Logged,
                _ => Strength::SignedOnly,
            },
        )
    }

    /// In plain words, what a passing bundle shows, and what it doesn't.
    pub fn summary(&self) -> Summary {
        let mut shows = Vec::new();
        let mut not = Vec::new();
        if let Some(c) = self.passed("signature") {
            shows.push(format!(
                "a witness ({}) signed that it saw this page at the stated time",
                c.detail.trim_start_matches("signed by witness ")
            ));
        }
        if self.passed("log inclusion").is_some() {
            shows.push("the statement is in that witness's append-only public log".into());
        } else {
            not.push(
                "that the witness recorded it publicly: without its log, it could sign contradicting statements".into(),
            );
        }
        if let Some(c) = self.passed("cosignatures") {
            shows.push(format!("{}, vouching for that log's history", c.detail));
            not.push(
                "who the cosigners are: this bundle can't tell independent witnesses from keys the same operator controls".into(),
            );
        }
        match self.passed("not before") {
            Some(c) => shows.push(c.detail.clone()),
            None => not.push("an earliest time (no drand beacon)".into()),
        }
        match self.passed("anchor") {
            Some(c) => shows.push(c.detail.clone()),
            None => not.push("a Bitcoin-confirmed latest time (no checked anchor)".into()),
        }
        if self.passed("tls notary").is_some() {
            shows.push(
                "a second witness took part in the TLS connection and confirms the server sent this content".into(),
            );
        } else {
            not.push(
                "that the website really sent it: a dishonest witness could have made the content up".into(),
            );
        }
        if self.passed("body").is_some() || self.passed("normalized").is_some() {
            shows.push("the included content is exactly what was signed".into());
        }
        not.push(
            "that independent witnesses saw the same: `keepword verdict` shows that, and bundles don't carry it yet".into(),
        );
        Summary {
            strength: self.strength(),
            shows,
            does_not_show: not,
        }
    }
}

/// How far a bundle's evidence reaches, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// Only the witness's signature.
    SignedOnly,
    /// Also in the witness's append-only log.
    Logged,
    /// Also cosigned by other keys.
    Cosigned,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::SignedOnly => "SIGNED ONLY",
            Strength::Logged => "LOGGED",
            Strength::Cosigned => "LOGGED + COSIGNED",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub strength: Option<Strength>,
    pub shows: Vec<String>,
    pub does_not_show: Vec<String>,
}

impl Bundle {
    pub fn new(attestation: SignedAttestation) -> Self {
        Bundle {
            format: FORMAT.into(),
            attestation,
            inclusion: None,
            content: None,
            anchor: None,
            tlsn: None,
        }
    }

    /// Run every check that doesn't need the normalizer. Callers that can
    /// re-run normalization add a check of their own.
    pub fn verify(&self) -> Report {
        let mut r = Report::default();
        let a = &self.attestation.attestation;

        if self.format != FORMAT {
            r.push(
                "format",
                Status::Fail,
                format!("unknown format {:?}", self.format),
            );
            return r;
        }

        match self.attestation.verify() {
            Ok(()) => r.push(
                "signature",
                Status::Pass,
                format!("signed by witness {}", a.witness),
            ),
            Err(e) => r.push("signature", Status::Fail, e.to_string()),
        }

        let id = self.attestation.id();
        match &self.inclusion {
            None => r.push(
                "log inclusion",
                Status::Skip,
                "no inclusion proof in bundle",
            ),
            Some(inc) => {
                let th = &inc.tree_head;
                if let Err(e) = th.verify() {
                    r.push("tree head", Status::Fail, e.to_string());
                } else if th.head.log != a.witness {
                    r.push(
                        "tree head",
                        Status::Fail,
                        "tree head is from a different log",
                    );
                } else {
                    r.push(
                        "tree head",
                        Status::Pass,
                        format!("size {} root {}", th.head.size, th.head.root.short()),
                    );
                    let leaf = merkle::leaf_hash(id.as_bytes());
                    if merkle::verify_inclusion(
                        &leaf,
                        inc.leaf_index,
                        th.head.size,
                        &inc.proof,
                        &th.head.root,
                    ) {
                        r.push(
                            "log inclusion",
                            Status::Pass,
                            format!("leaf {} of {}", inc.leaf_index, th.head.size),
                        );
                    } else {
                        r.push(
                            "log inclusion",
                            Status::Fail,
                            "inclusion proof does not match tree head",
                        );
                    }
                    if th.head.timestamp_ms < a.fetched_at_ms {
                        r.push(
                            "timeline",
                            Status::Fail,
                            "tree head is older than the capture it includes",
                        );
                    }
                    check_cosignatures(&mut r, th, &inc.cosignatures);
                }
            }
        }

        match &a.beacon {
            None => r.push("not before", Status::Skip, "no drand beacon in attestation"),
            Some(b) => match b.verify() {
                Err(_) => r.push(
                    "not before",
                    Status::Fail,
                    "drand beacon signature is invalid",
                ),
                // Allow a minute of clock skew between the witness and drand.
                Ok(()) if b.time_ms() > a.fetched_at_ms.saturating_add(crate::beacon::SKEW_MS) => r
                    .push(
                        "not before",
                        Status::Fail,
                        format!(
                            "beacon round {} is from after the claimed capture time",
                            b.round
                        ),
                    ),
                Ok(()) => r.push(
                    "not before",
                    Status::Pass,
                    format!(
                        "captured after {} (drand round {}, {}s before the claimed time)",
                        crate::format_ms(b.time_ms()),
                        b.round,
                        (a.fetched_at_ms - b.time_ms()) / 1000
                    ),
                ),
            },
        }

        if let Some(anchor) = &self.anchor {
            check_anchor(&mut r, &self.attestation, anchor);
        }
        if let Some(t) = &self.tlsn {
            check_tlsn(&mut r, &self.attestation, t);
        }

        let content = self.content.clone().unwrap_or_default();
        check_bytes(&mut r, "headers", content.headers(), &a.headers_hash, None);
        check_bytes(
            &mut r,
            "body",
            content.body(),
            &a.body_hash,
            Some(a.body_len),
        );
        match (&content.normalized, &a.norm) {
            (Some(text), Some(n)) => {
                if Digest::of(text.as_bytes()) == n.hash {
                    r.push(
                        "normalized",
                        Status::Pass,
                        format!("matches {}", n.hash.short()),
                    );
                } else {
                    r.push(
                        "normalized",
                        Status::Fail,
                        "normalized text does not match norm hash",
                    );
                }
            }
            (Some(_), None) => r.push("normalized", Status::Fail, "attestation has no norm hash"),
            (None, _) => r.push("normalized", Status::Skip, "normalized text not included"),
        }
        r
    }
}

fn check_cosignatures(r: &mut Report, th: &SignedTreeHead, cosigs: &[Signed<Cosignature>]) {
    let mut good = std::collections::BTreeSet::new();
    let mut bad = 0;
    for c in cosigs {
        if c.verify().is_ok() && c.body.covers(th) && c.body.cosigner != th.head.log {
            good.insert(c.body.cosigner);
        } else {
            bad += 1;
        }
    }
    if bad > 0 {
        r.push(
            "cosignatures",
            Status::Fail,
            format!("{bad} invalid cosignatures"),
        );
    } else if good.is_empty() {
        r.push(
            "cosignatures",
            Status::Skip,
            "no other witness has cosigned this tree head",
        );
    } else {
        r.push(
            "cosignatures",
            Status::Pass,
            format!(
                "tree head cosigned by {} other key{}",
                good.len(),
                if good.len() == 1 { "" } else { "s" }
            ),
        );
    }
}

fn check_anchor(r: &mut Report, att: &SignedAttestation, anchor: &Anchor) {
    let th = &anchor.tree_head;
    if th.verify().is_err() || th.head.log != att.attestation.witness {
        r.push(
            "anchor",
            Status::Fail,
            "anchored tree head is not signed by this witness",
        );
        return;
    }
    let leaf = merkle::leaf_hash(att.id().as_bytes());
    let idx = anchor.leaf_index;
    if !merkle::verify_inclusion(&leaf, idx, th.head.size, &anchor.proof, &th.head.root) {
        r.push(
            "anchor",
            Status::Fail,
            "attestation is not in the anchored tree head",
        );
        return;
    }
    match anchor.claims() {
        Err(e) => r.push("anchor", Status::Fail, e.to_string()),
        Ok(claims) => {
            let blocks: Vec<String> = claims
                .iter()
                .filter_map(|c| match c.attestation {
                    ots::Attestation::Bitcoin { height } => Some(format!(
                        "block {height} (merkle root {})",
                        c.bitcoin_merkle_root_hex().unwrap_or_default()
                    )),
                    _ => None,
                })
                .collect();
            let detail = if blocks.is_empty() {
                format!("leaf {idx} of anchored head; timestamp still pending at the calendars")
            } else {
                format!(
                    "leaf {idx} of anchored head; commits to Bitcoin {}, not yet checked against the chain",
                    blocks.join(", ")
                )
            };
            r.push("anchor", Status::Skip, detail);
        }
    }
}

fn check_tlsn(r: &mut Report, att: &SignedAttestation, t: &TlsnEvidence) {
    let a = &att.attestation;
    let rc = &t.receipt.body;
    let host = url::Url::parse(&a.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    let problem = if t.receipt.verify().is_err() {
        Some("receipt signature is invalid".to_string())
    } else if rc.prover != a.witness {
        Some("receipt is for a different prover".into())
    } else if rc.verifier == a.witness {
        Some("a witness cannot notarize its own capture".into())
    } else if host.as_deref() != Some(rc.server_name.to_ascii_lowercase().as_str()) {
        Some(format!(
            "receipt is for server {}, not {}",
            rc.server_name,
            host.unwrap_or_default()
        ))
    } else if rc.verified_at_ms.abs_diff(a.fetched_at_ms) > 10 * 60_000 {
        Some("receipt time does not match the capture time".into())
    } else {
        None
    };
    if let Some(p) = problem {
        r.push("tls notary", Status::Fail, p);
        return;
    }
    let Some(raw) = t.received_b64.as_ref() else {
        r.push(
            "tls notary",
            Status::Skip,
            "valid receipt, but the transcript that links it to this body is not included",
        );
        return;
    };
    let Ok(raw) = B64.decode(raw) else {
        r.push("tls notary", Status::Fail, "transcript is not base64");
        return;
    };
    if Digest::of(&raw) != rc.received_hash || raw.len() as u64 != rc.received_len {
        r.push(
            "tls notary",
            Status::Fail,
            "transcript does not match the receipt",
        );
        return;
    }
    match crate::httpmsg::parse_response(&raw) {
        Ok(resp)
            if Digest::of(&resp.body) == a.body_hash
                && Digest::of(&resp.header_block) == a.headers_hash
                && resp.status == a.status =>
        {
            r.push(
                "tls notary",
                Status::Pass,
                format!(
                    "witness {} verified the TLS session with {} (MPC-TLS); the body came from that server",
                    rc.verifier.short(),
                    rc.server_name
                ),
            )
        }
        Ok(_) => r.push("tls notary", Status::Fail, "transcript does not produce this attestation's response"),
        Err(e) => r.push("tls notary", Status::Fail, format!("transcript: {e}")),
    }
}

fn check_bytes(
    r: &mut Report,
    name: &str,
    bytes: Option<Result<Vec<u8>, base64::DecodeError>>,
    want: &Digest,
    want_len: Option<u64>,
) {
    match bytes {
        None => r.push(name, Status::Skip, "not included"),
        Some(Err(e)) => r.push(name, Status::Fail, format!("bad base64: {e}")),
        Some(Ok(b)) => {
            if Digest::of(&b) != *want {
                r.push(name, Status::Fail, "hash mismatch");
            } else if want_len.is_some_and(|l| l != b.len() as u64) {
                r.push(name, Status::Fail, "length mismatch");
            } else {
                r.push(
                    name,
                    Status::Pass,
                    format!("{} bytes, hash {}", b.len(), want.short()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_reflects_what_passed() {
        let mut r = Report::default();
        r.push("signature", Status::Pass, "signed by witness abc");
        r.push("log inclusion", Status::Skip, "no inclusion proof");
        r.push("cosignatures", Status::Skip, "none");
        assert_eq!(r.strength(), Some(Strength::SignedOnly));
        let s = r.summary();
        assert!(
            s.does_not_show
                .iter()
                .any(|l| l.contains("recorded it publicly"))
        );
        assert!(
            s.does_not_show
                .iter()
                .any(|l| l.contains("made the content up"))
        );

        let mut r = Report::default();
        r.push("signature", Status::Pass, "signed by witness abc");
        r.push("log inclusion", Status::Pass, "leaf 1 of 2");
        r.push(
            "cosignatures",
            Status::Pass,
            "tree head cosigned by 3 other keys",
        );
        assert_eq!(r.strength(), Some(Strength::Cosigned));
        assert!(
            r.summary()
                .does_not_show
                .iter()
                .any(|l| l.contains("same operator"))
        );

        r.push("body", Status::Fail, "hash mismatch");
        assert_eq!(r.strength(), None);
    }

    /// Both times come signed from keys anyone can make: any two values
    /// far apart fail the check, the extremes too.
    #[test]
    fn receipt_times_far_from_the_capture_fail() {
        let prover = crate::Keypair::generate().unwrap();
        let verifier = crate::Keypair::generate().unwrap();
        let t = 1_700_000_000_000;
        for (fetched, verified, want) in [
            (t, t + 5 * 60_000, Status::Skip),
            (t, t + 11 * 60_000, Status::Fail),
            (i64::MIN, 0, Status::Fail),
            (-(1 << 62), 1 << 62, Status::Fail),
            (i64::MAX, i64::MIN, Status::Fail),
        ] {
            let mut a = crate::attestation::tests::sample(&prover);
            a.fetched_at_ms = fetched;
            let receipt = Signed::sign(
                TlsnReceipt {
                    prover: prover.public(),
                    server_name: "example.com".into(),
                    sent_hash: Digest::of(b"request"),
                    received_hash: Digest::of(b"response"),
                    received_len: 8,
                    verified_at_ms: verified,
                    verifier: verifier.public(),
                },
                &verifier,
            )
            .unwrap();
            let evidence = TlsnEvidence {
                receipt,
                received_b64: None,
            };
            let mut r = Report::default();
            check_tlsn(&mut r, &a.sign(&prover).unwrap(), &evidence);
            assert_eq!(r.checks[0].status, want, "{fetched} {verified}: {r:?}");
        }
    }
}
