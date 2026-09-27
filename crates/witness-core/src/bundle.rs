//! Self-contained evidence bundles.
//!
//! A bundle carries everything a third party needs to check a claim without
//! trusting the witness's server: the signed attestation, its inclusion proof
//! against a signed tree head, and optionally the captured bytes.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::attestation::SignedAttestation;
use crate::sth::SignedTreeHead;
use crate::{merkle, Digest};

pub const FORMAT: &str = "witness-bundle/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub attestation: SignedAttestation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion: Option<Inclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Content>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inclusion {
    pub leaf_index: u64,
    pub proof: Vec<Digest>,
    pub tree_head: SignedTreeHead,
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
}

impl Bundle {
    pub fn new(attestation: SignedAttestation) -> Self {
        Bundle {
            format: FORMAT.into(),
            attestation,
            inclusion: None,
            content: None,
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
                }
            }
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
