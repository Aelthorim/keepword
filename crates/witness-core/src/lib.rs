//! Protocol core for Witness.
//!
//! Everything here is pure: no I/O, no clocks, no network. That keeps the
//! rules every node and verifier must agree on in one small, testable place.

pub mod assign;
pub mod attestation;
pub mod bundle;
pub mod encoding;
mod hash;
pub mod keys;
pub mod merkle;
pub mod quorum;
pub mod sth;
pub mod target;

pub use attestation::{Attestation, CaptureMethod, NormCommitment, SignedAttestation, Vantage};
pub use hash::Digest;
pub use keys::{Keypair, Signature, WitnessKey};
pub use sth::{SignedTreeHead, TreeHead};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("signature verification failed")]
    BadSignature,
    #[error("tree heads are inconsistent")]
    Inconsistent,
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Format a millisecond Unix timestamp as RFC 3339 (UTC).
pub fn format_ms(ms: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ms.to_string())
}

pub fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}
