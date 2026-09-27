//! Signed tree heads: a witness's commitment to the state of its log.

use serde::{Deserialize, Serialize};

use crate::encoding::Encoder;
use crate::keys::{Keypair, Signature, WitnessKey};
use crate::{Digest, Error, merkle};

const SIGNING_DOMAIN: &str = "witness/tree-head/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHead {
    /// The log's identity, which is the witness key that signs it.
    pub log: WitnessKey,
    pub size: u64,
    pub root: Digest,
    pub timestamp_ms: i64,
}

impl TreeHead {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(SIGNING_DOMAIN);
        e.fixed(&self.log.0)
            .u64(self.size)
            .fixed(self.root.as_bytes())
            .i64(self.timestamp_ms);
        e.finish()
    }

    pub fn sign(self, key: &Keypair) -> Result<SignedTreeHead, Error> {
        if key.public() != self.log {
            return Err(Error::Malformed("tree head names a different log key"));
        }
        let signature = key.sign(&self.signing_bytes());
        Ok(SignedTreeHead {
            head: self,
            signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub head: TreeHead,
    pub signature: Signature,
}

impl SignedTreeHead {
    pub fn verify(&self) -> Result<(), Error> {
        self.head
            .log
            .verify(&self.head.signing_bytes(), &self.signature)
    }

    /// Two validly signed heads of the same log and size with different
    /// roots are cryptographic proof that the log forked (equivocated).
    pub fn is_equivocation_with(&self, other: &SignedTreeHead) -> bool {
        self.head.log == other.head.log
            && self.head.size == other.head.size
            && self.head.root != other.head.root
            && self.verify().is_ok()
            && other.verify().is_ok()
    }

    /// Check that `newer` extends this head, given a consistency proof.
    pub fn verify_extension(&self, newer: &SignedTreeHead, proof: &[Digest]) -> Result<(), Error> {
        self.verify()?;
        newer.verify()?;
        if self.head.log != newer.head.log {
            return Err(Error::Malformed("tree heads belong to different logs"));
        }
        if merkle::verify_consistency(
            self.head.size,
            newer.head.size,
            &self.head.root,
            &newer.head.root,
            proof,
        ) {
            Ok(())
        } else {
            Err(Error::Inconsistent)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{consistency_proof, leaf_hash, root};

    #[test]
    fn extension_and_equivocation() {
        let kp = Keypair::generate().unwrap();
        let leaves: Vec<_> = (0..9u8).map(|i| leaf_hash(&[i])).collect();
        let head = |n: usize, l: &[Digest]| {
            TreeHead {
                log: kp.public(),
                size: n as u64,
                root: root(&l[..n]),
                timestamp_ms: n as i64,
            }
            .sign(&kp)
            .unwrap()
        };
        let a = head(5, &leaves);
        let b = head(9, &leaves);
        a.verify_extension(&b, &consistency_proof(&leaves, 5).unwrap())
            .unwrap();

        let mut forked = leaves.clone();
        forked[2] = leaf_hash(b"x");
        let c = head(5, &forked);
        assert!(a.is_equivocation_with(&c));
        assert!(!a.is_equivocation_with(&a));
    }
}
