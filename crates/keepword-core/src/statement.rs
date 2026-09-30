//! Generic signed statements for the network protocol.
//!
//! Every message a node gossips is a small struct with a canonical encoding,
//! signed by the key it names. `Signed<T>` does the signing, verification
//! and content-derived IDs once for all of them.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::encoding::Encoder;
use crate::keys::{Keypair, Signature, WitnessKey};
use crate::{Digest, Error};

pub trait Statement: Clone + Serialize + DeserializeOwned {
    /// Domain-separation string; unique per statement type and version.
    const DOMAIN: &'static str;
    fn encode(&self, e: &mut Encoder);
    /// The key that must have signed this statement.
    fn signer(&self) -> WitnessKey;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "T: Statement")]
pub struct Signed<T> {
    pub body: T,
    pub signature: Signature,
}

pub fn signing_bytes<T: Statement>(body: &T) -> Vec<u8> {
    let mut e = Encoder::new(T::DOMAIN);
    body.encode(&mut e);
    e.finish()
}

impl<T: Statement> Signed<T> {
    pub fn sign(body: T, key: &Keypair) -> Result<Self, Error> {
        if body.signer() != key.public() {
            return Err(Error::Malformed("statement names a different signer"));
        }
        let signature = key.sign(&signing_bytes(&body));
        Ok(Signed { body, signature })
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.body
            .signer()
            .verify(&signing_bytes(&self.body), &self.signature)
    }

    pub fn id(&self) -> Digest {
        Digest::tagged(
            "keepword statement-id v1",
            &[&signing_bytes(&self.body), &self.signature.0],
        )
    }
}
