//! OpenTimestamps proofs: anchoring tree heads in Bitcoin.
//!
//! A timestamp is a tree of operations (hash, append, prepend...) starting at
//! a message and ending in attestations: "pending at calendar X" or "this
//! value is the Merkle root of Bitcoin block N". Witness anchors
//! `SHA-256(tree-head signing bytes)`, so a `.ots` file produced here is an
//! ordinary detached timestamp that the standard `ots` client can also verify
//! against a file containing those bytes.
//!
//! Format reference: python-opentimestamps (`core/timestamp.py`, `op.py`,
//! `notary.py`, `serialize.py`).

use sha2::{Digest as _, Sha256};

use crate::Error;

pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const MAJOR_VERSION: u64 = 1;
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const TAG_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const MAX_OP_ARG: usize = 4096;
const MAX_DEPTH: usize = 256;
const MAX_MSG: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Sha1 => 0x02,
            Op::Ripemd160 => 0x03,
            Op::Sha256 => 0x08,
            Op::Keccak256 => 0x67,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
            Op::Reverse => 0xf2,
            Op::Hexlify => 0xf3,
        }
    }

    fn serialize(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        if let Op::Append(a) | Op::Prepend(a) = self {
            write_varbytes(out, a);
        }
    }

    pub fn apply(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let out = match self {
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Sha1 => {
                use sha1::Digest as _;
                sha1::Sha1::digest(msg).to_vec()
            }
            Op::Ripemd160 => {
                use ripemd::Digest as _;
                ripemd::Ripemd160::digest(msg).to_vec()
            }
            Op::Keccak256 => {
                return Err(Error::Malformed("keccak256 timestamps are not supported"))
            }
            Op::Append(a) => [msg, a].concat(),
            Op::Prepend(p) => [p.as_slice(), msg].concat(),
            Op::Reverse => msg.iter().rev().copied().collect(),
            Op::Hexlify => hex::encode(msg).into_bytes(),
        };
        if out.len() > MAX_MSG {
            return Err(Error::Malformed("timestamp message too long"));
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attestation {
    /// Submitted to a calendar that will commit it to Bitcoin later.
    Pending {
        uri: String,
    },
    /// The message is the Merkle root of this Bitcoin block.
    Bitcoin {
        height: u64,
    },
    Unknown {
        tag: [u8; 8],
        payload: Vec<u8>,
    },
}

impl Attestation {
    fn serialize(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        let tag = match self {
            Attestation::Pending { uri } => {
                write_varbytes(&mut payload, uri.as_bytes());
                TAG_PENDING
            }
            Attestation::Bitcoin { height } => {
                write_varuint(&mut payload, *height);
                TAG_BITCOIN
            }
            Attestation::Unknown { tag, payload: p } => {
                payload.extend_from_slice(p);
                *tag
            }
        };
        out.extend_from_slice(&tag);
        write_varbytes(out, &payload);
    }

    fn sort_key(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.serialize(&mut v);
        v
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub msg: Vec<u8>,
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Op, Timestamp)>,
}

/// A leaf of the proof tree: an attestation and the message it attests to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub msg: Vec<u8>,
    pub attestation: Attestation,
}

impl Claim {
    /// For Bitcoin claims: the block Merkle root in the byte order block
    /// explorers display.
    pub fn bitcoin_merkle_root_hex(&self) -> Option<String> {
        match self.attestation {
            Attestation::Bitcoin { .. } if self.msg.len() == 32 => Some(hex::encode(
                self.msg.iter().rev().copied().collect::<Vec<_>>(),
            )),
            _ => None,
        }
    }
}

impl Timestamp {
    pub fn new(msg: Vec<u8>) -> Self {
        Timestamp {
            msg,
            attestations: vec![],
            ops: vec![],
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        let mut atts: Vec<&Attestation> = self.attestations.iter().collect();
        atts.sort_by_key(|a| a.sort_key());
        let mut ops: Vec<&(Op, Timestamp)> = self.ops.iter().collect();
        ops.sort_by_key(|(op, _)| {
            let mut v = Vec::new();
            op.serialize(&mut v);
            v
        });
        if atts.len() > 1 {
            for a in &atts[..atts.len() - 1] {
                out.extend_from_slice(&[0xff, 0x00]);
                a.serialize(out);
            }
        }
        if ops.is_empty() {
            if let Some(last) = atts.last() {
                out.push(0x00);
                last.serialize(out);
            }
        } else {
            if let Some(last) = atts.last() {
                out.extend_from_slice(&[0xff, 0x00]);
                last.serialize(out);
            }
            for (op, ts) in &ops[..ops.len() - 1] {
                out.push(0xff);
                op.serialize(out);
                ts.serialize(out);
            }
            let (op, ts) = ops.last().expect("non-empty");
            op.serialize(out);
            ts.serialize(out);
        }
    }

    pub fn deserialize(r: &mut Reader<'_>, msg: Vec<u8>) -> Result<Self, Error> {
        Self::deser(r, msg, 0)
    }

    fn deser(r: &mut Reader<'_>, msg: Vec<u8>, depth: usize) -> Result<Self, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Malformed("timestamp nested too deeply"));
        }
        let mut ts = Timestamp::new(msg);
        let mut tag = r.byte()?;
        while tag == 0xff {
            let t = r.byte()?;
            ts.branch(r, t, depth)?;
            tag = r.byte()?;
        }
        ts.branch(r, tag, depth)?;
        Ok(ts)
    }

    fn branch(&mut self, r: &mut Reader<'_>, tag: u8, depth: usize) -> Result<(), Error> {
        if tag == 0x00 {
            let t: [u8; 8] = r.take(8)?.try_into().expect("8 bytes");
            let payload = r.varbytes(8192)?;
            let mut p = Reader::new(&payload);
            let att = match t {
                TAG_PENDING => {
                    let uri = String::from_utf8(p.varbytes(1000)?)
                        .map_err(|_| Error::Malformed("calendar URI is not UTF-8"))?;
                    Attestation::Pending { uri }
                }
                TAG_BITCOIN => Attestation::Bitcoin {
                    height: p.varuint()?,
                },
                _ => Attestation::Unknown { tag: t, payload },
            };
            self.attestations.push(att);
            return Ok(());
        }
        let op = match tag {
            0x02 => Op::Sha1,
            0x03 => Op::Ripemd160,
            0x08 => Op::Sha256,
            0x67 => Op::Keccak256,
            0xf0 => Op::Append(r.varbytes(MAX_OP_ARG)?),
            0xf1 => Op::Prepend(r.varbytes(MAX_OP_ARG)?),
            0xf2 => Op::Reverse,
            0xf3 => Op::Hexlify,
            _ => return Err(Error::Malformed("unknown timestamp operation")),
        };
        let next = op.apply(&self.msg)?;
        let child = Self::deser(r, next, depth + 1)?;
        self.ops.push((op, child));
        Ok(())
    }

    /// Every attestation in the tree with the message it commits to.
    pub fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut Vec<Claim>) {
        for a in &self.attestations {
            out.push(Claim {
                msg: self.msg.clone(),
                attestation: a.clone(),
            });
        }
        for (_, t) in &self.ops {
            t.collect(out);
        }
    }

    /// Merge another timestamp for the same message (a calendar upgrade).
    pub fn merge(&mut self, other: Timestamp) -> Result<(), Error> {
        if self.msg != other.msg {
            return Err(Error::Malformed(
                "cannot merge timestamps of different messages",
            ));
        }
        for a in other.attestations {
            if !self.attestations.contains(&a) {
                self.attestations.push(a);
            }
        }
        for (op, t) in other.ops {
            match self.ops.iter_mut().find(|(o, _)| *o == op) {
                Some((_, mine)) => mine.merge(t)?,
                None => self.ops.push((op, t)),
            }
        }
        Ok(())
    }

    /// Find the node whose message is `msg` (where a calendar's upgrade
    /// attaches).
    pub fn node_mut(&mut self, msg: &[u8]) -> Option<&mut Timestamp> {
        if self.msg == msg {
            return Some(self);
        }
        self.ops.iter_mut().find_map(|(_, t)| t.node_mut(msg))
    }
}

/// A `.ots` file: a SHA-256 digest and its timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedTimestamp {
    pub digest: [u8; 32],
    pub timestamp: Timestamp,
}

impl DetachedTimestamp {
    pub fn new(digest: [u8; 32]) -> Self {
        DetachedTimestamp {
            digest,
            timestamp: Timestamp::new(digest.to_vec()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        write_varuint(&mut out, MAJOR_VERSION);
        Op::Sha256.serialize(&mut out);
        out.extend_from_slice(&self.digest);
        self.timestamp.serialize(&mut out);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(b);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(Error::Malformed("not an OpenTimestamps proof"));
        }
        if r.varuint()? != MAJOR_VERSION {
            return Err(Error::Malformed("unsupported OpenTimestamps version"));
        }
        if r.byte()? != Op::Sha256.tag() {
            return Err(Error::Malformed(
                "only SHA-256 detached timestamps are supported",
            ));
        }
        let digest: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let timestamp = Timestamp::deserialize(&mut r, digest.to_vec())?;
        if !r.is_empty() {
            return Err(Error::Malformed("trailing bytes after timestamp"));
        }
        Ok(DetachedTimestamp { digest, timestamp })
    }
}

pub struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }

    fn is_empty(&self) -> bool {
        self.b.is_empty()
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() < n {
            return Err(Error::Malformed("truncated timestamp"));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    fn varuint(&mut self) -> Result<u64, Error> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::Malformed("varuint too long"))
    }

    fn varbytes(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let n = self.varuint()? as usize;
        if n > max {
            return Err(Error::Malformed("timestamp field too long"));
        }
        Ok(self.take(n)?.to_vec())
    }
}

fn write_varuint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varuint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// Parse a calendar's response to a digest submission or upgrade request:
/// a bare timestamp starting at `msg`.
pub fn parse_calendar_response(msg: &[u8], body: &[u8]) -> Result<Timestamp, Error> {
    let mut r = Reader::new(body);
    let t = Timestamp::deserialize(&mut r, msg.to_vec())?;
    if !r.is_empty() {
        return Err(Error::Malformed("trailing bytes in calendar response"));
    }
    Ok(t)
}

/// Build the bytes a calendar would return, for tests and mock calendars.
pub fn serialize_timestamp(t: &Timestamp) -> Vec<u8> {
    let mut out = Vec::new();
    t.serialize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A calendar-style path: prepend a nonce, hash, then pending.
    fn pending(msg: &[u8], uri: &str) -> Timestamp {
        let nonce = Op::Prepend(vec![0xaa; 16]);
        let a = nonce.apply(msg).unwrap();
        let b = Op::Sha256.apply(&a).unwrap();
        let mut leaf = Timestamp::new(b.clone());
        leaf.attestations
            .push(Attestation::Pending { uri: uri.into() });
        let mut mid = Timestamp::new(a);
        mid.ops.push((Op::Sha256, leaf));
        let mut root = Timestamp::new(msg.to_vec());
        root.ops.push((nonce, mid));
        root
    }

    #[test]
    fn roundtrip_and_claims() {
        let digest: [u8; 32] = Sha256::digest(b"tree head").into();
        let mut d = DetachedTimestamp::new(digest);
        d.timestamp
            .merge(pending(&digest, "https://a.example"))
            .unwrap();
        d.timestamp
            .merge(pending(&digest, "https://b.example"))
            .unwrap();
        let bytes = d.to_bytes();
        assert!(bytes.starts_with(MAGIC));
        let back = DetachedTimestamp::from_bytes(&bytes).unwrap();
        assert_eq!(back.to_bytes(), bytes);
        let claims = back.timestamp.claims();
        assert_eq!(claims.len(), 2);
        assert!(claims
            .iter()
            .all(|c| matches!(c.attestation, Attestation::Pending { .. })));
    }

    #[test]
    fn upgrade_to_bitcoin() {
        let digest: [u8; 32] = Sha256::digest(b"tree head").into();
        let mut d = DetachedTimestamp::new(digest);
        d.timestamp
            .merge(pending(&digest, "https://a.example"))
            .unwrap();
        let commitment = d.timestamp.claims()[0].msg.clone();

        // The calendar later answers with a path from the commitment to a
        // block Merkle root.
        let sibling = vec![0x11; 32];
        let step = Op::Append(sibling);
        let m1 = step.apply(&commitment).unwrap();
        let m2 = Op::Sha256.apply(&m1).unwrap();
        let root = Op::Sha256.apply(&m2).unwrap();
        let mut top = Timestamp::new(root.clone());
        top.attestations
            .push(Attestation::Bitcoin { height: 358_391 });
        let mut t2 = Timestamp::new(m2);
        t2.ops.push((Op::Sha256, top));
        let mut t1 = Timestamp::new(m1);
        t1.ops.push((Op::Sha256, t2));
        let mut upgrade = Timestamp::new(commitment.clone());
        upgrade.ops.push((step, t1));

        let resp = serialize_timestamp(&upgrade);
        let parsed = parse_calendar_response(&commitment, &resp).unwrap();
        d.timestamp
            .node_mut(&commitment)
            .unwrap()
            .merge(parsed)
            .unwrap();

        let back = DetachedTimestamp::from_bytes(&d.to_bytes()).unwrap();
        let btc: Vec<_> = back
            .timestamp
            .claims()
            .into_iter()
            .filter(|c| matches!(c.attestation, Attestation::Bitcoin { .. }))
            .collect();
        assert_eq!(btc.len(), 1);
        assert_eq!(btc[0].msg, root);
        let shown = btc[0].bitcoin_merkle_root_hex().unwrap();
        assert_eq!(
            hex::decode(shown)
                .unwrap()
                .into_iter()
                .rev()
                .collect::<Vec<_>>(),
            root
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(DetachedTimestamp::from_bytes(b"nope").is_err());
        let digest = [7u8; 32];
        let mut d = DetachedTimestamp::new(digest);
        d.timestamp
            .attestations
            .push(Attestation::Pending { uri: "x".into() });
        let mut b = d.to_bytes();
        b.push(0);
        assert!(DetachedTimestamp::from_bytes(&b).is_err());
        b.truncate(b.len() - 3);
        assert!(DetachedTimestamp::from_bytes(&b).is_err());
    }
}
