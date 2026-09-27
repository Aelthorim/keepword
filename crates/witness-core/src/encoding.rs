//! Canonical binary encoding for signed statements.
//!
//! JSON is used for transport, but signatures are always computed over this
//! encoding, so two implementations agree on the signed bytes regardless of
//! key order, whitespace or number formatting. The rules are deliberately
//! tiny: big-endian fixed-width integers, `u32` length prefixes for variable
//! data, a one-byte presence tag for optional fields.

use std::net::IpAddr;

#[derive(Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Start an encoding with a domain-separation header.
    pub fn new(domain: &str) -> Self {
        let mut e = Encoder {
            buf: Vec::with_capacity(256),
        };
        e.str(domain);
        e
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn fixed(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        let len = u32::try_from(v.len()).expect("field longer than 4 GiB");
        self.u32(len);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    pub fn opt<T>(&mut self, v: Option<T>, f: impl FnOnce(&mut Self, T)) -> &mut Self {
        match v {
            None => {
                self.u8(0);
            }
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
        }
        self
    }

    pub fn list<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        let len = u32::try_from(items.len()).expect("list too long");
        self.u32(len);
        for it in items {
            f(self, it);
        }
        self
    }

    pub fn ip(&mut self, ip: &IpAddr) -> &mut Self {
        match ip {
            IpAddr::V4(v4) => self.u8(4).fixed(&v4.octets()),
            IpAddr::V6(v6) => self.u8(6).fixed(&v6.octets()),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_stable() {
        let mut e = Encoder::new("D");
        e.u8(1).u16(2).str("ab").opt(None::<u8>, |e, v| {
            e.u8(v);
        });
        e.opt(Some(7u8), |e, v| {
            e.u8(v);
        });
        assert_eq!(
            e.finish(),
            vec![0, 0, 0, 1, b'D', 1, 0, 2, 0, 0, 0, 2, b'a', b'b', 0, 1, 7]
        );
    }
}
