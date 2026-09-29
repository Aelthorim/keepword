//! Where a request came from, behind reverse proxies and CDNs.
//!
//! Each proxy appends the address it got the request from to
//! X-Forwarded-For, so an entry is only as good as the proxy that wrote it.
//! Walking back from the connection, entries can be believed as long as
//! they were written by this node's own proxies; the first address that
//! isn't one of those is the client. Where a peer connects from places it
//! in a network, so this must not be forgeable, and a CDN's address must
//! never pass for a peer's.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::LazyLock;

use anyhow::{Result, anyhow};
use axum::http::HeaderMap;
use witness_capture::netpolicy::is_public;

/// Cloudflare's addresses, from <https://www.cloudflare.com/ips/>.
const CLOUDFLARE: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

static CLOUDFLARE_RANGES: LazyLock<Vec<Cidr>> =
    LazyLock::new(|| CLOUDFLARE.iter().map(|c| c.parse().unwrap()).collect());

/// Whether `ip` is one of Cloudflare's.
pub fn is_cloudflare(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    CLOUDFLARE_RANGES.iter().any(|r| r.contains(ip))
}

/// An address range such as `203.0.113.0/24`; a bare address is a range
/// of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    bits: u8,
}

impl FromStr for Cidr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let err = || anyhow!("{s:?} is not an address range like 203.0.113.0/24");
        let (addr, bits) = match s.trim().split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s.trim(), None),
        };
        let base: IpAddr = addr.parse().map_err(|_| err())?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => max,
            Some(b) => b.parse().ok().filter(|b| *b <= max).ok_or_else(err)?,
        };
        Ok(Cidr {
            base: base.to_canonical(),
            bits,
        })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        // The top `bits` bits of a `width`-bit address.
        let prefix = |x: u128, width: u8| {
            if self.bits == 0 {
                0
            } else {
                x >> (width - self.bits)
            }
        };
        match (self.base, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                prefix(u32::from(n).into(), 32) == prefix(u32::from(a).into(), 32)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix(n.into(), 128) == prefix(a.into(), 128),
            _ => false,
        }
    }
}

/// The proxies in front of this node: `network.trust_forwarded_for` and
/// `network.trusted_proxies`.
#[derive(Clone, Debug, Default)]
pub struct Proxies {
    /// Believe X-Forwarded-For at all.
    forwarded: bool,
    /// Proxies on public addresses, besides the ones on private networks.
    ranges: Vec<Cidr>,
    cloudflare: bool,
}

impl Proxies {
    /// `trusted` is `network.trusted_proxies`: `"cloudflare"`, or address
    /// ranges.
    pub fn new(trust_forwarded_for: bool, trusted: &[String]) -> Result<Self> {
        let mut p = Proxies {
            forwarded: trust_forwarded_for,
            ..Default::default()
        };
        for t in trusted {
            if t.trim().eq_ignore_ascii_case("cloudflare") {
                p.cloudflare = true;
            } else {
                p.ranges.push(
                    t.parse()
                        .map_err(|e| anyhow!("network.trusted_proxies: {e}, or \"cloudflare\""))?,
                );
            }
        }
        Ok(p)
    }

    /// Whether Cloudflare is in front.
    pub fn cloudflare(&self) -> bool {
        self.cloudflare
    }

    /// The address of the client behind a connection from `peer`, or
    /// `None` when the proxies in between didn't say.
    pub fn client(&self, peer: IpAddr, headers: &HeaderMap) -> Option<IpAddr> {
        let mut hop = peer.to_canonical();
        if !self.forwarded {
            return Some(hop);
        }
        // Newest first: the address the proxy nearest this node saw.
        let mut forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .rev()
            // An entry that can't be read stops the walk there.
            .flat_map(|v| v.to_str().unwrap_or("?").rsplit(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_hop);
        loop {
            if self.cloudflare && is_cloudflare(hop) {
                // Cloudflare sets this header itself, whereas the
                // X-Forwarded-For it passes on starts with whatever the
                // client sent.
                return cloudflare_client(headers);
            }
            if is_public(hop) && !self.ranges.iter().any(|r| r.contains(hop)) {
                return Some(hop);
            }
            match forwarded.next() {
                Some(Some(before)) => hop = before,
                // Garbage where one of our proxies should have written an
                // address.
                Some(None) => return None,
                // Nothing further back: a client on a private network, or
                // a public proxy that didn't say.
                None => return (!is_public(hop)).then_some(hop),
            }
        }
    }
}

/// An address as a proxy wrote it, sometimes with a port.
fn parse_hop(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .or_else(|_| s.parse::<SocketAddr>().map(|a| a.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

fn cloudflare_client(headers: &HeaderMap) -> Option<IpAddr> {
    // Cloudflare sends each once; a second one came from someone else.
    let header = |name: &str| match headers.get_all(name).iter().collect::<Vec<_>>()[..] {
        [v] => v
            .to_str()
            .ok()
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical()),
        _ => None,
    };
    let ip = header("cf-connecting-ip")?;
    // With "Pseudo IPv4" set to overwrite headers, IPv6 clients show up
    // with an address from 240.0.0.0/4 and their own is in this one.
    let pseudo = matches!(ip, IpAddr::V4(v4) if v4.octets()[0] >= 240);
    if pseudo {
        header("cf-connecting-ipv6")
    } else {
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, v.parse().unwrap());
        }
        h
    }

    fn proxies(trusted: &[&str]) -> Proxies {
        let t: Vec<String> = trusted.iter().map(|s| s.to_string()).collect();
        Proxies::new(true, &t).unwrap()
    }

    const CLIENT: &str = "81.2.69.160";
    const OTHER: &str = "9.9.9.9";
    const CF_EDGE: &str = "172.70.4.1";
    const CADDY: &str = "10.10.20.10";

    #[test]
    fn ranges() {
        let r: Cidr = "172.64.0.0/13".parse().unwrap();
        assert!(r.contains(ip("172.71.255.255")));
        assert!(!r.contains(ip("172.72.0.0")));
        assert!(r.contains(ip("::ffff:172.64.0.1")), "IPv4-mapped");
        assert!(!r.contains(ip("2606:4700::1")));
        let r: Cidr = "2a06:98c0::/29".parse().unwrap();
        assert!(r.contains(ip("2a06:98c0:3600::103")));
        assert!(!r.contains(ip("2a06:98c8::1")));
        let one: Cidr = "203.0.113.9".parse().unwrap();
        assert!(one.contains(ip("203.0.113.9")) && !one.contains(ip("203.0.113.8")));
        let all: Cidr = "::/0".parse().unwrap();
        assert!(all.contains(ip("2001:db8::1")) && !all.contains(ip("1.2.3.4")));
        for bad in [
            "10.0.0.0/33",
            "fe80::/129",
            "cloudflare.com",
            "10.0.0.0/x",
            "10.0.0.0/",
            "",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
        assert!(is_cloudflare(ip(CF_EDGE)) && is_cloudflare(ip("2400:cb00::1")));
        assert!(
            !is_cloudflare(ip("1.1.1.1")),
            "Cloudflare's resolver isn't a proxy"
        );
        assert!(Proxies::new(true, &["cloudfare".into()]).is_err());
    }

    #[test]
    fn without_trust_the_connection_is_the_client() {
        let p = Proxies::new(false, &["cloudflare".into()]).unwrap();
        let h = headers(&[("x-forwarded-for", OTHER), ("cf-connecting-ip", OTHER)]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CADDY)));
        assert_eq!(p.client(ip(CF_EDGE), &h), Some(ip(CF_EDGE)));
    }

    #[test]
    fn behind_a_proxy_of_ours() {
        let p = proxies(&[]);
        // The proxy appends the address it saw; the rest is the client's.
        let h = headers(&[("x-forwarded-for", &format!("{OTHER}, {CLIENT}"))]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
        assert_eq!(p.client(ip("127.0.0.1"), &h), Some(ip(CLIENT)));
        // Two proxies of ours: a load balancer and Caddy.
        let h = headers(&[("x-forwarded-for", &format!("{OTHER}, {CLIENT}, 10.0.0.5"))]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
        // Header lines are one list, in order.
        let h = headers(&[("x-forwarded-for", OTHER), ("x-forwarded-for", CLIENT)]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
        // Ports, IPv4-mapped connections.
        let h = headers(&[("x-forwarded-for", &format!("{CLIENT}:4711"))]);
        assert_eq!(p.client(ip("::ffff:10.10.20.10"), &h), Some(ip(CLIENT)));
        let h = headers(&[("x-forwarded-for", "[2001:4860::8888]:443")]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip("2001:4860::8888")));
        // A client on the LAN, or a proxy that sent no header.
        let h = headers(&[("x-forwarded-for", "192.168.1.5")]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip("192.168.1.5")));
        assert_eq!(p.client(ip(CADDY), &HeaderMap::new()), Some(ip(CADDY)));
        // Garbage where our proxy's entry should be.
        let h = headers(&[("x-forwarded-for", "unknown")]);
        assert_eq!(p.client(ip(CADDY), &h), None);
    }

    #[test]
    fn connections_from_elsewhere_cannot_claim_an_address() {
        let p = proxies(&["cloudflare"]);
        let h = headers(&[
            ("x-forwarded-for", &format!("{OTHER}, {CF_EDGE}")),
            ("cf-connecting-ip", OTHER),
        ]);
        assert_eq!(p.client(ip(CLIENT), &h), Some(ip(CLIENT)));
        // Straight to Caddy, around Cloudflare: Caddy writes the address
        // it saw, and passes the made-up CF-Connecting-IP on.
        let h = headers(&[("x-forwarded-for", CLIENT), ("cf-connecting-ip", OTHER)]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
    }

    #[test]
    fn behind_cloudflare() {
        let p = proxies(&["cloudflare"]);
        // Caddy not trusting Cloudflare: it writes only the edge's address.
        let h = headers(&[("x-forwarded-for", CF_EDGE), ("cf-connecting-ip", CLIENT)]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
        // Caddy trusting Cloudflare keeps what came before, including
        // what the client made up; Cloudflare's header is what counts.
        let h = headers(&[
            ("x-forwarded-for", &format!("{OTHER}, {CLIENT}, {CF_EDGE}")),
            ("cf-connecting-ip", CLIENT),
        ]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
        // Cloudflare straight in front of the node.
        let h = headers(&[("cf-connecting-ip", "2a01:4f8::1")]);
        assert_eq!(
            p.client(ip("2606:4700::6810:1"), &h),
            Some(ip("2a01:4f8::1"))
        );
        // Pseudo IPv4.
        let h = headers(&[
            ("cf-connecting-ip", "240.16.0.1"),
            ("cf-connecting-ipv6", "2a01:4f8::1"),
        ]);
        assert_eq!(p.client(ip(CF_EDGE), &h), Some(ip("2a01:4f8::1")));
        // Cloudflare without its header: nobody knows, and the edge's
        // address must not stand in for the client's.
        let h = headers(&[("x-forwarded-for", CF_EDGE)]);
        assert_eq!(p.client(ip(CADDY), &h), None);
        // Nor with two, one of them not Cloudflare's.
        let h = headers(&[
            ("x-forwarded-for", CF_EDGE),
            ("cf-connecting-ip", OTHER),
            ("cf-connecting-ip", CLIENT),
        ]);
        assert_eq!(p.client(ip(CADDY), &h), None);
        // Without "cloudflare", the edge is taken for the client: what
        // `witness net status` warns about.
        let h = headers(&[("x-forwarded-for", CF_EDGE), ("cf-connecting-ip", CLIENT)]);
        assert_eq!(proxies(&[]).client(ip(CADDY), &h), Some(ip(CF_EDGE)));
    }

    #[test]
    fn behind_another_cdn() {
        let p = proxies(&["151.101.0.0/16", "2a04:4e40::/32"]);
        let h = headers(&[(
            "x-forwarded-for",
            &format!("{OTHER}, {CLIENT}, 151.101.9.9"),
        )]);
        assert_eq!(p.client(ip(CADDY), &h), Some(ip(CLIENT)));
        assert_eq!(p.client(ip("151.101.9.9"), &h), Some(ip(CLIENT)));
        // Its address never stands in for the client's.
        let h = headers(&[("x-forwarded-for", "151.101.9.9")]);
        assert_eq!(p.client(ip(CADDY), &h), None);
    }
}
