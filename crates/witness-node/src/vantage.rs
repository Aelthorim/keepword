//! Where a witness really is: IP → ASN lookup and corroboration from
//! observation receipts (docs/DESIGN.md §6.3).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use witness_core::WitnessKey;
use witness_core::net::Observation;
use witness_core::statement::Signed;

/// IP-range → (ASN, country) table in the iptoasn.com TSV format:
/// `range_start  range_end  AS_number  country_code  AS_description`.
#[derive(Clone, Debug, Default)]
pub struct AsnDb {
    ranges: Vec<(u128, u128, u32, String)>,
}

fn ip_key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => u128::from(v4.to_ipv6_mapped()),
            None => u128::from(v6),
        },
    }
}

impl AsnDb {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut ranges = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            let parse = || -> Option<(u128, u128, u32, String)> {
                let a: IpAddr = f.first()?.trim().parse().ok()?;
                let b: IpAddr = f.get(1)?.trim().parse().ok()?;
                let asn: u32 = f.get(2)?.trim().parse().ok()?;
                Some((
                    ip_key(a),
                    ip_key(b),
                    asn,
                    f.get(3).unwrap_or(&"").trim().to_string(),
                ))
            };
            let r = parse().with_context(|| format!("bad ASN table line {}", n + 1))?;
            // ASN 0 marks unrouted space.
            if r.2 != 0 {
                ranges.push(r);
            }
        }
        ranges.sort_by_key(|r| r.0);
        Ok(AsnDb { ranges })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<(u32, String)> {
        let k = ip_key(ip);
        let i = self.ranges.partition_point(|r| r.0 <= k);
        let r = self.ranges.get(i.checked_sub(1)?)?;
        (k <= r.1).then(|| (r.2, r.3.clone()))
    }
}

/// A corroborated location.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Location {
    pub asn: u32,
    pub country: String,
    /// Independent networks whose observers agree on it; 0 when
    /// self-reported.
    pub observers: usize,
    /// This node saw the witness connect from there itself.
    #[serde(default)]
    pub direct: bool,
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.direct, self.observers) {
            (true, _) => write!(f, "AS{} {} (seen directly)", self.asn, self.country),
            (false, 0) => write!(f, "AS{} {} (self-reported)", self.asn, self.country),
            (false, n) => write!(f, "AS{} {} ({n} observer networks)", self.asn, self.country),
        }
    }
}

/// Where `subject` connects from, as far as `me` can tell.
///
/// Keys are free, so observers are never counted as such. Instead:
///
/// 1. If `me` has seen `subject` connect itself, that settles it: no
///    number of other keys can outvote what this node saw.
/// 2. Otherwise, observations count only from observers this node has
///    seen connect itself, and once per network those observers are in
///    (`observer_asn`). Twenty keys on one server are one observer, so
///    they can't vouch each other into twenty networks.
pub fn corroborate(
    subject: &WitnessKey,
    me: &WitnessKey,
    observations: &[Signed<Observation>],
    db: &AsnDb,
    min_observers: usize,
    observer_asn: impl Fn(&WitnessKey) -> Option<u32>,
) -> Option<Location> {
    let valid = observations
        .iter()
        .filter(|o| o.body.subject == *subject && o.body.observer != *subject)
        .filter(|o| o.verify().is_ok());
    let mut by_asn: BTreeMap<(u32, String), BTreeSet<u32>> = BTreeMap::new();
    for o in valid {
        let Some(loc) = db.lookup(o.body.ip) else {
            continue;
        };
        if o.body.observer == *me && subject != me {
            return Some(Location {
                asn: loc.0,
                country: loc.1,
                observers: 1,
                direct: true,
            });
        }
        if let Some(net) = observer_asn(&o.body.observer) {
            by_asn.entry(loc).or_default().insert(net);
        }
    }
    let ((asn, country), nets) = by_asn.into_iter().max_by_key(|(_, n)| n.len())?;
    (nets.len() >= min_observers).then_some(Location {
        asn,
        country,
        observers: nets.len(),
        direct: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_core::Keypair;

    const DB: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
                      10.0.0.0\t10.255.255.255\t0\tNone\tNot routed\n\
                      80.128.0.0\t80.146.191.255\t3320\tDE\tDTAG\n\
                      2001:db8::\t2001:db8::ffff\t64500\tZZ\tTEST\n";

    #[test]
    fn lookups() {
        let db = AsnDb::parse(DB).unwrap();
        assert_eq!(
            db.lookup("80.130.1.2".parse().unwrap()),
            Some((3320, "DE".into()))
        );
        assert_eq!(
            db.lookup("::ffff:80.130.1.2".parse().unwrap()),
            Some((3320, "DE".into()))
        );
        assert_eq!(db.lookup("1.0.0.7".parse().unwrap()).unwrap().0, 13335);
        assert_eq!(db.lookup("10.1.1.1".parse().unwrap()), None);
        assert_eq!(db.lookup("9.9.9.9".parse().unwrap()), None);
        assert_eq!(db.lookup("2001:db8::10".parse().unwrap()).unwrap().0, 64500);
    }

    fn obs(subject: &Keypair, observer: &Keypair, ip: &str) -> Signed<Observation> {
        Signed::sign(
            Observation {
                subject: subject.public(),
                ip: ip.parse().unwrap(),
                observed_at_ms: 1,
                observer: observer.public(),
            },
            observer,
        )
        .unwrap()
    }

    #[test]
    fn needs_independent_observers() {
        let db = AsnDb::parse(DB).unwrap();
        let new_key = || Keypair::generate().unwrap();
        let (me, s, o1, o2, o3) = (new_key(), new_key(), new_key(), new_key(), new_key());
        // I saw o1 on Cloudflare's network, o2 and o3 on Deutsche Telekom's.
        let net = |k: &WitnessKey| match k {
            k if *k == o1.public() => Some(13335),
            k if *k == o2.public() || *k == o3.public() => Some(3320),
            _ => None,
        };
        let loc =
            |v: &[Signed<Observation>]| corroborate(&s.public(), &me.public(), v, &db, 2, net);

        // Self-observation and a single observer are not enough.
        assert_eq!(
            loc(&[obs(&s, &s, "80.130.1.2"), obs(&s, &o1, "80.130.1.2")]),
            None
        );
        // Two observers, but both on one network: that's one observer.
        assert_eq!(
            loc(&[obs(&s, &o2, "80.130.1.2"), obs(&s, &o3, "80.130.1.2")]),
            None
        );
        // Observers on two networks agree.
        let l = loc(&[obs(&s, &o1, "80.130.1.2"), obs(&s, &o2, "80.140.9.9")]).unwrap();
        assert_eq!(
            (l.asn, l.country.as_str(), l.observers, l.direct),
            (3320, "DE", 2, false)
        );
        // Observers this node never saw don't count at all.
        let (x, y) = (new_key(), new_key());
        assert_eq!(loc(&[obs(&s, &x, "1.0.0.1"), obs(&s, &y, "1.0.0.1")]), None);
        // Forged receipts are ignored.
        let mut forged = obs(&s, &o2, "80.130.1.2");
        forged.body.ip = "1.0.0.9".parse().unwrap();
        assert_eq!(loc(&[obs(&s, &o1, "1.0.0.1"), forged]), None);
    }

    /// One server, twenty keys, each vouching that the others are on
    /// twenty different networks.
    #[test]
    fn sybil_observers_cannot_invent_networks() {
        let db = AsnDb::parse(DB).unwrap();
        let me = Keypair::generate().unwrap();
        let sybils: Vec<Keypair> = (0..20).map(|_| Keypair::generate().unwrap()).collect();
        let fake_ips = ["1.0.0.1", "80.130.1.2", "2001:db8::10"];
        let mut v = Vec::new();
        for (i, s) in sybils.iter().enumerate() {
            for o in sybils.iter().filter(|o| o.public() != s.public()) {
                v.push(obs(s, o, fake_ips[i % fake_ips.len()]));
            }
        }
        // This node saw every one of them connect from the same server.
        let real = |_: &WitnessKey| Some(13335);
        for s in &sybils {
            let l = corroborate(&s.public(), &me.public(), &v, &db, 2, real);
            assert_eq!(l, None, "sybils vouched each other into a network");
        }
        // And once they push to this node directly, it sees where they are.
        let mut mine = v.clone();
        mine.push(obs(&sybils[0], &me, "1.0.0.9"));
        let l = corroborate(&sybils[0].public(), &me.public(), &mine, &db, 2, real).unwrap();
        assert_eq!((l.asn, l.direct), (13335, true));
    }
}
