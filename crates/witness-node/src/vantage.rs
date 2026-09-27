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
    pub observers: usize,
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.observers {
            0 => write!(f, "AS{} {} (self-reported)", self.asn, self.country),
            n => write!(f, "AS{} {} ({n} observers)", self.asn, self.country),
        }
    }
}

/// The ASN most independent observers saw `subject` connect from, if at
/// least `min_observers` agree. Self-observations don't count.
pub fn corroborate(
    subject: &WitnessKey,
    observations: &[Signed<Observation>],
    db: &AsnDb,
    min_observers: usize,
) -> Option<Location> {
    let mut by_asn: BTreeMap<(u32, String), BTreeSet<WitnessKey>> = BTreeMap::new();
    for o in observations {
        let b = &o.body;
        if b.subject != *subject || b.observer == *subject || o.verify().is_err() {
            continue;
        }
        if let Some(loc) = db.lookup(b.ip) {
            by_asn.entry(loc).or_default().insert(b.observer);
        }
    }
    let ((asn, country), obs) = by_asn.into_iter().max_by_key(|(_, o)| o.len())?;
    (obs.len() >= min_observers).then_some(Location {
        asn,
        country,
        observers: obs.len(),
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
        let s = Keypair::generate().unwrap();
        let (o1, o2, o3) = (
            Keypair::generate().unwrap(),
            Keypair::generate().unwrap(),
            Keypair::generate().unwrap(),
        );
        // Self-observation and a single observer are not enough.
        let v = vec![obs(&s, &s, "80.130.1.2"), obs(&s, &o1, "80.130.1.2")];
        assert_eq!(corroborate(&s.public(), &v, &db, 2), None);
        // Two observers agree; a third saw it elsewhere.
        let v = vec![
            obs(&s, &o1, "80.130.1.2"),
            obs(&s, &o2, "80.140.9.9"),
            obs(&s, &o3, "1.0.0.1"),
        ];
        let loc = corroborate(&s.public(), &v, &db, 2).unwrap();
        assert_eq!(
            (loc.asn, loc.country.as_str(), loc.observers),
            (3320, "DE", 2)
        );
        // Forged receipts are ignored.
        let mut forged = obs(&s, &o3, "80.130.1.2");
        forged.body.ip = "1.0.0.9".parse().unwrap();
        let v = vec![obs(&s, &o1, "1.0.0.1"), forged];
        assert_eq!(corroborate(&s.public(), &v, &db, 2), None);
    }
}
