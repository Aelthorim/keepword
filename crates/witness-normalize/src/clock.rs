//! Masking "live clocks": absolute timestamps that equal the capture time.
//!
//! Pages print the current time ("Stand: 27.09.2026 10:15:32", a JS clock,
//! "generated at 2026-09-27T08:53:25Z"). Those change on every request
//! without the content changing. A timestamp within a small window of the
//! signed `fetched_at` is replaced by `<now>`. Because `fetched_at` is part of
//! the attestation, a verifier re-running normalization gets the same result.
//!
//! Timestamps without a zone are only masked when they carry seconds, and
//! may be off from UTC by whole hours (the page's local time). Minute
//! precision without a zone would mask genuine publication times too often.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};

/// Zoned timestamps this close to the capture time are "now".
const ZONED_WINDOW_S: i64 = 120;
/// Zone-less timestamps (with seconds) this close, modulo whole hours.
const NAIVE_WINDOW_S: i64 = 90;

static ISO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,]\d+)?)?(\s?(?:Z|UTC|[+-]\d{2}:?\d{2}))?",
    )
    .expect("valid regex")
});

static EU: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,2})\.(\d{1,2})\.(\d{4}),?\s+(\d{1,2}):(\d{2}):(\d{2})(\s*Uhr)?")
        .expect("valid regex")
});

fn num(c: &Captures<'_>, i: usize) -> Option<i64> {
    c.get(i)?.as_str().parse().ok()
}

fn to_unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let date = Date::from_calendar_date(y as i32, Month::try_from(mo as u8).ok()?, d as u8).ok()?;
    let time = Time::from_hms(h as u8, mi as u8, s as u8).ok()?;
    Some(
        PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp(),
    )
}

fn parse_offset(z: &str) -> Option<i64> {
    let z = z.trim();
    if z == "Z" || z == "UTC" {
        return Some(0);
    }
    let sign = if z.starts_with('-') { -1 } else { 1 };
    let digits: String = z.chars().filter(char::is_ascii_digit).collect();
    let h: i64 = digits.get(..2)?.parse().ok()?;
    let m: i64 = digits.get(2..4)?.parse().ok()?;
    UtcOffset::from_hms((sign * h) as i8, (sign * m) as i8, 0).ok()?;
    Some(sign * (h * 3600 + m * 60))
}

fn naive_is_now(t: i64, now: i64) -> bool {
    (-14..=14).any(|k| (t - k * 3600 - now).abs() <= NAIVE_WINDOW_S)
}

/// Replace timestamps equal to the capture time with `<now>`.
pub fn mask_now(s: &str, fetched_at_ms: i64) -> Cow<'_, str> {
    if !s.bytes().any(|b| b == b':') {
        return Cow::Borrowed(s);
    }
    let now = fetched_at_ms.div_euclid(1000);
    let s = ISO.replace_all(s, |c: &Captures<'_>| {
        let whole = c[0].to_string();
        let (Some(y), Some(mo), Some(d), Some(h), Some(mi)) =
            (num(c, 1), num(c, 2), num(c, 3), num(c, 4), num(c, 5))
        else {
            return whole;
        };
        let sec = num(c, 6);
        let Some(t) = to_unix(y, mo, d, h, mi, sec.unwrap_or(0)) else {
            return whole;
        };
        let hit = match c.get(7).and_then(|z| parse_offset(z.as_str())) {
            Some(off) => (t - off - now).abs() <= ZONED_WINDOW_S,
            None => sec.is_some() && naive_is_now(t, now),
        };
        if hit {
            "<now>".to_string()
        } else {
            whole
        }
    });
    let s = match s {
        Cow::Borrowed(b) => EU.replace_all(b, |c: &Captures<'_>| eu(c, now)),
        Cow::Owned(o) => Cow::Owned(
            EU.replace_all(&o, |c: &Captures<'_>| eu(c, now))
                .into_owned(),
        ),
    };
    s
}

fn eu(c: &Captures<'_>, now: i64) -> String {
    let t = (|| {
        to_unix(
            num(c, 3)?,
            num(c, 2)?,
            num(c, 1)?,
            num(c, 4)?,
            num(c, 5)?,
            num(c, 6)?,
        )
    })();
    match t {
        Some(t) if naive_is_now(t, now) => "<now>".into(),
        _ => c[0].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-09-27T08:53:25Z
    const NOW: i64 = 1_790_499_205_000;

    #[test]
    fn masks_clocks() {
        assert_eq!(
            mask_now("as of 2026-09-27T08:53:25.200Z", NOW),
            "as of <now>"
        );
        assert_eq!(
            mask_now("as of 2026-09-27T10:54:10+02:00", NOW),
            "as of <now>"
        );
        // Local time without zone, with seconds, two hours ahead of UTC.
        assert_eq!(
            mask_now("Stand: 27.09.2026 10:53:40 Uhr", NOW),
            "Stand: <now>"
        );
        assert_eq!(mask_now("2026-09-27 10:52:59", NOW), "<now>");
    }

    #[test]
    fn keeps_real_dates() {
        for s in [
            "published 2026-09-27T07:00:00Z", // an hour before
            "2026-09-26T08:53:25Z",           // a day before
            "27.09.2026 10:53 Uhr",           // no seconds, no zone
            "2026-09-27T10:53:25+05:00",      // zoned, five hours off
            "Marathon in 2:03:45",            // not a date
            "Updated 2024-05-01",             // date only
        ] {
            assert_eq!(mask_now(s, NOW), s, "{s}");
        }
    }
}
