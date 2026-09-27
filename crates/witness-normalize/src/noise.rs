//! Text-level noise: relative timestamps, live counters, invisible
//! characters, tracking parameters.

use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;
use url::Url;

static RELTIME: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // English: "5 minutes ago", "an hour ago", "3h ago"
        r"(?i)\b(\d+|an?|one)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|wks?|w|months?|mos?|years?|yrs?|y)\s+ago\b",
        r"(?i)\bjust now\b",
        // German: "vor 5 Minuten", "vor einer Stunde"
        r"(?i)\bvor\s+(\d+|einer?|einem)\s+(Sekunden?|Sek\.?|Minuten?|Min\.?|Stunden?|Std\.?|Tagen?|Tag|Wochen?|Monaten?|Monat|Jahren?|Jahr)\b",
        r"(?i)\bgerade eben\b",
        // French: "il y a 5 minutes"
        r"(?i)\bil y a\s+(\d+|une?)\s+(secondes?|minutes?|heures?|jours?|semaines?|mois|ans?)\b",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("valid regex"))
    .collect()
});

static COUNTERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b\d[\d.,]*\s*[kKmM]?\s+(views?|comments?|likes?|shares?|reads?|readers?|followers?|Kommentare?|Aufrufe|Leser|Views)\b",
    )
    .expect("valid regex")
});

/// Unicode NFC, invisible characters removed, whitespace collapsed, and
/// time-relative or ever-changing phrases replaced by placeholders.
pub fn clean_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for c in s.nfc() {
        match c {
            '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}' => {}
            c if c.is_whitespace() => space = true,
            c => {
                if space && !out.is_empty() {
                    out.push(' ');
                }
                space = false;
                out.push(c);
            }
        }
    }
    let mut s = out;
    for re in RELTIME.iter() {
        if re.is_match(&s) {
            s = re.replace_all(&s, "<reltime>").into_owned();
        }
    }
    if COUNTERS.is_match(&s) {
        s = COUNTERS.replace_all(&s, "<n> $1").into_owned();
    }
    s
}

const TRACKING_PARAMS: &[&str] = &[
    "fbclid",
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "yclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "_ga",
    "_gl",
    "_hsenc",
    "_hsmi",
    "mkt_tok",
    "oly_anon_id",
    "oly_enc_id",
    "rb_clickid",
    "s_cid",
    "vero_id",
    "wickedid",
    "ref_src",
    "ref_url",
    "cmpid",
    "wt_mc",
    "wt_zmc",
    "at_medium",
    "at_campaign",
    // Cache busters.
    "_",
    "cb",
    "cachebust",
    "cachebuster",
    "nocache",
];

fn is_tracking(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.starts_with("utm_") || k.starts_with("pk_") || TRACKING_PARAMS.contains(&k.as_str())
}

/// Resolve a link against the page URL, drop the fragment and tracking
/// parameters. Returns `None` for non-web links (javascript:, mailto:, ...).
pub fn clean_link(base: &Url, href: &str) -> Option<String> {
    let mut u = base.join(href.trim()).ok()?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return None;
    }
    u.set_fragment(None);
    if u.query().is_some() {
        let kept: Vec<(String, String)> = u
            .query_pairs()
            .filter(|(k, _)| !is_tracking(k))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if kept.is_empty() {
            u.set_query(None);
        } else {
            u.query_pairs_mut().clear().extend_pairs(kept);
        }
    }
    Some(u.into())
}

/// Image sources are compared without their query string: CDNs put resize
/// parameters, signatures and cache busters there. `data:` URIs are replaced
/// by their hash.
pub fn clean_image(base: &Url, src: &str) -> Option<String> {
    let src = src.trim();
    if src.starts_with("data:") {
        return Some(format!(
            "data:{}",
            witness_core::Digest::of(src.as_bytes()).short()
        ));
    }
    let mut u = base.join(src).ok()?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return None;
    }
    u.set_fragment(None);
    u.set_query(None);
    Some(u.into())
}

const NOISE_TOKENS: &[&str] = &[
    "ad",
    "ads",
    "adslot",
    "adunit",
    "advert",
    "adverts",
    "advertisement",
    "advertising",
    "anzeige",
    "sponsor",
    "sponsored",
    "promo",
    "promoted",
    "cookie",
    "cookies",
    "consent",
    "cmp",
    "gdpr",
    "newsletter",
    "paywall",
    "outbrain",
    "taboola",
    "share",
    "sharing",
    "social",
    "related",
    "relatedposts",
    "recommended",
    "recommendations",
    "trending",
    "popular",
    "most-read",
    // User comments are not the publisher's content.
    "comment",
    "comments",
    "kommentare",
];

/// Consent-management platforms and ad networks whose ids and classes are
/// recognisable by prefix (`onetrust-banner-sdk`, `sp_message_container_123`).
const NOISE_PREFIXES: &[&str] = &[
    "onetrust",
    "ot-sdk",
    "usercentrics",
    "uc-banner",
    "cybotcookiebot",
    "cookiebot",
    "didomi",
    "sp_message",
    "sp_veil",
    "qc-cmp",
    "truste",
    "cmpbox",
    "cmpwrapper",
    "borlabs-cookie",
    "cmplz",
    "gdpr",
    "taboola",
    "outbrain",
    "google_ads",
    "disqus",
    "jp-relatedposts",
    "div-gpt-ad",
    "adsbygoogle",
];

/// Whether a class or id marks advertising, consent banners, share widgets
/// and similar per-visit noise. Matching is by whole token (so `header`
/// doesn't match `ad`), or by known vendor prefix.
pub fn is_noise_token_list(value: &str) -> bool {
    value.split_whitespace().any(|word| {
        let w = word.to_ascii_lowercase();
        NOISE_TOKENS.contains(&w.as_str())
            || NOISE_PREFIXES.iter().any(|p| w.starts_with(p))
            || w.split(['-', '_']).any(|t| NOISE_TOKENS.contains(&t))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times() {
        assert_eq!(
            clean_text("Posted 5 minutes ago by X"),
            "Posted <reltime> by X"
        );
        assert_eq!(
            clean_text("vor 3 Stunden aktualisiert"),
            "<reltime> aktualisiert"
        );
        assert_eq!(clean_text("an hour ago"), "<reltime>");
        assert_eq!(clean_text("1,234 views"), "<n> views");
        assert_eq!(clean_text("I went 5 miles ago"), "I went 5 miles ago");
    }

    #[test]
    fn whitespace_and_invisibles() {
        assert_eq!(clean_text("  a\u{200B}b \n\t c\u{00A0}d "), "ab c d");
        // NFC: decomposed é equals composed é.
        assert_eq!(clean_text("e\u{0301}"), clean_text("\u{00E9}"));
    }

    #[test]
    fn links() {
        let base = Url::parse("https://example.com/a/b").unwrap();
        assert_eq!(
            clean_link(&base, "../c?utm_source=x&id=5#top").unwrap(),
            "https://example.com/c?id=5"
        );
        assert_eq!(
            clean_link(&base, "/d?fbclid=1").unwrap(),
            "https://example.com/d"
        );
        assert!(clean_link(&base, "javascript:void(0)").is_none());
        assert_eq!(
            clean_image(&base, "/i.png?w=300&sig=abc").unwrap(),
            "https://example.com/i.png"
        );
    }

    #[test]
    fn noise_tokens() {
        assert!(is_noise_token_list("sidebar ad-slot"));
        assert!(is_noise_token_list("cookie_banner"));
        assert!(is_noise_token_list("most-read"));
        assert!(!is_noise_token_list("header shadow"));
        assert!(!is_noise_token_list("article-body"));
        assert!(is_noise_token_list("onetrust-consent-sdk"));
        assert!(is_noise_token_list("sp_message_container_893412"));
        assert!(is_noise_token_list("usercentrics-root"));
        assert!(is_noise_token_list("CybotCookiebotDialog"));
        assert!(!is_noise_token_list("adress")); // German spelling, not "ad"
    }
}
