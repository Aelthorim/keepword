//! The Keepword canonicalizer and diff engine.
//!
//! Normalization maps a captured response to a text form that changes when
//! the page's *content* changes and stays put when only per-request noise
//! does. Its output is hashed into the attestation's `norm.hash`, together
//! with a `norm.profile` digest naming the exact normalizer version and site
//! rules used.

mod clock;
pub mod diff;
mod html;
mod noise;
pub mod rules;

use std::sync::LazyLock;

use keepword_core::{Digest, NormCommitment};
use regex::bytes::Regex;
use url::Url;

pub use noise::clean_text;
pub use rules::{RuleError, SiteRules};

/// Bump whenever normalizer output can change for the same input.
pub const VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Html,
    Json,
    Text,
    /// Anything else (PDFs, images...). Normalized form is the body hash.
    Opaque,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Html => "html",
            Kind::Json => "json",
            Kind::Text => "text",
            Kind::Opaque => "opaque",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Normalized {
    pub kind: Kind,
    pub text: String,
    pub commitment: NormCommitment,
    /// The site rules that were applied, if any.
    pub rules: Option<SiteRules>,
}

#[derive(Clone, Debug, Default)]
pub struct Normalizer {
    rules: Vec<SiteRules>,
}

impl Normalizer {
    pub fn new(rules: Vec<SiteRules>) -> Result<Self, RuleError> {
        for r in &rules {
            r.validate()?;
        }
        Ok(Normalizer { rules })
    }

    /// The most specific rule set whose host matches.
    pub fn rules_for(&self, url: &Url) -> Option<&SiteRules> {
        let host = url.host_str()?.to_ascii_lowercase();
        self.rules
            .iter()
            .filter(|r| r.matches(&host))
            .max_by_key(|r| r.host.len())
    }

    /// `fetched_at_ms` is the signed capture time; timestamps equal to it
    /// are live clocks and get masked.
    pub fn normalize(
        &self,
        url: &Url,
        content_type: Option<&str>,
        body: &[u8],
        fetched_at_ms: i64,
    ) -> Normalized {
        normalize_with(self.rules_for(url), url, content_type, body, fetched_at_ms)
    }
}

/// Profile digest for a normalizer version and optional rules.
pub fn profile(rules: Option<&SiteRules>) -> Digest {
    let rules_json = rules
        .map(|r| serde_json::to_string(r).expect("rules serialize"))
        .unwrap_or_default();
    Digest::tagged(
        "keepword norm-profile v1",
        &[&VERSION.to_be_bytes(), rules_json.as_bytes()],
    )
}

/// Normalize with explicit rules. Verifiers use this to re-run a capture's
/// normalization from a bundle.
pub fn normalize_with(
    rules: Option<&SiteRules>,
    url: &Url,
    content_type: Option<&str>,
    body: &[u8],
    fetched_at_ms: i64,
) -> Normalized {
    let kind = detect(content_type, body);
    let mut text = format!("keepword-norm/{VERSION} {}\n", kind.label());
    match kind {
        Kind::Html => {
            let s = decode(content_type, body);
            for line in html::normalize(&s, url, rules, fetched_at_ms) {
                text.push_str(&line);
                text.push('\n');
            }
        }
        Kind::Json => match serde_json::from_slice::<serde_json::Value>(body) {
            // serde_json's default map is ordered by key, so this is canonical.
            Ok(v) => {
                text.push_str(&serde_json::to_string_pretty(&v).expect("json serializes"));
                text.push('\n');
            }
            Err(_) => push_text(&mut text, &decode(content_type, body), fetched_at_ms),
        },
        Kind::Text => push_text(&mut text, &decode(content_type, body), fetched_at_ms),
        Kind::Opaque => {
            text.push_str(&format!("body: {}\n", Digest::of(body)));
        }
    }
    let commitment = NormCommitment {
        profile: profile(rules),
        hash: Digest::of(text.as_bytes()),
    };
    Normalized {
        kind,
        text,
        commitment,
        rules: rules.cloned(),
    }
}

fn push_text(out: &mut String, s: &str, fetched_at_ms: i64) {
    for line in s.lines() {
        let cleaned = clean_text(line);
        let l = clock::mask_now(&cleaned, fetched_at_ms);
        if !l.is_empty() {
            out.push_str(&l);
            out.push('\n');
        }
    }
}

fn detect(content_type: Option<&str>, body: &[u8]) -> Kind {
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    let mime = ct.split(';').next().unwrap_or("").trim();
    match mime {
        "text/html" | "application/xhtml+xml" => Kind::Html,
        m if m == "application/json" || m.ends_with("+json") => Kind::Json,
        m if m.starts_with("text/") => Kind::Text,
        "" => {
            let head = &body[..body.len().min(512)];
            let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
            if lower.contains("<html") || lower.contains("<!doctype html") {
                Kind::Html
            } else if std::str::from_utf8(body).is_ok() {
                Kind::Text
            } else {
                Kind::Opaque
            }
        }
        _ => Kind::Opaque,
    }
}

static META_CHARSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta[^>]+charset\s*=\s*["']?([a-zA-Z0-9_\-:.]+)"#).expect("valid regex")
});

/// Decode using the Content-Type charset, a BOM, or a `<meta charset>` in the
/// first 2 KiB, falling back to UTF-8.
fn decode(content_type: Option<&str>, body: &[u8]) -> String {
    let from_header = content_type.and_then(|ct| {
        ct.split(';')
            .filter_map(|p| p.trim().strip_prefix("charset="))
            .next()
            .map(|c| c.trim_matches('"').to_string())
    });
    let from_meta = || {
        META_CHARSET
            .captures(&body[..body.len().min(2048)])
            .and_then(|c| c.get(1))
            .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
    };
    let enc = from_header
        .or_else(from_meta)
        .and_then(|l| encoding_rs::Encoding::for_label(l.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    // `decode` also honours a BOM, which takes precedence per the spec.
    enc.decode(body).0.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(html: &str) -> Normalized {
        let url = Url::parse("https://news.example/article/1").unwrap();
        Normalizer::default().normalize(&url, Some("text/html; charset=utf-8"), html.as_bytes(), 0)
    }

    const PAGE: &str = r#"<!doctype html><html><head>
        <title>Minister resigns</title>
        <meta property="article:modified_time" content="2024-05-01T10:00:00Z">
        <script>var csrf = "abc123";</script>
        </head><body>
        <nav><a href="/">Home</a></nav>
        <main>
          <h1>Minister resigns</h1>
          <p class="byline">By A. Writer, <time datetime="2024-05-01T09:00:00Z">5 minutes ago</time></p>
          <div class="ad-slot">BUY NOW</div>
          <p>The minister <b>resigned</b> on Monday. <a href="/more?utm_source=tw#x">More</a></p>
          <img src="/img/photo.jpg?w=800" alt="The minister">
          <div id="cookie-consent">We use cookies</div>
          <p hidden>secret</p>
          <ul><li>One</li><li>Two</li></ul>
        </main>
        </body></html>"#;

    #[test]
    fn extracts_content() {
        let n = norm(PAGE);
        let expected = "keepword-norm/2 html\n\
            title: Minister resigns\n\
            modified: 2024-05-01T10:00:00Z\n\
            h1: Minister resigns\n\
            p: By A. Writer, 2024-05-01T09:00:00Z\n\
            p: The minister resigned on Monday. More\n\
            link: https://news.example/more | More\n\
            img: https://news.example/img/photo.jpg | The minister\n\
            li: One\n\
            li: Two\n";
        assert_eq!(n.text, expected);
        assert_eq!(n.kind, Kind::Html);
    }

    #[test]
    fn stable_under_noise() {
        let noisy = PAGE
            .replace("abc123", "zzz999")
            .replace("5 minutes ago", "6 minutes ago")
            .replace("BUY NOW", "SALE")
            .replace("utm_source=tw", "utm_source=fb")
            .replace("?w=800", "?w=1200")
            .replace("<b>resigned</b> on", "<b>resigned</b>\n\n   on");
        assert_eq!(norm(PAGE).commitment, norm(&noisy).commitment);
    }

    #[test]
    fn sensitive_to_content() {
        let edited = PAGE.replace("on Monday", "on Tuesday");
        assert_ne!(norm(PAGE).commitment.hash, norm(&edited).commitment.hash);
        let relinked = PAGE.replace("/more?", "/other?");
        assert_ne!(norm(PAGE).commitment.hash, norm(&relinked).commitment.hash);
    }

    #[test]
    fn site_rules_change_profile_and_output() {
        let rules = SiteRules {
            host: "example".into(),
            remove: vec![".byline".into()],
            root: None,
        };
        let n = Normalizer::new(vec![rules]).unwrap();
        let url = Url::parse("https://news.example/a").unwrap();
        let out = n.normalize(&url, Some("text/html"), PAGE.as_bytes(), 0);
        assert!(!out.text.contains("A. Writer"));
        assert_ne!(out.commitment.profile, profile(None));
        assert!(
            Normalizer::new(vec![SiteRules {
                host: "x".into(),
                remove: vec!["[[".into()],
                root: None
            }])
            .is_err()
        );
    }

    #[test]
    fn json_is_key_order_independent() {
        let url = Url::parse("https://api.example/").unwrap();
        let n = Normalizer::default();
        let a = n.normalize(&url, Some("application/json"), br#"{"b":1,"a":[1,2]}"#, 0);
        let b = n.normalize(
            &url,
            Some("application/json"),
            br#"{ "a":[1,2], "b":1 }"#,
            0,
        );
        assert_eq!(a.commitment, b.commitment);
    }

    #[test]
    fn legacy_charset() {
        let url = Url::parse("https://example.de/").unwrap();
        let body = b"<html><head><meta charset=\"iso-8859-1\"></head><body><p>Gr\xfc\xdfe</p></body></html>";
        let n = Normalizer::default().normalize(&url, Some("text/html"), body, 0);
        assert!(n.text.contains("p: Grüße"), "{}", n.text);
    }

    #[test]
    fn opaque_bodies() {
        let url = Url::parse("https://example.com/f.pdf").unwrap();
        let n =
            Normalizer::default().normalize(&url, Some("application/pdf"), b"%PDF-1.7 \x00\x01", 0);
        assert_eq!(n.kind, Kind::Opaque);
    }
}
