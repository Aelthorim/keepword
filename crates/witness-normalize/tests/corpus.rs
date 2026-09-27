//! Regression corpus: realistic pages plus variants that must or must not
//! register as edits.
//!
//! Each fixture is modelled on a common publishing stack (a German public
//! broadcaster's article, WordPress with Jetpack and Cloudflare, a SaaS
//! privacy policy behind OneTrust, GOV.UK, a JS-rendered dashboard). Noise
//! variants reproduce what changes between two requests to the real thing.

use std::fs;

use url::Url;
use witness_normalize::diff::{self, Disclosure};
use witness_normalize::Normalizer;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Expect {
    /// Must normalize identically.
    Same,
    /// Must change and be classified as silent.
    Silent,
    /// Must change and be classified as disclosed.
    Disclosed,
}

struct Variant {
    name: &'static str,
    replace: &'static [(&'static str, &'static str)],
    /// Seconds after the base capture time.
    later_s: i64,
    expect: Expect,
}

const T0: i64 = 1_790_499_205_000; // 2026-09-27T08:53:25Z

fn check(fixture: &str, url: &str, variants: &[Variant]) {
    let base = fs::read_to_string(format!(
        "{}/tests/corpus/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let url = Url::parse(url).unwrap();
    let n = Normalizer::default();
    let a = n.normalize(&url, Some("text/html; charset=utf-8"), base.as_bytes(), T0);
    assert!(
        a.text.lines().count() > 3,
        "{fixture} normalized to almost nothing:\n{}",
        a.text
    );
    for v in variants {
        let mut page = base.clone();
        for (from, to) in v.replace {
            assert!(
                page.contains(from),
                "{fixture}/{}: pattern {from:?} not in fixture",
                v.name
            );
            page = page.replace(from, to);
        }
        let b = n.normalize(
            &url,
            Some("text/html; charset=utf-8"),
            page.as_bytes(),
            T0 + v.later_s * 1000,
        );
        let got = match diff::diff(&a.text, &b.text) {
            None => Expect::Same,
            Some(c) => match c.disclosure {
                Disclosure::Silent => Expect::Silent,
                Disclosure::Disclosed { .. } => Expect::Disclosed,
            },
        };
        assert_eq!(
            got,
            v.expect,
            "{fixture}/{}\n--- diff ---\n{}",
            v.name,
            diff::diff(&a.text, &b.text)
                .map(|c| c.unified)
                .unwrap_or_default()
        );
    }
}

#[test]
fn news_de() {
    check(
        "news-de.html",
        "https://nachrichten.example.de/inland/haushalt-2027-100.html",
        &[
            Variant {
                name: "second request",
                replace: &[
                    ("a8f3c1d9e2", "0c9d8e7f6a"),
                    ("1.204 Shares", "1.388 Shares"),
                    ("312 Kommentare", "340 Kommentare"),
                    ("div-gpt-ad-1695812-2", "div-gpt-ad-1695899-2"),
                    ("app.css?v=20260927", "app.css?v=20260928"),
                    ("sig=9f2c", "sig=77aa"),
                    ("Steuerschätzung: Weniger Einnahmen", "Wetter: Sturm im Norden"),
                    ("Wir verwenden Cookies.", "Wir und unsere 312 Partner verwenden Cookies."),
                    ("utm_source=intern", "utm_source=startseite"),
                    ("Das könnte Sie auch interessieren", "Empfehlungen für Sie"),
                ],
                later_s: 600,
                expect: Expect::Same,
            },
            Variant {
                name: "number quietly changed",
                replace: &[("48 Milliarden", "52 Milliarden")],
                later_s: 3600,
                expect: Expect::Silent,
            },
            Variant {
                name: "quote removed",
                replace: &[("„Das ist ein Haushalt der verpassten Chancen“, sagte die Fraktionschefin.", "")],
                later_s: 3600,
                expect: Expect::Silent,
            },
            Variant {
                name: "edit with new Stand line",
                replace: &[("48 Milliarden", "52 Milliarden"), ("Stand: 27.09.2026 10:15 Uhr", "Stand: 27.09.2026 11:40 Uhr")],
                later_s: 3600,
                expect: Expect::Disclosed,
            },
            Variant {
                name: "edit with JSON-LD dateModified",
                replace: &[("48 Milliarden", "52 Milliarden"), ("\"dateModified\":\"2026-09-27T10:15:00+02:00\"", "\"dateModified\":\"2026-09-27T11:40:00+02:00\"")],
                later_s: 3600,
                expect: Expect::Disclosed,
            },
            Variant {
                name: "correction appended",
                replace: &[(
                    "<p class=\"autorenzeile\">",
                    "<p><em>Korrektur: In einer früheren Version stand, die Neuverschuldung liege bei 52 Milliarden Euro.</em></p><p class=\"autorenzeile\">",
                )],
                later_s: 3600,
                expect: Expect::Disclosed,
            },
            Variant {
                name: "headline changed",
                replace: &[("<h1 class=\"article__headline\">Bundestag beschließt Haushalt 2027</h1>", "<h1 class=\"article__headline\">Bundestag beschließt umstrittenen Haushalt 2027</h1>")],
                later_s: 3600,
                expect: Expect::Silent,
            },
        ],
    );
}

#[test]
fn blog_wordpress() {
    check(
        "blog-wp.html",
        "https://blog.example.com/2026/06/01/cloud/",
        &[
            Variant {
                name: "second request",
                replace: &[
                    ("4b1f0c2d77", "91aa0e3b54"),
                    // Cloudflare re-keys obfuscated addresses on every request.
                    (
                        "e3908e8290a3818f8c84cd869b828e938f86cd808c8e\"><span",
                        "5a29373b291a38363d3574223b37363f36743935\"><span",
                    ),
                    (
                        "data-cfemail=\"e3908e8290a3818f8c84cd869b828e938f86cd808c8e\"",
                        "data-cfemail=\"5a29373b291a38363d3574223b37363f36743935\"",
                    ),
                    ("ver=6.6.1", "ver=6.6.2"),
                    ("2 days ago", "3 days ago"),
                    ("3 thoughts on", "4 thoughts on"),
                    ("Why Kubernetes", "Our 2025 in review"),
                ],
                later_s: 86_400,
                expect: Expect::Same,
            },
            Variant {
                name: "cost figure changed",
                replace: &[("it is $9,500", "it is $14,500")],
                later_s: 86_400,
                expect: Expect::Silent,
            },
            Variant {
                name: "bullet removed",
                replace: &[("<li>We underestimated power density.</li>", "")],
                later_s: 86_400,
                expect: Expect::Silent,
            },
            Variant {
                name: "edit with modified time",
                replace: &[
                    ("it is $9,500", "it is $14,500"),
                    ("2026-06-02T14:11:09+00:00", "2026-09-27T09:00:00+00:00"),
                ],
                later_s: 86_400,
                expect: Expect::Disclosed,
            },
        ],
    );
}

#[test]
fn privacy_policy() {
    check(
        "privacy-policy.html",
        "https://acme.example/legal/privacy",
        &[
            Variant {
                name: "second request",
                replace: &[
                    ("Zx81kQpLmN0aa\">\n</head>", "Qq0Lr7Tt21bXz\">\n</head>"),
                    ("value=\"Zx81kQpLmN0aa\"", "value=\"Qq0Lr7Tt21bXz\""),
                    (
                        "We use cookies to improve your experience.",
                        "We and our partners use cookies.",
                    ),
                ],
                later_s: 7 * 86_400,
                expect: Expect::Same,
            },
            Variant {
                name: "the classic",
                replace: &[(
                    "We do not sell your personal information.",
                    "We may share personal information with advertising partners.",
                )],
                later_s: 7 * 86_400,
                expect: Expect::Silent,
            },
            Variant {
                name: "retention extended with date bump",
                replace: &[
                    ("for 30 days after deletion", "for 3 years after deletion"),
                    (
                        "Last updated: March 3, 2026",
                        "Last updated: September 20, 2026",
                    ),
                ],
                later_s: 7 * 86_400,
                expect: Expect::Disclosed,
            },
            Variant {
                name: "subprocessor link retargeted",
                replace: &[("/legal/subprocessors", "/legal/partners")],
                later_s: 7 * 86_400,
                expect: Expect::Silent,
            },
        ],
    );
}

#[test]
fn gov_uk() {
    check(
        "gov-uk.html",
        "https://www.gov.uk/visa-fees",
        &[
            Variant {
                name: "second request",
                replace: &[
                    ("Cookies on GOV.UK", "Cookies on GOV.UK (updated)"),
                    ("Visas and immigration", "Browse: Visas"),
                ],
                later_s: 3600,
                expect: Expect::Same,
            },
            Variant {
                name: "fee changed silently",
                replace: &[("£475", "£490")],
                later_s: 3600,
                expect: Expect::Silent,
            },
            Variant {
                name: "fee changed with last-updated",
                replace: &[
                    ("£475", "£490"),
                    ("Last updated 12 May 2026", "Last updated 27 September 2026"),
                ],
                later_s: 3600,
                expect: Expect::Disclosed,
            },
        ],
    );
}

#[test]
fn rendered_dashboard_clock() {
    check(
        "app-rendered.html",
        "https://status.example.com/",
        &[
            Variant {
                name: "later render",
                replace: &[
                    ("2026-09-27T08:53:25.412Z", "2026-09-27T09:08:26.019Z"),
                    ("5 minutes ago", "2 minutes ago"),
                    ("variant-b", "variant-a"),
                    ("r-8812", "r-9920"),
                ],
                later_s: 900,
                expect: Expect::Same,
            },
            Variant {
                name: "status changed",
                replace: &[
                    ("Degraded performance", "Operational"),
                    ("2026-09-27T08:53:25.412Z", "2026-09-27T09:08:26.019Z"),
                ],
                later_s: 900,
                expect: Expect::Silent,
            },
        ],
    );
}
