//! HTML → normalized line format.
//!
//! The output is one line per content block, prefixed by its kind:
//!
//! ```text
//! title: Example Domain
//! modified: 2024-05-01T10:00:00Z
//! h1: Example Domain
//! p: This domain is for use in illustrative examples.
//! link: https://www.iana.org/domains/example | More information...
//! ```
//!
//! Lines are diffable, human-readable and stable under the noise the plan
//! calls out (ads, timestamps, CSRF tokens, relative times).

use std::collections::HashSet;

use scraper::{ElementRef, Html, Node, Selector};
use url::Url;

use crate::noise::{clean_image, clean_link, clean_text, is_noise_token_list};
use crate::rules::SiteRules;

/// Elements whose content is never meaningful page text.
const DROP: &[&str] = &[
    "script", "style", "noscript", "template", "iframe", "object", "embed", "canvas", "svg",
    "math", "link", "meta", "head", "input", "select", "textarea", "button", "option", "audio",
    "video", "source", "track", "map", "dialog",
];

fn block_kind(name: &str) -> Option<&'static str> {
    Some(match name {
        "h1" => "h1",
        "h2" => "h2",
        "h3" => "h3",
        "h4" => "h4",
        "h5" => "h5",
        "h6" => "h6",
        "p" => "p",
        "li" => "li",
        "blockquote" => "quote",
        "pre" => "pre",
        "td" | "th" => "cell",
        "dt" => "dt",
        "dd" => "dd",
        "figcaption" | "caption" | "legend" => "caption",
        // Generic blocks inherit the surrounding kind.
        "html" | "body" | "div" | "section" | "article" | "main" | "header" | "footer" | "nav"
        | "aside" | "ul" | "ol" | "dl" | "table" | "thead" | "tbody" | "tfoot" | "tr" | "form"
        | "fieldset" | "figure" | "address" | "details" | "summary" | "hr" | "center" => "",
        _ => return None,
    })
}

struct Walker<'a> {
    base: &'a Url,
    skip: HashSet<ego_tree::NodeId>,
    out: Vec<String>,
    buf: String,
    pending: Vec<String>,
}

impl<'a> Walker<'a> {
    fn flush(&mut self, kind: &str) {
        let text = clean_text(&self.buf);
        self.buf.clear();
        if !text.is_empty() {
            self.out.push(format!("{kind}: {text}"));
        }
        self.out.append(&mut self.pending);
    }

    fn walk(&mut self, el: ElementRef<'_>, kind: &'static str) {
        let v = el.value();
        let name = v.name();
        if DROP.contains(&name) || self.skip.contains(&el.id()) || is_hidden(el) {
            return;
        }
        if v.attr("class").is_some_and(is_noise_token_list)
            || v.attr("id").is_some_and(is_noise_token_list)
        {
            return;
        }
        match name {
            "br" => {
                self.buf.push(' ');
                return;
            }
            "img" => {
                if let Some(src) = v.attr("src").and_then(|s| clean_image(self.base, s)) {
                    let alt = clean_text(v.attr("alt").unwrap_or(""));
                    self.pending.push(format!("img: {src} | {alt}"));
                }
                return;
            }
            // A machine-readable datetime replaces "5 minutes ago".
            "time" => {
                if let Some(dt) = v.attr("datetime") {
                    self.buf.push(' ');
                    self.buf.push_str(dt.trim());
                    self.buf.push(' ');
                    return;
                }
            }
            _ => {}
        }

        match block_kind(name) {
            Some(k) => {
                self.flush(kind);
                let k = if k.is_empty() { kind } else { k };
                self.children(el, k);
                self.flush(k);
            }
            None => self.children(el, kind),
        }

        if name == "a" {
            if let Some(href) = v.attr("href").and_then(|h| clean_link(self.base, h)) {
                let text = clean_text(&el.text().collect::<String>());
                self.pending.push(format!("link: {href} | {text}"));
            }
        }
    }

    fn children(&mut self, el: ElementRef<'_>, kind: &'static str) {
        for child in el.children() {
            match child.value() {
                Node::Text(t) => self.buf.push_str(t),
                Node::Element(_) => {
                    if let Some(c) = ElementRef::wrap(child) {
                        self.walk(c, kind);
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_hidden(el: ElementRef<'_>) -> bool {
    let v = el.value();
    if v.attr("hidden").is_some() || v.attr("aria-hidden") == Some("true") {
        return true;
    }
    if let Some(style) = v.attr("style") {
        let s: String = style
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if s.contains("display:none") || s.contains("visibility:hidden") {
            return true;
        }
    }
    false
}

fn sel(s: &str) -> Selector {
    Selector::parse(s).expect("static selector")
}

fn first_text(doc: &Html, s: &str) -> Option<String> {
    doc.select(&sel(s))
        .next()
        .map(|e| clean_text(&e.text().collect::<String>()))
        .filter(|t| !t.is_empty())
}

fn meta(doc: &Html, s: &str) -> Option<String> {
    doc.select(&sel(s))
        .filter_map(|e| e.value().attr("content"))
        .map(clean_text)
        .find(|t| !t.is_empty())
}

/// Search JSON-LD blocks for the first string value of `key`.
fn json_ld(doc: &Html, key: &str) -> Option<String> {
    fn find(v: &serde_json::Value, key: &str) -> Option<String> {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(serde_json::Value::String(s)) = m.get(key) {
                    return Some(s.clone());
                }
                m.values().find_map(|v| find(v, key))
            }
            serde_json::Value::Array(a) => a.iter().find_map(|v| find(v, key)),
            _ => None,
        }
    }
    doc.select(&sel(r#"script[type="application/ld+json"]"#))
        .filter_map(|e| {
            serde_json::from_str::<serde_json::Value>(&e.text().collect::<String>()).ok()
        })
        .find_map(|v| find(&v, key))
        .map(|s| clean_text(&s))
}

pub fn normalize(html: &str, base: &Url, rules: Option<&SiteRules>) -> Vec<String> {
    let doc = Html::parse_document(html);
    let mut lines = Vec::new();

    if let Some(t) = first_text(&doc, "title") {
        lines.push(format!("title: {t}"));
    }
    if let Some(c) = doc
        .select(&sel(r#"link[rel="canonical"]"#))
        .find_map(|e| e.value().attr("href"))
        .and_then(|h| clean_link(base, h))
    {
        lines.push(format!("canonical: {c}"));
    }
    if let Some(d) = meta(&doc, r#"meta[name="description"]"#) {
        lines.push(format!("description: {d}"));
    }
    let published = meta(&doc, r#"meta[property="article:published_time"]"#)
        .or_else(|| json_ld(&doc, "datePublished"));
    if let Some(p) = published {
        lines.push(format!("published: {p}"));
    }
    let modified = meta(&doc, r#"meta[property="article:modified_time"]"#)
        .or_else(|| meta(&doc, r#"meta[property="og:updated_time"]"#))
        .or_else(|| json_ld(&doc, "dateModified"));
    if let Some(m) = modified {
        lines.push(format!("modified: {m}"));
    }

    let mut skip = HashSet::new();
    if let Some(r) = rules {
        for s in r.remove_selectors() {
            skip.extend(doc.select(&s).map(|e| e.id()));
        }
    }

    let root = rules
        .and_then(|r| r.root_selector())
        .and_then(|s| doc.select(&s).next())
        .or_else(|| unique(&doc, "main"))
        .or_else(|| unique(&doc, "article"))
        .or_else(|| doc.select(&sel("body")).next())
        .unwrap_or_else(|| doc.root_element());

    let mut w = Walker {
        base,
        skip,
        out: lines,
        buf: String::new(),
        pending: Vec::new(),
    };
    w.walk(root, "text");
    w.flush("text");
    w.out
}

fn unique<'a>(doc: &'a Html, s: &str) -> Option<ElementRef<'a>> {
    let selector = sel(s);
    let mut it = doc.select(&selector);
    let first = it.next()?;
    it.next().is_none().then_some(first)
}
