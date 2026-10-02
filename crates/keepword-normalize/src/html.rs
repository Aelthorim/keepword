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

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use ego_tree::NodeId;
use ego_tree::iter::Children;
use html5ever::LocalName;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, Tag, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
    TokenizerResult,
};
use html5ever::tree_builder::{Tracer, TreeBuilder, TreeBuilderOpts};
use scraper::{ElementRef, Html, Node, Selector};
use url::Url;

use crate::clock::mask_now;
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

/// How much parser state (open elements and active formatting elements) a
/// document may build up before further start tags are ignored. The parser
/// scans that state for most tokens, so without a bound a page of nested
/// tags takes time quadratic in its size: a megabyte of `<div>` costs
/// minutes, the 32 MiB a capture may have days. Chromium and Safari don't
/// nest elements deeper than 512 either.
const MAX_PARSER_STATE: usize = 512;

/// Start tags that never leave an element open (void elements), or whose
/// content the tokenizer must read as text: always passed on.
fn opens_nothing(name: &LocalName) -> bool {
    matches!(
        &**name,
        "area"
            | "base"
            | "basefont"
            | "bgsound"
            | "br"
            | "col"
            | "embed"
            | "frame"
            | "hr"
            | "image"
            | "img"
            | "input"
            | "keygen"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
            | "iframe"
            | "noembed"
            | "noframes"
            | "noscript"
            | "plaintext"
            | "script"
            | "style"
            | "textarea"
            | "title"
            | "xmp"
    )
}

/// Counts the handles the tree builder holds.
struct Count(Cell<usize>);

impl Tracer for Count {
    type Handle = NodeId;

    fn trace_handle(&self, _: &NodeId) {
        self.0.set(self.0.get() + 1);
    }
}

/// The tree builder, minus the start tags that would take its state past
/// [`MAX_PARSER_STATE`] and, while it stays there, the end tags that would
/// have closed them (their content stays, in the element they would have
/// nested in), and minus everything after the tree reaches `max_nodes`.
struct Bounded {
    tb: TreeBuilder<NodeId, Html>,
    dropped: HashMap<LocalName, usize>,
    max_nodes: usize,
}

impl Bounded {
    fn state(&self) -> usize {
        let n = Count(Cell::new(0));
        self.tb.trace_handles(&n);
        n.0.get()
    }
}

impl TokenSink for Bounded {
    type Handle = NodeId;

    fn process_token(&mut self, token: Token, line: u64) -> TokenSinkResult<NodeId> {
        if self.tb.sink.tree.nodes().len() > self.max_nodes && token != Token::EOFToken {
            return TokenSinkResult::Continue;
        }
        if let Token::TagToken(Tag {
            kind,
            name,
            self_closing,
            ..
        }) = &token
        {
            let opens = *kind == TagKind::StartTag && !opens_nothing(name);
            if opens || (*kind == TagKind::EndTag && !self.dropped.is_empty()) {
                if self.state() < MAX_PARSER_STATE {
                    // Back below the bound, the elements dropped at it would
                    // have been closed by now: their names mustn't take the
                    // end tags of later elements.
                    self.dropped.clear();
                } else if opens {
                    if !self_closing {
                        *self.dropped.entry(name.clone()).or_default() += 1;
                    }
                    return TokenSinkResult::Continue;
                } else if let Some(n) = self.dropped.get_mut(name).filter(|n| **n > 0) {
                    *n -= 1;
                    return TokenSinkResult::Continue;
                }
            }
        }
        self.tb.process_token(token, line)
    }

    fn end(&mut self) {
        self.tb.end();
    }

    fn adjusted_current_node_present_but_not_in_html_namespace(&self) -> bool {
        self.tb
            .adjusted_current_node_present_but_not_in_html_namespace()
    }
}

/// `Html::parse_document`, with the parser's state and output bounded.
///
/// Markup takes at least two bytes per node, but reopening formatting
/// elements (`<font>` left open, then a new paragraph) creates nodes the
/// input doesn't have: 160 kB could build 10 million of them. The tree may
/// have one node per two bytes of input; the rest of the input is ignored.
fn parse(html: &str) -> Html {
    let tb = TreeBuilder::new(Html::new_document(), TreeBuilderOpts::default());
    let sink = Bounded {
        tb,
        dropped: HashMap::new(),
        max_nodes: html.len() / 2 + 65_536,
    };
    let mut tok = Tokenizer::new(sink, TokenizerOpts::default());
    let mut input = BufferQueue::default();
    input.push_back(StrTendril::from(html));
    while let TokenizerResult::Script(_) = tok.feed(&mut input) {}
    tok.end();
    tok.sink.tb.sink
}

struct Walker<'a> {
    base: &'a Url,
    skip: HashSet<NodeId>,
    out: Vec<String>,
    buf: String,
    pending: Vec<String>,
    fetched_at_ms: i64,
}

/// An element whose children are being walked.
struct Open<'b> {
    el: ElementRef<'b>,
    /// The kind its children inherit.
    kind: &'static str,
    /// A block: flushed as `kind` when its children are done.
    block: bool,
    children: Children<'b, Node>,
}

impl<'a> Walker<'a> {
    fn flush(&mut self, kind: &str) {
        let cleaned = clean_text(&self.buf);
        let text = mask_now(&cleaned, self.fetched_at_ms);
        self.buf.clear();
        if !text.is_empty() {
            self.out.push(format!("{kind}: {text}"));
        }
        self.out.append(&mut self.pending);
    }

    /// Walk `root` in document order. Iterative: pages can nest elements
    /// deeper than a thread's stack can recurse.
    fn walk(&mut self, root: ElementRef<'_>, kind: &'static str) {
        let mut stack: Vec<Open<'_>> = self.enter(root, kind).into_iter().collect();
        while let Some(top) = stack.last_mut() {
            let kind = top.kind;
            match top.children.next() {
                Some(child) => match child.value() {
                    Node::Text(t) => self.buf.push_str(t),
                    Node::Element(_) => {
                        if let Some(open) =
                            ElementRef::wrap(child).and_then(|c| self.enter(c, kind))
                        {
                            stack.push(open);
                        }
                    }
                    _ => {}
                },
                None => {
                    let done = stack.pop().expect("stack is not empty");
                    self.leave(done);
                }
            }
        }
    }

    /// Start on an element. Returns it if its children are to be walked.
    fn enter<'b>(&mut self, el: ElementRef<'b>, kind: &'static str) -> Option<Open<'b>> {
        let v = el.value();
        let name = v.name();
        if DROP.contains(&name) || self.skip.contains(&el.id()) || is_hidden(el) {
            return None;
        }
        if v.attr("class").is_some_and(is_noise_token_list)
            || v.attr("id").is_some_and(is_noise_token_list)
        {
            return None;
        }
        match name {
            "br" => {
                self.buf.push(' ');
                return None;
            }
            "img" => {
                if let Some(src) = v.attr("src").and_then(|s| clean_image(self.base, s)) {
                    let alt = clean_text(v.attr("alt").unwrap_or(""));
                    self.pending.push(format!("img: {src} | {alt}"));
                }
                return None;
            }
            // A machine-readable datetime replaces "5 minutes ago".
            "time" => {
                if let Some(dt) = v.attr("datetime") {
                    self.buf.push(' ');
                    self.buf.push_str(dt.trim());
                    self.buf.push(' ');
                    return None;
                }
            }
            _ => {}
        }

        let (kind, block) = match block_kind(name) {
            Some(k) => {
                self.flush(kind);
                (if k.is_empty() { kind } else { k }, true)
            }
            None => (kind, false),
        };
        Some(Open {
            el,
            kind,
            block,
            children: el.children(),
        })
    }

    /// Finish an element once its children are done.
    fn leave(&mut self, open: Open<'_>) {
        if open.block {
            self.flush(open.kind);
        }
        let v = open.el.value();
        if v.name() == "a" {
            if let Some(href) = v.attr("href").and_then(|h| clean_link(self.base, h)) {
                let text = clean_text(&link_text(open.el));
                self.pending.push(format!("link: {href} | {text}"));
            }
        }
    }
}

/// A link's text, without the text of links inside it. Links don't nest in
/// valid HTML, but they parse nested inside table cells and the like, and
/// each would repeat all the text below it: a 1 MB page could normalize to
/// gigabytes.
fn link_text(a: ElementRef<'_>) -> String {
    let mut text = String::new();
    let mut stack = vec![a.children()];
    while let Some(top) = stack.last_mut() {
        match top.next() {
            Some(child) => match child.value() {
                Node::Text(t) => text.push_str(t),
                Node::Element(e) if is_html_a(e) => {}
                _ => stack.push(child.children()),
            },
            None => {
                stack.pop();
            }
        }
    }
    text
}

fn is_html_a(e: &scraper::node::Element) -> bool {
    &*e.name.local == "a" && &*e.name.ns == "http://www.w3.org/1999/xhtml"
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

pub fn normalize(
    html: &str,
    base: &Url,
    rules: Option<&SiteRules>,
    fetched_at_ms: i64,
) -> Vec<String> {
    let doc = parse(html);
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
        fetched_at_ms,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://e.example/").unwrap()
    }

    fn deepest(doc: &Html) -> usize {
        doc.tree
            .nodes()
            .map(|n| n.ancestors().count())
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn parses_like_scraper_below_the_bounds() {
        let nested = format!("<body>{}x{}", "<div>".repeat(400), "</div>".repeat(400));
        for html in [
            "<!doctype html><title>T</title><p>a<b>b<i>c</b>d</i><table><tr><td>e<a href=/x>f",
            "<p><font color=1>a<p><font color=2>b<p>c<p>d",
            "<svg><title>s</title></svg><math><mi>m</mi></math><template><p>t</template>",
            "<select><option>1<option>2</select><textarea><p>raw</textarea><script>x<y</script>",
            nested.as_str(),
        ] {
            assert!(parse(html) == Html::parse_document(html), "{html}");
        }
    }

    #[test]
    fn nesting_is_bounded_and_keeps_the_text() {
        let n = 50_000;
        let html: String = (0..n).map(|i| format!("<div>t{i} ")).collect();
        let doc = parse(&html);
        assert!(deepest(&doc) <= MAX_PARSER_STATE + 8, "{}", deepest(&doc));
        let text: String = doc.root_element().text().collect();
        assert!(text.contains("t0 ") && text.contains(&format!("t{} ", n - 1)));
        // Tags past the bound are dropped with their end tags, so what
        // follows is back where it belongs.
        let html = format!(
            "<div>{}x{}</div><p>after",
            "<div>".repeat(n),
            "</div>".repeat(n)
        );
        let out = normalize(&html, &base(), None, 0);
        assert_eq!(out.last().map(String::as_str), Some("p: after"), "{out:?}");
    }

    #[test]
    fn dropped_tags_dont_outlast_the_bound() {
        // The <div> past the bound is never closed. Back below the bound,
        // it mustn't take the end tag of a later div: that div would stay
        // open around everything after it, hidden here.
        let n = 600;
        let html = format!(
            "<body>{}<div>deep{}<div hidden>secret</div><p>after",
            "<section>".repeat(n),
            "</section>".repeat(n)
        );
        let out = normalize(&html, &base(), None, 0);
        assert_eq!(out, ["text: deep", "p: after"]);
    }

    #[test]
    fn reopened_formatting_cant_multiply_nodes() {
        // Each paragraph reopens every <font> still open: without a bound,
        // 160 kB built 10 million nodes and 3.6 GB.
        let fonts: String = (0..250).map(|i| format!("<font color=c{i}>")).collect();
        let html = format!("<p>{fonts}{}", "<p>x".repeat(40_000));
        let doc = parse(&html);
        assert!(doc.tree.nodes().len() <= html.len() / 2 + 65_536 + 1_000);
    }

    #[test]
    fn deep_pages_dont_overflow_the_stack() {
        // A capture is normalized on a runtime worker thread with a 2 MiB
        // stack; 5000 nested elements used to abort the process.
        let html = format!(
            "<html><body>{}deep{}",
            "<span>".repeat(200_000),
            "</span>".repeat(200_000)
        );
        let out = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || normalize(&html, &base(), None, 0))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(out, ["text: deep"]);
    }

    #[test]
    fn nested_links_dont_repeat_their_text() {
        // Links nest inside table cells and the like. Each used to repeat
        // the text of every link inside it: quadratic output.
        let n = 100;
        let html = format!(
            "<body>{}{}",
            "<a href=/x><marquee>".repeat(n),
            "word ".repeat(1000)
        );
        let out = normalize(&html, &base(), None, 0);
        let links: Vec<_> = out.iter().filter(|l| l.starts_with("link: ")).collect();
        assert_eq!(links.len(), n);
        let total: usize = out.iter().map(String::len).sum();
        assert!(total < 3 * html.len(), "{total} bytes from {}", html.len());
        assert!(links[0].ends_with(&"word ".repeat(1000).trim_end().to_string()));
    }
}
