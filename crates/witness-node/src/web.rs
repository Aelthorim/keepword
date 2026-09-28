//! Read-only web UI and the watch scheduler.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use witness_core::bundle::Status;
use witness_core::{Digest, format_ms, now_ms, target};
use witness_normalize::diff::{self, OpTag};
use witness_store::Record;

use crate::{Node, method_name};

// ---------------------------------------------------------------- scheduler

/// Capture every watched URL that is due. Returns how many were attempted.
pub async fn run_due(node: &Arc<Node>, log: impl Fn(String)) -> anyhow::Result<usize> {
    let now = now_ms();
    let due: Vec<_> = node
        .store
        .watches()?
        .into_iter()
        .filter(|w| {
            w.last_run
                .is_none_or(|last| now - last >= w.every_secs as i64 * 1000)
        })
        .collect();
    for w in &due {
        match node.capture(&w.url, w.render).await {
            Ok(o) => {
                node.store.watch_mark(&w.url, now_ms(), None)?;
                let status = match &o.change {
                    Some(c) if c.silent => format!("SILENT EDIT: {}", c.summary),
                    Some(c) => format!("changed: {}", c.summary),
                    None if o.previous.is_none() => "first capture".into(),
                    None => "unchanged".into(),
                };
                log(format!(
                    "{}  {}  {}  {status}",
                    format_ms(now_ms()),
                    o.record.id.short(),
                    w.url
                ));
            }
            Err(e) => {
                node.store
                    .watch_mark(&w.url, now_ms(), Some(&format!("{e:#}")))?;
                log(format!("{}  error  {}  {e:#}", format_ms(now_ms()), w.url));
            }
        }
    }
    Ok(due.len())
}

pub async fn scheduler(node: Arc<Node>, log: impl Fn(String)) -> anyhow::Result<()> {
    loop {
        run_due(&node, &log).await?;
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

// ---------------------------------------------------------------------- web

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/url", get(url_page))
        .route("/diff", get(diff_page))
        .route("/a/{id}", get(attestation_page))
        .route("/a/{id}/bundle.json", get(bundle_json))
        .route("/a/{id}/warc", get(warc))
        .route("/api/tree-head", get(tree_head))
        .route("/network", get(network_page))
        .route("/alerts", get(alerts_page))
        .with_state(node)
}

struct WebError(StatusCode, String);

impl<E: std::fmt::Display> From<E> for WebError {
    fn from(e: E) -> Self {
        WebError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (self.0, page("Error", &format!("<p>{}</p>", esc(&self.1)))).into_response()
    }
}

type WebResult<T> = Result<T, WebError>;

fn not_found(what: &str) -> WebError {
    WebError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn q(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

const CSS: &str = r#"
:root{--bg:#fbfbf9;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--add:#e3f4e1;--del:#fbe4e2;--warn:#b3261e;--accent:#1f5fae}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#9a9993;--line:#2e2e2b;--add:#17351a;--del:#3d1a18;--warn:#ff8a80;--accent:#8ab4f8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}a{color:var(--accent)}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.muted{color:var(--muted)}.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:13px}.wrap{overflow-x:auto}
.silent{color:var(--warn);font-weight:600}.pill{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:4px;font-size:12px}
.diff div{white-space:pre-wrap;word-break:break-word;padding:1px 8px}.diff .ins{background:var(--add)}.diff .del{background:var(--del)}
.diff .gap{color:var(--muted);font-style:italic}.pass{color:#2e7d32}.fail{color:var(--warn);font-weight:600}
pre{background:var(--line);padding:12px;overflow-x:auto;border-radius:6px}
"#;

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content='width=device-width,initial-scale=1'>\
         <title>{} · Witness</title><style>{CSS}</style></head>\
         <body><main><p class=muted><a href='/'>Witness</a> · <a href='/network'>Network</a> · <a href='/alerts'>Alerts</a></p>{body}\
         <p class=muted>Witness {} · free software under the AGPL-3.0 · <a href='{}'>source code</a></p></main></body></html>",
        esc(title),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY"),
    ))
}

fn id_link(id: &Digest) -> String {
    format!("<a class=mono href='/a/{}'>{}</a>", id, id.short())
}

async fn index(State(node): State<Arc<Node>>) -> WebResult<Html<String>> {
    let mut b = String::new();
    b.push_str("<h1>Witness node</h1>");
    b.push_str(&format!(
        "<p class='muted mono'>key {}</p>",
        node.key.public()
    ));
    if let Some(h) = node.store.latest_tree_head()? {
        b.push_str(&format!(
            "<p>Log: {} entries · root <span class=mono>{}</span> · signed {} · <a href='/api/tree-head'>tree head</a></p>",
            h.head.size,
            h.head.root.short(),
            format_ms(h.head.timestamp_ms)
        ));
    }

    let changes = node.store.changes(None, 20)?;
    b.push_str("<h2>Recent changes</h2>");
    if changes.is_empty() {
        b.push_str("<p class=muted>None detected yet.</p>");
    } else {
        b.push_str(
            "<div class=wrap><table><tr><th>Detected</th><th>URL</th><th>Change</th><th></th></tr>",
        );
        for c in changes {
            b.push_str(&format!(
                "<tr><td>{}</td><td><a href='/url?u={}'>{}</a></td><td class='{}'>{}</td><td><a href='/diff?from={}&to={}'>diff</a></td></tr>",
                format_ms(c.detected_at),
                q(&c.url),
                esc(&c.url),
                if c.silent { "silent" } else { "" },
                esc(&c.summary),
                c.from_id,
                c.to_id
            ));
        }
        b.push_str("</table></div>");
    }

    b.push_str("<h2>Pages</h2><div class=wrap><table><tr><th>URL</th><th>Captures</th><th>Versions</th><th>Changes</th><th>Last capture</th></tr>");
    for s in node.store.urls()? {
        b.push_str(&format!(
            "<tr><td><a href='/url?u={}'>{}</a></td><td>{}</td><td>{}</td><td>{}{}</td><td>{}</td></tr>",
            q(&s.url),
            esc(&s.url),
            s.captures,
            s.versions,
            s.changes,
            if s.silent_changes > 0 { format!(" <span class=silent>({} silent)</span>", s.silent_changes) } else { String::new() },
            format_ms(s.last_capture)
        ));
    }
    b.push_str("</table></div>");

    let watches = node.store.watches()?;
    if !watches.is_empty() {
        b.push_str("<h2>Watchlist</h2><div class=wrap><table><tr><th>URL</th><th>Every</th><th>Last run</th><th>Error</th></tr>");
        for w in watches {
            b.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=muted>{}</td></tr>",
                esc(&w.url),
                humantime::format_duration(Duration::from_secs(w.every_secs)),
                w.last_run.map(format_ms).unwrap_or_else(|| "never".into()),
                esc(w.last_error.as_deref().unwrap_or(""))
            ));
        }
        b.push_str("</table></div>");
    }
    Ok(page("Witness", &b))
}

async fn url_page(
    State(node): State<Arc<Node>>,
    Query(p): Query<HashMap<String, String>>,
) -> WebResult<Html<String>> {
    let raw = p.get("u").ok_or_else(|| not_found("url parameter"))?;
    let url = target::canonical_url(raw)?;
    let hist = node.store.history(url.as_str())?;
    // Best effort: fetch the assigned witnesses' latest captures first.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        node.refresh_url(url.as_str()),
    )
    .await;
    let verdict = node.verdict(url.as_str())?;
    if hist.is_empty() && verdict.considered == 0 {
        return Err(not_found("captures for this URL"));
    }
    let mut b = format!(
        "<h1>{}</h1><p><a href='{}' rel=noreferrer>open live page</a></p>",
        esc(url.as_str()),
        esc(url.as_str())
    );
    b.push_str(&verdict_html(&verdict));

    let changes = node.store.changes(Some(url.as_str()), 200)?;
    b.push_str("<h2>Edit history</h2>");
    if changes.is_empty() {
        b.push_str("<p class=muted>No content changes detected.</p>");
    } else {
        b.push_str("<div class=wrap><table><tr><th>Detected</th><th>Change</th><th>From → to</th><th></th></tr>");
        for c in &changes {
            b.push_str(&format!(
                "<tr><td>{}</td><td class='{}'>{}</td><td>{} → {}</td><td><a href='/diff?from={}&to={}'>diff</a></td></tr>",
                format_ms(c.detected_at),
                if c.silent { "silent" } else { "" },
                esc(&c.summary),
                id_link(&c.from_id),
                id_link(&c.to_id),
                c.from_id,
                c.to_id
            ));
        }
        b.push_str("</table></div>");
    }

    b.push_str("<h2>Captures</h2><div class=wrap><table><tr><th>Fetched</th><th>Attestation</th><th>Method</th><th>Status</th><th>Size</th><th>Normalized hash</th></tr>");
    for r in hist.iter().rev() {
        let a = &r.signed.attestation;
        b.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=mono>{}</td></tr>",
            format_ms(a.fetched_at_ms),
            id_link(&r.id),
            method_name(a.method),
            a.status,
            a.body_len,
            a.comparison_hash().short()
        ));
    }
    b.push_str("</table></div>");
    Ok(page(url.as_str(), &b))
}

fn record(node: &Node, id: &str) -> WebResult<Record> {
    let d: Digest = id.parse().map_err(|_| not_found("attestation"))?;
    node.store.get(&d)?.ok_or_else(|| not_found("attestation"))
}

async fn diff_page(
    State(node): State<Arc<Node>>,
    Query(p): Query<HashMap<String, String>>,
) -> WebResult<Html<String>> {
    let from = record(&node, p.get("from").map(String::as_str).unwrap_or(""))?;
    let to = record(&node, p.get("to").map(String::as_str).unwrap_or(""))?;
    let (Some(a), Some(b_text)) = (
        node.normalized_text(&from.signed.attestation)?,
        node.normalized_text(&to.signed.attestation)?,
    ) else {
        return Err(WebError(
            StatusCode::GONE,
            "normalized text was not retained".into(),
        ));
    };
    let fa = &from.signed.attestation;
    let ta = &to.signed.attestation;
    let mut b = format!(
        "<h1>{}</h1><p>{} ({}) → {} ({})</p>",
        esc(&ta.url),
        id_link(&from.id),
        format_ms(fa.fetched_at_ms),
        id_link(&to.id),
        format_ms(ta.fetched_at_ms)
    );
    match diff::diff(&a, &b_text) {
        None => b.push_str("<p>No difference in normalized content.</p>"),
        Some(c) => {
            b.push_str(&format!(
                "<p class='{}'>{}</p><div class='diff mono'>",
                if c.is_silent() { "silent" } else { "" },
                esc(&c.summary())
            ));
            // Show changes with three lines of context; collapse the rest.
            let near: Vec<bool> = (0..c.ops.len())
                .map(|i| {
                    let lo = i.saturating_sub(3);
                    let hi = (i + 4).min(c.ops.len());
                    c.ops[lo..hi].iter().any(|o| o.tag != OpTag::Equal)
                })
                .collect();
            let mut skipped = 0;
            for (op, show) in c.ops.iter().zip(near) {
                if !show {
                    skipped += 1;
                    continue;
                }
                if skipped > 0 {
                    b.push_str(&format!(
                        "<div class=gap>… {skipped} unchanged lines …</div>"
                    ));
                    skipped = 0;
                }
                let (cls, sign) = match op.tag {
                    OpTag::Equal => ("", " "),
                    OpTag::Insert => ("ins", "+"),
                    OpTag::Delete => ("del", "-"),
                };
                b.push_str(&format!(
                    "<div class='{cls}'>{sign} {}</div>",
                    esc(&op.line)
                ));
            }
            if skipped > 0 {
                b.push_str(&format!(
                    "<div class=gap>… {skipped} unchanged lines …</div>"
                ));
            }
            b.push_str("</div>");
        }
    }
    Ok(page("Diff", &b))
}

async fn attestation_page(
    State(node): State<Arc<Node>>,
    Path(id): Path<String>,
) -> WebResult<Html<String>> {
    let rec = record(&node, &id)?;
    let report = Node::verify_bundle(&node.bundle(&rec, true)?);
    let a = &rec.signed.attestation;
    let mut b = format!(
        "<h1>Attestation <span class=mono>{}</span></h1><p><a href='/url?u={}'>{}</a> · {}</p>",
        rec.id.short(),
        q(&a.url),
        esc(&a.url),
        format_ms(a.fetched_at_ms)
    );
    b.push_str(&format!(
        "<p><a href='/a/{0}/bundle.json'>evidence bundle</a> · <a href='/a/{0}/warc'>WARC</a> · verify offline with <code>witness verify --bundle FILE</code></p>",
        rec.id
    ));
    if let Some(c) = a.cert_sha256 {
        let hex: String = c.iter().map(|x| format!("{x:02x}")).collect();
        b.push_str(&format!("<p>TLS certificate: <a href='https://crt.sh/?sha256={hex}' rel=noreferrer>crt.sh</a></p>"));
    }
    let summary = report.summary();
    b.push_str(&format!(
        "<h2>Verification: <span class='{}'>{}</span></h2>",
        if report.ok() { "pass" } else { "fail" },
        summary
            .strength
            .map_or("FAILED".to_string(), |s| format!("verified, {}", s.label()))
    ));
    if summary.strength.is_some() {
        b.push_str("<p>This record shows:</p><ul>");
        for line in &summary.shows {
            b.push_str(&format!("<li>{}</li>", esc(line)));
        }
        b.push_str("</ul><p class=muted>It does not show:</p><ul class=muted>");
        for line in &summary.does_not_show {
            b.push_str(&format!("<li>{}</li>", esc(line)));
        }
        b.push_str("</ul>");
    }
    b.push_str("<table>");
    for c in &report.checks {
        let (cls, label) = match c.status {
            Status::Pass => ("pass", "ok"),
            Status::Fail => ("fail", "FAIL"),
            Status::Skip => ("muted", "skip"),
        };
        b.push_str(&format!(
            "<tr><td class='{cls}'>{label}</td><td>{}</td><td>{}</td></tr>",
            esc(&c.name),
            esc(&c.detail)
        ));
    }
    b.push_str("</table><h2>Signed statement</h2>");
    b.push_str(&format!(
        "<pre>{}</pre>",
        esc(&serde_json::to_string_pretty(&rec.signed)?)
    ));
    Ok(page("Attestation", &b))
}

async fn bundle_json(State(node): State<Arc<Node>>, Path(id): Path<String>) -> WebResult<Response> {
    let rec = record(&node, &id)?;
    let json = serde_json::to_string_pretty(&node.bundle(&rec, true)?)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"witness-{}.json\"", rec.id.short()),
            ),
        ],
        json,
    )
        .into_response())
}

async fn warc(State(node): State<Arc<Node>>, Path(id): Path<String>) -> WebResult<Response> {
    let rec = record(&node, &id)?;
    let a = &rec.signed.attestation;
    let (Some(h), Some(body)) = (
        node.store.blobs.get(&a.headers_hash)?,
        node.store.blobs.get(&a.body_hash)?,
    ) else {
        return Err(WebError(
            StatusCode::GONE,
            "raw content was not retained".into(),
        ));
    };
    Ok((
        [
            (header::CONTENT_TYPE, "application/warc".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"witness-{}.warc\"", rec.id.short()),
            ),
        ],
        witness_capture::warc::export(&rec.signed, &h, &body),
    )
        .into_response())
}

async fn tree_head(State(node): State<Arc<Node>>) -> WebResult<Response> {
    let h = node
        .store
        .latest_tree_head()?
        .ok_or_else(|| not_found("tree head"))?;
    Ok(axum::Json(h).into_response())
}

fn verdict_html(v: &crate::consensus::VerdictView) -> String {
    use witness_core::quorum::Verdict;
    let mut b = String::from("<h2>Across witnesses</h2>");
    let group_rows = |groups: &[witness_core::quorum::Group]| {
        let mut t = String::from(
            "<table><tr><th>Normalized content</th><th>Witnesses</th><th>Independent networks</th></tr>",
        );
        for g in groups {
            t.push_str(&format!(
                "<tr><td class=mono>{}</td><td>{}</td><td>{}</td></tr>",
                g.hash.short(),
                g.witnesses.len(),
                g.asns
                    .iter()
                    .map(|a| format!("AS{a}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        t.push_str("</table>");
        t
    };
    match &v.evaluation.verdict {
        Verdict::Agreed { group, dissenters } => {
            b.push_str(&format!(
                "<p class=pass>Agreed: {} witnesses in {} independent networks saw the same content.</p>",
                group.witnesses.len(),
                group.asns.len()
            ));
            if !dissenters.is_empty() {
                b.push_str(&format!(
                    "<p class=muted>{} dissenting witnesses.</p>",
                    dissenters.len()
                ));
            }
        }
        Verdict::Split { groups } => {
            b.push_str("<p class=silent>Split: independent witnesses saw different content at the same time, so the server treats visitors differently. Often harmless (localization, an A/B test, a rollout in progress, bot blocking); compare the versions before concluding it is cloaking.</p>");
            b.push_str(&group_rows(groups));
        }
        Verdict::Disputed { groups, pending } => {
            b.push_str(if *pending {
                "<p class=muted>Disputed: the assigned witnesses disagree. Witnesses drawn at random from the same countries are capturing the page again; only versions they reproduce will count.</p>"
            } else {
                "<p class=muted>Disputed: the assigned witnesses disagree, and the rechecks reproduced no version clearly enough to decide.</p>"
            });
            b.push_str(&group_rows(groups));
        }
        Verdict::Insufficient { groups } => {
            b.push_str(&format!(
                "<p class=muted>Not enough independent witnesses yet ({} recent attestations).</p>",
                v.considered
            ));
            if !groups.is_empty() {
                b.push_str(&group_rows(groups));
            }
        }
    }
    b
}

async fn network_page(State(node): State<Arc<Node>>) -> WebResult<Html<String>> {
    let now = now_ms();
    let mut b = String::from("<h1>Network</h1>");
    let me = node.location_of(&node.key.public(), now)?;
    b.push_str(&format!(
        "<p>This witness: <span class=mono>{}</span> · endpoint {} · location {}</p>",
        node.key.public().short(),
        esc(node
            .config
            .network
            .endpoint
            .as_deref()
            .unwrap_or("none (push-only)")),
        me.map(|l| format!("AS{} {}", l.asn, esc(&l.country)))
            .unwrap_or_else(|| "not corroborated".into())
    ));
    let bad = node.store.equivocating_logs()?;
    let scores = node.store.reputation_scores(now)?;
    b.push_str("<div class=wrap><table><tr><th>Witness</th><th>Endpoint</th><th>Location</th><th>Audited log</th><th>Reputation</th><th>Last sync</th><th>Status</th></tr>");
    for p in node.store.peers()? {
        let loc = node.location_of(&p.key, now)?;
        let status = if bad.contains(&p.key) {
            "<span class=silent>EQUIVOCATED</span>".to_string()
        } else {
            esc(p.last_error.as_deref().unwrap_or("ok"))
        };
        b.push_str(&format!(
            "<tr><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1}</td><td>{}</td><td>{}</td></tr>",
            p.key.short(),
            esc(p.endpoint.as_deref().unwrap_or("-")),
            loc.map(|l| esc(&l.to_string())).unwrap_or_else(|| "unknown".into()),
            p.head
                .as_ref()
                .map_or("-".to_string(), |h| h.head.size.to_string()),
            scores.get(&p.key).copied().unwrap_or(0.0),
            p.last_sync.map(format_ms).unwrap_or_else(|| "never".into()),
            status
        ));
    }
    b.push_str("</table></div>");
    let requests = node.store.requests_active(now)?;
    if !requests.is_empty() {
        b.push_str("<h2>Active watch requests</h2><div class=wrap><table><tr><th>URL</th><th>Every</th><th>Until</th><th>Requester</th></tr>");
        for r in requests {
            b.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=mono>{}</td></tr>",
                esc(&r.body.url),
                humantime::format_duration(Duration::from_secs(r.body.every_secs)),
                format_ms(r.body.expires_at_ms),
                r.body.requester.short()
            ));
        }
        b.push_str("</table></div>");
    }
    let anchors = node.store.anchors()?;
    if !anchors.is_empty() {
        b.push_str("<h2>Bitcoin anchors</h2><table><tr><th>Tree size</th><th>Status</th><th>Block</th></tr>");
        for a in anchors {
            b.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                a.size,
                esc(&a.status),
                a.height.map(|h| h.to_string()).unwrap_or_default()
            ));
        }
        b.push_str("</table>");
    }
    Ok(page("Network", &b))
}

async fn alerts_page(State(node): State<Arc<Node>>) -> WebResult<Html<String>> {
    let mut b = String::from("<h1>Alerts</h1>");
    let alerts = node.store.alerts(200)?;
    if alerts.is_empty() {
        b.push_str("<p class=muted>No alerts.</p>");
    }
    b.push_str("<div class=wrap><table><tr><th>When</th><th>Kind</th><th>URL</th><th>Summary</th><th>From</th></tr>");
    for a in alerts {
        let kind = match a.body.kind {
            witness_core::net::AlertKind::Split => "split",
            witness_core::net::AlertKind::SilentEdit => "silent edit",
            witness_core::net::AlertKind::Equivocation => "equivocation",
        };
        let url = a
            .body
            .url
            .as_deref()
            .map(|u| format!("<a href='/url?u={}'>{}</a>", q(u), esc(u)))
            .unwrap_or_default();
        b.push_str(&format!(
            "<tr><td>{}</td><td class=silent>{kind}</td><td>{url}</td><td>{}</td><td class=mono>{}</td></tr>",
            format_ms(a.body.issued_at_ms),
            esc(&a.body.summary),
            a.body.issuer.short()
        ));
    }
    b.push_str("</table></div>");
    Ok(page("Alerts", &b))
}
