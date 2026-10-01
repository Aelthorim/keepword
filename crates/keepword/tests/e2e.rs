//! End-to-end: a real HTTP server, a real node on disk, the whole pipeline.

use std::sync::{Arc, Mutex};

use keepword::Node;
use keepword::config::Config;
use keepword_core::bundle::{Bundle, Content, Status};
use keepword_core::now_ms;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAGE: &str = r#"<!doctype html><html><head><title>Policy</title>
<script>window.csrf="TOKEN";</script></head><body>
<main>
  <h1>Privacy policy</h1>
  <p class="meta">Last viewed <time>5 minutes ago</time></p>
  <div class="ad">Buy things</div>
  <p>We never sell your data.</p>
  <p>Contact: privacy@example.com</p>
</main></body></html>"#;

/// Minimal HTTP/1.1 server whose page body can be swapped between requests.
async fn serve(body: Arc<Mutex<String>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                }
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let resp = if path == "/old" {
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: /page\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else if path == "/page" {
                    let b = body.lock().unwrap().clone();
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        b.len(),
                        b
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

fn node(dir: &std::path::Path, allow_private: bool) -> Node {
    let mut cfg = Config::default();
    cfg.capture.allow_private_addresses = allow_private;
    cfg.vantage.asn = Some(64496);
    cfg.vantage.country = Some("DE".into());
    cfg.beacon.drand_url = None;
    Node::init(dir, &cfg).unwrap();
    Node::open(dir).unwrap()
}

#[tokio::test]
async fn capture_detect_verify_purge() {
    let body = Arc::new(Mutex::new(PAGE.to_string()));
    let base = serve(body.clone()).await;
    let url = format!("{base}/page");
    let tmp = tempfile::tempdir().unwrap();
    let node = node(tmp.path(), true);

    // First capture.
    let first = node.capture(&url, false).await.unwrap();
    assert!(first.previous.is_none());
    let a = &first.record.signed.attestation;
    assert_eq!(a.status, 200);
    assert_eq!(a.vantage.asn, Some(64496));
    assert!(a.server_ip.unwrap().is_loopback());

    // Noise only: new CSRF token, relative time, different ad.
    *body.lock().unwrap() = PAGE
        .replace("TOKEN", "OTHER")
        .replace("5 minutes", "9 minutes")
        .replace("Buy things", "Sale!");
    let second = node.capture(&url, false).await.unwrap();
    assert_eq!(second.previous, Some(first.record.id));
    assert!(second.change.is_none(), "noise was reported as a change");
    assert_ne!(
        second.record.signed.attestation.body_hash,
        first.record.signed.attestation.body_hash
    );

    // A silent edit.
    *body.lock().unwrap() = PAGE.replace("never sell", "may share");
    let third = node.capture(&url, false).await.unwrap();
    let change = third.change.as_ref().expect("edit detected");
    assert!(change.silent);
    let d = change.diff.as_ref().unwrap();
    assert!(d.unified.contains("-p: We never sell your data."));
    assert!(d.unified.contains("+p: We may share your data."));

    // A disclosed edit.
    *body.lock().unwrap() = PAGE.replace(
        "<p>We never sell your data.</p>",
        "<p>We may share your data.</p><p>Updated: we changed section 2.</p>",
    );
    let fourth = node.capture(&url, false).await.unwrap();
    assert!(!fourth.change.as_ref().unwrap().silent);

    // History and the change table agree.
    let changes = node.store.changes(Some(&url), 10).unwrap();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes.iter().filter(|c| c.silent).count(), 1);

    // Bundle for the silent-edit capture verifies fully, including
    // re-running normalization, and survives a JSON round trip.
    let bundle = node.bundle(&third.record, true).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let bundle: Bundle = serde_json::from_str(&json).unwrap();
    let report = Node::verify_bundle(&bundle);
    assert!(report.ok(), "{report:?}");
    for name in [
        "signature",
        "tree head",
        "log inclusion",
        "headers",
        "body",
        "normalized",
        "renormalize",
    ] {
        let c = report.checks.iter().find(|c| c.name == name).unwrap();
        assert_eq!(c.status, Status::Pass, "{name}: {}", c.detail);
    }

    // Tampering with the body is caught.
    let mut forged = bundle.clone();
    let content = forged.content.as_mut().unwrap();
    content.body_b64 = Some(Content::encode(PAGE.as_bytes()));
    assert!(!Node::verify_bundle(&forged).ok());

    // So is claiming a different fetch time.
    let mut forged = bundle.clone();
    forged.attestation.attestation.fetched_at_ms -= 86_400_000;
    assert!(!Node::verify_bundle(&forged).ok());

    // A bundle without content still proves the hashes.
    let bare = node.bundle(&third.record, false).unwrap();
    assert!(Node::verify_bundle(&bare).ok());

    // Resolve by URL at a time and by ID prefix.
    let at = node
        .resolve(&url, Some(third.record.signed.attestation.fetched_at_ms))
        .unwrap();
    assert!(at.leaf_index >= third.record.leaf_index);
    let by_prefix = node.resolve(&third.record.id.to_hex()[..10], None).unwrap();
    assert_eq!(by_prefix.id, third.record.id);

    // WARC export.
    let a = &third.record.signed.attestation;
    let h = node.store.blobs.get(&a.headers_hash).unwrap().unwrap();
    let b = node.store.blobs.get(&a.body_hash).unwrap().unwrap();
    let warc =
        String::from_utf8(keepword_capture::warc::export(&third.record.signed, &h, &b)).unwrap();
    assert!(warc.contains("WARC-Type: response"));
    assert!(warc.contains("HTTP/1.1 200 OK\r\n"));
    assert!(warc.contains("We may share your data."));

    // Redirects are followed and recorded.
    let redirected = node.capture(&format!("{base}/old"), false).await.unwrap();
    let ra = &redirected.record.signed.attestation;
    assert_eq!(ra.final_url, url);
    assert_eq!(ra.redirects, vec![format!("{base}/old")]);

    // The whole store audits clean.
    assert!(node.audit().unwrap().ok());

    // Erasure: content and records go, the log and other proofs stay valid.
    let root_before = node.store.latest_tree_head().unwrap().unwrap().head.root;
    let (blobs, rows) = node.store.purge(&url, true).unwrap();
    assert!(blobs > 0);
    assert_eq!(rows, 4);
    assert_eq!(
        node.store.latest_tree_head().unwrap().unwrap().head.root,
        root_before
    );
    assert!(node.audit().unwrap().ok());
    let still = node.bundle(&redirected.record, true).unwrap();
    assert!(Node::verify_bundle(&still).ok());
    // The earlier bundle (exported before erasure) still verifies too.
    assert!(Node::verify_bundle(&bundle).ok());
}

#[tokio::test]
async fn refuses_private_targets_by_default() {
    let body = Arc::new(Mutex::new(PAGE.to_string()));
    let base = serve(body).await;
    let tmp = tempfile::tempdir().unwrap();
    let node = node(tmp.path(), false);
    let err = node
        .capture(&format!("{base}/page"), false)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("not a public address"),
        "{err:#}"
    );
    let err = node
        .capture("http://localhost:1/", false)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("non-public"), "{err:#}");
}

/// The audit checks a store that may have been tampered with: log leaves
/// missing under a tree head are a failed check, not a crash.
#[tokio::test]
async fn audit_reports_missing_leaves() {
    let body = Arc::new(Mutex::new(PAGE.to_string()));
    let base = serve(body.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let node = node(tmp.path(), true);
    for i in 0..3 {
        *body.lock().unwrap() = PAGE.replace("never", &format!("never ({i})"));
        node.capture(&format!("{base}/page"), false).await.unwrap();
    }
    assert!(node.audit().unwrap().ok());
    rusqlite::Connection::open(tmp.path().join("index.sqlite"))
        .unwrap()
        .execute(
            "DELETE FROM log_leaves WHERE idx = (SELECT MAX(idx) FROM log_leaves)",
            [],
        )
        .unwrap();
    let r = node.audit().unwrap();
    assert!(!r.ok());
    assert!(
        r.checks
            .iter()
            .any(|c| c.name == "tree heads" && c.status == Status::Fail),
        "{r:?}"
    );
}

/// `keepword init` with a bad flag: nothing is written, so it can be run
/// again (an invalid config would stop every other command, `config` too).
#[test]
fn init_writes_no_config_it_cant_load() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let mut cfg = Config::default();
    cfg.vantage.country = Some("DEU".into());
    assert!(Node::init(&dir, &cfg).is_err());
    assert!(!dir.exists());
    cfg.vantage.country = Some("DE".into());
    Node::init(&dir, &cfg).unwrap();
    Node::open(&dir).unwrap();
}

/// `keepword request` for a URL it already requested: the old request is
/// only withdrawn for a valid new one.
#[test]
fn bad_request_replacements_keep_the_old_request() {
    let tmp = tempfile::tempdir().unwrap();
    let node = node(tmp.path(), false);
    let url = "https://example.org/terms";
    let day = 86_400_000;
    let active = || -> Vec<_> {
        node.store
            .requests_by(&node.key.public(), now_ms())
            .unwrap()
            .iter()
            .map(|r| r.id())
            .collect()
    };
    let (first, replaced) = node.replace_request(url, 600, day, false).unwrap();
    assert_eq!(replaced, 0);
    assert!(node.replace_request(url, 60, day, false).is_err());
    assert!(node.replace_request(url, 600, 0, false).is_err());
    assert!(node.replace_request(url, 600, 365 * day, false).is_err());
    assert_eq!(active(), [first.id()]);
    let (second, replaced) = node.replace_request(url, 1200, day, false).unwrap();
    assert_eq!(replaced, 1);
    assert_eq!(active(), [second.id()]);
}

/// Watch requests from the network can ask for any interval at least ten
/// minutes long. The longest ones must not make a URL due every round.
#[tokio::test]
async fn the_longest_intervals_arent_due_every_round() {
    let base = serve(Arc::new(Mutex::new(PAGE.to_string()))).await;
    let tmp = tempfile::tempdir().unwrap();
    let node = Arc::new(node(tmp.path(), true));
    let url = format!("{base}/page");
    for every_secs in [1 << 62, u64::MAX] {
        node.store
            .watch_add(&url, every_secs, false, now_ms())
            .unwrap();
        assert_eq!(keepword::web::run_due(&node, |_| {}).await.unwrap(), 1);
        assert_eq!(keepword::web::run_due(&node, |_| {}).await.unwrap(), 0);
        node.store.watch_remove(&url).unwrap();
    }
}
