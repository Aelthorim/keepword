//! drand beacons and Bitcoin anchoring against local mocks of drand, an
//! OpenTimestamps calendar and an Esplora block explorer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use keepword::Node;
use keepword::config::Config;
use keepword_core::beacon::Beacon;
use keepword_core::bundle::Status;
use keepword_core::ots::{self, Attestation, Op, Timestamp};
use tokio::net::TcpListener;

const SIG_123: &str = "b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92";
const HEIGHT: u64 = 800_000;
const BLOCK_HASH: &str = "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054";

#[derive(Default)]
struct Mock {
    base: Mutex<String>,
    confirmed: AtomicBool,
    /// Merkle root the "block" commits to (internal byte order).
    root: Mutex<Option<Vec<u8>>>,
    wrong_root: AtomicBool,
}

type S = State<Arc<Mock>>;

async fn drand(Path((_chain, _round)): Path<(String, String)>) -> impl IntoResponse {
    let b = Beacon {
        round: 123,
        signature: hex::decode(SIG_123).unwrap(),
    };
    Json(
        serde_json::json!({ "round": 123, "randomness": b.randomness().to_hex(), "signature": SIG_123 }),
    )
}

/// Calendar: commit to the digest via a nonce and hash, pending here.
async fn digest(State(m): S, body: Bytes) -> impl IntoResponse {
    let nonce = Op::Prepend(vec![0x5a; 16]);
    let a = nonce.apply(&body).unwrap();
    let c = Op::Sha256.apply(&a).unwrap();
    let mut leaf = Timestamp::new(c);
    leaf.attestations.push(Attestation::Pending {
        uri: m.base.lock().unwrap().clone(),
    });
    let mut mid = Timestamp::new(a);
    mid.ops.push((Op::Sha256, leaf));
    let mut root = Timestamp::new(body.to_vec());
    root.ops.push((nonce, mid));
    ots::serialize_timestamp(&root)
}

/// Upgrade: 404 until "mined", then a path to the block Merkle root.
async fn timestamp(State(m): S, Path(commitment): Path<String>) -> impl IntoResponse {
    if !m.confirmed.load(Ordering::SeqCst) {
        return (StatusCode::NOT_FOUND, Vec::new());
    }
    let c = hex::decode(commitment).unwrap();
    let step = Op::Append(vec![0x33; 32]);
    let m1 = step.apply(&c).unwrap();
    let m2 = Op::Sha256.apply(&m1).unwrap();
    let root = Op::Sha256.apply(&m2).unwrap();
    *m.root.lock().unwrap() = Some(root.clone());
    let mut top = Timestamp::new(root);
    top.attestations
        .push(Attestation::Bitcoin { height: HEIGHT });
    let mut t2 = Timestamp::new(m2);
    t2.ops.push((Op::Sha256, top));
    let mut t1 = Timestamp::new(m1);
    t1.ops.push((Op::Sha256, t2));
    let mut up = Timestamp::new(c);
    up.ops.push((step, t1));
    (StatusCode::OK, ots::serialize_timestamp(&up))
}

async fn block_height(Path(h): Path<u64>) -> impl IntoResponse {
    assert_eq!(h, HEIGHT);
    BLOCK_HASH
}

async fn block(State(m): S, Path(_hash): Path<String>) -> impl IntoResponse {
    let mut root = m.root.lock().unwrap().clone().unwrap_or_default();
    if m.wrong_root.load(Ordering::SeqCst) {
        root[0] ^= 1;
    }
    root.reverse();
    Json(serde_json::json!({ "merkle_root": hex::encode(root) }))
}

async fn page() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        "<html><body><main><p>Anchored content.</p></main></body></html>",
    )
}

async fn mock() -> (Arc<Mock>, String) {
    let m = Arc::new(Mock::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    *m.base.lock().unwrap() = base.clone();
    let app = Router::new()
        .route("/{chain}/public/{round}", get(drand))
        .route("/digest", post(digest))
        .route("/timestamp/{c}", get(timestamp))
        .route("/block-height/{h}", get(block_height))
        .route("/block/{hash}", get(block))
        .route("/page", get(page))
        .with_state(m.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (m, base)
}

#[tokio::test]
async fn beacon_and_bitcoin_anchor() {
    let (m, base) = mock().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.capture.allow_private_addresses = true;
    cfg.network.allow_private_peers = true;
    cfg.beacon.drand_url = Some(base.clone());
    cfg.anchor.calendars = vec![base.clone()];
    cfg.anchor.esplora_url = Some(base.clone());
    Node::init(dir.path(), &cfg).unwrap();
    let node = Node::open(dir.path()).unwrap();

    // The capture carries a verified beacon: a lower bound on its time.
    let out = node.capture(&format!("{base}/page"), false).await.unwrap();
    assert_eq!(
        out.record.signed.attestation.beacon.as_ref().unwrap().round,
        123
    );
    let report = Node::verify_bundle(&node.bundle(&out.record, true).unwrap());
    let nb = report
        .checks
        .iter()
        .find(|c| c.name == "not before")
        .unwrap();
    assert_eq!(nb.status, Status::Pass, "{}", nb.detail);
    assert!(report.ok());

    // Anchor: pending first.
    let a = node.anchor_submit().await.unwrap().unwrap();
    assert_eq!(a.status, "pending");
    assert!(
        node.anchor_submit().await.unwrap().is_none(),
        "same head anchored twice"
    );
    let b = node.bundle(&out.record, false).unwrap();
    let r = Node::verify_bundle(&b);
    let anchor = r.checks.iter().find(|c| c.name == "anchor").unwrap();
    assert!(anchor.detail.contains("pending"), "{}", anchor.detail);

    let up = node.anchor_upgrade().await.unwrap();
    assert_eq!((up.checked, up.upgraded, up.confirmed), (1, 0, 0));

    // The calendar's transaction confirms.
    m.confirmed.store(true, Ordering::SeqCst);
    let up = node.anchor_upgrade().await.unwrap();
    assert_eq!((up.upgraded, up.confirmed), (1, 1));
    let rows = node.store.anchors().unwrap();
    assert_eq!(rows[0].status, "confirmed");
    assert_eq!(rows[0].height, Some(HEIGHT));

    // A bundle now proves the capture existed by block 800000, checked
    // against the (mock) chain.
    let b = node.bundle(&out.record, false).unwrap();
    let mut r = Node::verify_bundle(&b);
    let anchor = r.checks.iter().find(|c| c.name == "anchor").unwrap();
    assert!(anchor.detail.contains("block 800000"), "{}", anchor.detail);
    let http = keepword::httpc::Http::new(true, false).unwrap();
    keepword::anchor::verify_anchor_online(&http, &base, &b, &mut r).await;
    let btc = r.checks.iter().find(|c| c.name == "bitcoin").unwrap();
    assert_eq!(btc.status, Status::Pass, "{}", btc.detail);
    assert!(r.ok());

    // A chain that disagrees fails the check.
    m.wrong_root.store(true, Ordering::SeqCst);
    let mut r = Node::verify_bundle(&b);
    keepword::anchor::verify_anchor_online(&http, &base, &b, &mut r).await;
    assert_eq!(
        r.checks
            .iter()
            .find(|c| c.name == "bitcoin")
            .unwrap()
            .status,
        Status::Fail
    );

    // The stored proof is a standard detached .ots for the tree-head bytes.
    let d = ots::DetachedTimestamp::from_bytes(&rows[0].ots).unwrap();
    assert_eq!(
        d.digest,
        keepword_core::bundle::anchor_digest(&rows[0].head)
    );

    // A bundle survives JSON and still verifies offline.
    let json = serde_json::to_string(&b).unwrap();
    let back: keepword_core::bundle::Bundle = serde_json::from_str(&json).unwrap();
    assert!(Node::verify_bundle(&back).ok());
}

#[tokio::test]
async fn forged_beacon_fails() {
    let (_m, base) = mock().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.capture.allow_private_addresses = true;
    cfg.network.allow_private_peers = true;
    cfg.beacon.drand_url = None;
    cfg.anchor.calendars = vec![];
    Node::init(dir.path(), &cfg).unwrap();
    let node = Node::open(dir.path()).unwrap();
    // A witness claiming a beacon it made up (round 124 with round 123's
    // signature) is caught even though it signed the attestation itself.
    let bad = Beacon {
        round: 124,
        signature: hex::decode(SIG_123).unwrap(),
    };
    let captured = keepword_capture::HttpCapturer::new(keepword_capture::HttpConfig {
        allow_private: true,
        ..Default::default()
    })
    .unwrap()
    .capture(&url::Url::parse(&format!("{base}/page")).unwrap())
    .await
    .unwrap();
    let out = node.commit(captured, Some(bad)).unwrap();
    let r = Node::verify_bundle(&node.bundle(&out.record, false).unwrap());
    assert_eq!(
        r.checks
            .iter()
            .find(|c| c.name == "not before")
            .unwrap()
            .status,
        Status::Fail
    );
    assert!(!r.ok());
}
