//! Multi-node federation: four witnesses in four "ASNs" talking over real
//! HTTP on localhost.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use witness_core::TreeHead;
use witness_core::bundle::Status;
use witness_core::net::{AlertKind, Gossip};
use witness_core::quorum::Verdict;
use witness_node::Node;
use witness_node::config::Config;

/// Serves /page/*; clients whose User-Agent contains "cloaked" get a
/// different version.
async fn content_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                }
                let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let cloaked = req.contains("user-agent: cloaked");
                let text = if cloaked {
                    "Prices start at 99 euros."
                } else {
                    "Prices start at 49 euros."
                };
                let body =
                    format!("<html><body><main><h1>Offer</h1><p>{text}</p></main></body></html>");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

struct TestNode {
    node: Arc<Node>,
    endpoint: String,
    _dir: tempfile::TempDir,
}

async fn spawn(asn: u32, country: &str, ua: &str, peers: Vec<String>) -> TestNode {
    spawn_with(asn, country, ua, peers, |_| {}).await
}

async fn spawn_with(
    asn: u32,
    country: &str,
    ua: &str,
    peers: Vec<String>,
    tweak: impl Fn(&mut Config),
) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut cfg = Config::default();
    cfg.capture.allow_private_addresses = true;
    cfg.network.allow_private_peers = true;
    cfg.capture.user_agent = Some(ua.into());
    cfg.vantage.asn = Some(asn);
    cfg.vantage.country = Some(country.into());
    cfg.network.endpoint = Some(endpoint.clone());
    cfg.network.peers = peers;
    cfg.network.seeds = false;
    // Four witnesses in four countries: every URL is assigned to all of
    // them, so each one's captures reach every verdict.
    cfg.network.replication = 4;
    // Audit and cosign every round instead of hourly.
    cfg.network.checkpoint_interval_secs = 0;
    cfg.network.cosign_interval_secs = 0;
    cfg.beacon.drand_url = None;
    cfg.beacon.allow_insecure_seed = true;
    cfg.quorum.trust_self_reported = true;
    cfg.anchor.calendars = vec![];
    cfg.anchor.esplora_url = None;
    tweak(&mut cfg);
    Node::init(dir.path(), &cfg).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    let app = witness_node::api::router(node.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    TestNode {
        node,
        endpoint,
        _dir: dir,
    }
}

async fn sync_all(nodes: &[TestNode], rounds: usize) {
    for _ in 0..rounds {
        for n in nodes {
            let r = n.node.sync().await.unwrap();
            assert!(r.errors.is_empty(), "sync errors: {:?}", r.errors);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_witnesses() {
    let site = content_server().await;
    let a = spawn(64501, "DE", "witness-a", vec![]).await;
    let boot = vec![a.endpoint.clone()];
    let b = spawn(64502, "FR", "witness-b", boot.clone()).await;
    let c = spawn(64503, "NL", "cloaked-c", boot.clone()).await;
    let d = spawn(64504, "US", "cloaked-d", boot).await;
    let nodes = [a, b, c, d];

    // Discovery: everyone learns everyone through A.
    sync_all(&nodes, 2).await;
    for n in &nodes {
        assert_eq!(n.node.store.peers().unwrap().len(), 3, "peer count");
    }

    // A captures; its auditors (everyone, in a network this small) check
    // its checkpoint and hand it their cosignatures.
    let page = format!("{site}/page/one");
    let cap = nodes[0].node.capture(&page, false).await.unwrap();
    sync_all(&nodes, 2).await;
    let a_key = nodes[0].node.key.public();
    for n in &nodes[1..] {
        assert!(n.node.audited_logs_now().unwrap().contains(&a_key));
        let p = n.node.store.peer(&a_key).unwrap().unwrap();
        assert_eq!(p.head.unwrap().head.size, 1, "audited head");
        // Nothing is mirrored wholesale any more.
        assert_eq!(n.node.store.foreign_count().unwrap(), 0);
    }
    // A later checkpoint must extend the audited one; the auditors check
    // the consistency proof.
    nodes[0].node.capture(&page, false).await.unwrap();
    sync_all(&nodes, 1).await;
    for n in &nodes[1..] {
        let p = n.node.store.peer(&a_key).unwrap().unwrap();
        assert_eq!(p.head.unwrap().head.size, 2, "audited head after growth");
    }
    let bundle = nodes[0].node.bundle(&cap.record, false).unwrap();
    assert_eq!(bundle.inclusion.as_ref().unwrap().cosignatures.len(), 3);
    let report = Node::verify_bundle(&bundle);
    let cos = report
        .checks
        .iter()
        .find(|c| c.name == "cosignatures")
        .unwrap();
    assert_eq!(cos.status, Status::Pass, "{}", cos.detail);
    assert!(cos.detail.contains("3 other keys"));
    assert_eq!(
        report.strength(),
        Some(witness_core::bundle::Strength::Cosigned)
    );

    // Pushes produced observation receipts, and they flooded.
    let b_key = nodes[1].node.key.public();
    for n in &nodes {
        let obs = n.node.store.observations_of(&b_key, 0).unwrap();
        assert!(!obs.is_empty(), "no observation of B");
        assert!(obs.iter().all(|o| o.body.ip.is_loopback()));
    }
    // An observer doesn't re-issue an unchanged observation every round.
    let seen = |n: &TestNode| {
        n.node
            .store
            .observation(&b_key, &a_key)
            .unwrap()
            .map(|o| o.body.observed_at_ms)
    };
    let before = seen(&nodes[0]).expect("A observed B");
    sync_all(&nodes, 1).await;
    assert_eq!(seen(&nodes[0]), Some(before));

    // A watch request: all four witnesses get assigned and capture.
    let requested = format!("{site}/page/two");
    let first = nodes[0]
        .node
        .request_watch(&requested, 600, 86_400_000, false)
        .unwrap();
    sync_all(&nodes, 2).await;
    let mut assigned = 0;
    for n in &nodes {
        let w = n.node.store.watches().unwrap();
        if w.iter()
            .any(|w| w.url == requested && w.request_id.is_some())
        {
            assigned += 1;
            witness_node::web::run_due(&n.node, |_| {}).await.unwrap();
        }
    }
    assert_eq!(assigned, 4);
    sync_all(&nodes, 2).await;
    // C and D get cloaked content, so the verdict itself is a split; every
    // node must see all four captures after fetching them.
    for n in &nodes {
        n.node.refresh_url(&requested).await.unwrap();
        assert_eq!(n.node.verdict(&requested).unwrap().considered, 4);
    }

    // Replacing a request: a slower interval takes effect, which it
    // couldn't while the old request was still active.
    let request_watches =
        |every: u64| {
            nodes
                .iter()
                .filter(|n| {
                    n.node.store.watches().unwrap().iter().any(|w| {
                        w.url == requested && w.request_id.is_some() && w.every_secs == every
                    })
                })
                .count()
        };
    assert_eq!(nodes[0].node.cancel_requests(&requested).unwrap(), 1);
    nodes[0]
        .node
        .request_watch(&requested, 1200, 86_400_000, false)
        .unwrap();
    sync_all(&nodes, 2).await;
    assert_eq!(request_watches(1200), 4);
    assert_eq!(request_watches(600), 0);

    // Withdrawing it: every assigned witness stops, and the original
    // request can't be replayed.
    assert_eq!(nodes[0].node.cancel_requests(&requested).unwrap(), 1);
    assert_eq!(nodes[0].node.cancel_requests(&requested).unwrap(), 0);
    sync_all(&nodes, 2).await;
    assert_eq!(request_watches(1200), 0);
    for n in &nodes {
        n.node.store.gossip_prune(i64::MAX, i64::MAX).unwrap();
        assert!(!n.node.ingest(Gossip::Request(first.clone())).unwrap());
        assert!(
            n.node
                .store
                .requests_active(witness_core::now_ms())
                .unwrap()
                .is_empty()
        );
    }

    // Gossip from a key outside the peer table is dropped.
    let stranger = witness_core::Keypair::generate().unwrap();
    let fake = witness_core::statement::Signed::sign(
        witness_core::net::Alert {
            kind: AlertKind::Split,
            url: Some(requested.clone()),
            summary: "noise".into(),
            evidence: vec![],
            issued_at_ms: witness_core::now_ms(),
            issuer: stranger.public(),
        },
        &stranger,
    )
    .unwrap();
    assert!(!nodes[1].node.ingest(Gossip::Alert(fake)).unwrap());

    // Cloaking: everyone captures the same URL; C and D get another page.
    let cloaked = format!("{site}/page/three");
    for n in &nodes {
        n.node.capture(&cloaked, false).await.unwrap();
    }
    for n in &nodes {
        n.node.refresh_url(&cloaked).await.unwrap();
    }
    sync_all(&nodes, 2).await;
    for n in &nodes {
        let v = n.node.verdict(&cloaked).unwrap();
        match &v.evaluation.verdict {
            Verdict::Split { groups } => assert_eq!(groups.len(), 2),
            other => panic!("expected a split verdict, got {other:?}"),
        }
        let alerts = n.node.store.alerts(50).unwrap();
        assert!(
            alerts.iter().any(|a| a.body.kind == AlertKind::Split && a.body.url.as_deref() == Some(&cloaked)),
            "split alert did not reach every node"
        );
    }

    // Two networks agreeing is not yet a quorum (min_asns = 3).
    let honest = format!("{site}/page/four");
    for n in &nodes[..2] {
        n.node.capture(&honest, false).await.unwrap();
    }
    sync_all(&nodes, 1).await;
    nodes[2].node.refresh_url(&honest).await.unwrap();
    let v = nodes[2].node.verdict(&honest).unwrap();
    assert!(
        matches!(v.evaluation.verdict, Verdict::Insufficient { .. }),
        "two ASNs are not a quorum"
    );

    // Reputation never went negative: nobody dissented from an agreement.
    let scores = nodes[0]
        .node
        .store
        .reputation_scores(witness_core::now_ms())
        .unwrap();
    assert!(scores.values().all(|s| *s >= 0.0));

    // Equivocation: B signs a second, different log of the same size.
    let b_node = &nodes[1].node;
    b_node.capture(&page, false).await.unwrap();
    sync_all(&nodes, 1).await;
    let real = b_node.store.latest_tree_head().unwrap().unwrap();
    let forged = TreeHead {
        root: witness_core::Digest::of(b"a different history"),
        ..real.head.clone()
    }
    .sign(&b_node.key)
    .unwrap();
    assert!(nodes[0].node.ingest(Gossip::TreeHead(forged)).unwrap());
    assert!(
        nodes[0]
            .node
            .store
            .equivocating_logs()
            .unwrap()
            .contains(&b_key)
    );
    sync_all(&nodes[..1], 1).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    sync_all(&nodes[2..], 1).await;
    for n in &nodes[2..] {
        assert!(
            n.node.store.equivocating_logs().unwrap().contains(&b_key),
            "equivocation proof did not propagate"
        );
    }
    // A stops trusting B for assignment.
    let cands = nodes[0].node.candidates(witness_core::now_ms()).unwrap();
    assert!(!cands.iter().any(|c| c.key == b_key));
}

/// Larger networks: each round talks to a random sample of peers, and each
/// log is audited by only `audit_logs` of them. Gossip still reaches
/// everyone, and every log still collects its auditors' cosignatures.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sampled_gossip_and_audits() {
    let site = content_server().await;
    let tweak = |c: &mut Config| {
        c.network.gossip_fanout = 1;
        c.network.audit_logs = 2;
    };
    let first = spawn_with(64510, "DE", "w0", vec![], tweak).await;
    let boot = vec![first.endpoint.clone()];
    let mut nodes = vec![first];
    for i in 1..6u32 {
        nodes.push(spawn_with(64510 + i, "DE", &format!("w{i}"), boot.clone(), tweak).await);
    }
    let page = format!("{site}/page/sampled");
    for n in &nodes {
        n.node.capture(&page, false).await.unwrap();
    }
    // Everyone first learns of everyone (the full peer list comes on first
    // contact), then audits run whatever the sample.
    sync_all(&nodes, 3).await;
    for n in &nodes {
        assert_eq!(n.node.store.peers().unwrap().len(), 5, "peer count");
    }
    for n in &nodes {
        let log = n.node.key.public();
        let auditors: Vec<_> = nodes
            .iter()
            .filter(|m| m.node.audited_logs_now().unwrap().contains(&log))
            .collect();
        assert_eq!(auditors.len(), 2, "auditors per log");
        let head = n.node.store.latest_tree_head().unwrap().unwrap();
        let cosigs = n.node.store.cosigs_for(&head).unwrap();
        // Early on, before views converge, a few others audit it too.
        assert!(cosigs.len() >= 2, "cosignatures delivered to the log");
        for a in auditors {
            assert!(
                cosigs
                    .iter()
                    .any(|c| c.body.cosigner == a.node.key.public())
            );
        }
    }
}
