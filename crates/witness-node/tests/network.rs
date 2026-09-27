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
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut cfg = Config::default();
    cfg.capture.allow_private_addresses = true;
    cfg.capture.user_agent = Some(ua.into());
    cfg.vantage.asn = Some(asn);
    cfg.vantage.country = Some(country.into());
    cfg.network.endpoint = Some(endpoint.clone());
    cfg.network.peers = peers;
    cfg.network.replication = 3;
    cfg.beacon.drand_url = None;
    cfg.beacon.allow_insecure_seed = true;
    cfg.quorum.trust_self_reported = true;
    cfg.anchor.calendars = vec![];
    cfg.anchor.esplora_url = None;
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

    // A captures; peers mirror its log, verify it and cosign.
    let page = format!("{site}/page/one");
    let cap = nodes[0].node.capture(&page, false).await.unwrap();
    sync_all(&nodes, 2).await;
    for n in &nodes[1..] {
        assert_eq!(n.node.store.foreign_count().unwrap(), 1);
        let ids = n
            .node
            .store
            .peer_leaf_ids(&nodes[0].node.key.public())
            .unwrap();
        assert_eq!(ids, vec![cap.record.id]);
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
    assert!(cos.detail.contains("3 other witnesses"));

    // Pushes produced observation receipts, and they flooded.
    let b_key = nodes[1].node.key.public();
    for n in &nodes {
        let obs = n.node.store.observations_of(&b_key, 0).unwrap();
        assert!(!obs.is_empty(), "no observation of B");
        assert!(obs.iter().all(|o| o.body.ip.is_loopback()));
    }

    // A watch request: exactly three witnesses get assigned, capture, and
    // the network agrees.
    let requested = format!("{site}/page/two");
    nodes[0]
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
    assert_eq!(assigned, 3);
    sync_all(&nodes, 2).await;
    // Which three were assigned depends on the epoch seed, and C and D get
    // cloaked content, so the verdict itself varies; every node must see
    // all three captures.
    for n in &nodes {
        assert_eq!(n.node.verdict(&requested).unwrap().considered, 3);
    }

    // Cloaking: everyone captures the same URL; C and D get another page.
    let cloaked = format!("{site}/page/three");
    for n in &nodes {
        n.node.capture(&cloaked, false).await.unwrap();
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
