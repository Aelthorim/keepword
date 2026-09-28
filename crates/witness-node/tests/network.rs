//! Multi-node federation: four witnesses in four "ASNs" talking over real
//! HTTP on localhost.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use witness_core::TreeHead;
use witness_core::bundle::Status;
use witness_core::net::{AlertKind, Gossip};
use witness_core::quorum::Verdict;
use witness_node::Node;
use witness_node::config::Config;

/// Set once the publisher has edited "/edited" pages.
static EDITED: AtomicBool = AtomicBool::new(false);
/// Set once the publisher has edited the German version of "/split-edited"
/// pages; the French version stays the same.
static SPLIT_EDITED: AtomicBool = AtomicBool::new(false);

/// Serves pages; clients whose User-Agent contains "cloaked" get a
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
                // Also: "/regional" pages differ for witnesses in France
                // (user agents with "-fr"), "/lie" pages for "liar".
                let cloaked = req.contains("user-agent: cloaked")
                    || (req.starts_with("get /regional") && req.contains("-fr"))
                    || (req.starts_with("get /split-edited") && req.contains("-fr"))
                    || (req.starts_with("get /lie") && req.contains("user-agent: liar"));
                let edited = (req.starts_with("get /edited") && EDITED.load(Ordering::SeqCst))
                    || (req.starts_with("get /split-edited")
                        && SPLIT_EDITED.load(Ordering::SeqCst));
                let text = if cloaked {
                    "Prices start at 99 euros."
                } else if edited {
                    "Prices start at 59 euros."
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

    // Pushes produced observation receipts: every node keeps its own of B,
    // and B keeps the ones about it. They no longer flood.
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
    // Every witness is assigned, so nobody is left to recheck it: the
    // disagreement stays disputed and raises no alert.
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
            Verdict::Disputed { groups, pending } => {
                assert_eq!(groups.len(), 2);
                assert!(!pending, "no rechecker exists, so nothing is pending");
            }
            other => panic!("expected a disputed verdict, got {other:?}"),
        }
        let alerts = n.node.store.alerts(50).unwrap();
        assert!(
            !alerts.iter().any(|a| a.body.kind == AlertKind::Split),
            "an unconfirmed disagreement raised a split alert"
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

    // A fork of another size: D also signed a bigger head, of a history its
    // auditors never saw. C, which audits D, asks D to prove it consistent
    // with the head C verified itself; D can't, and C stops trusting it.
    let d_node = &nodes[3].node;
    let d_key = d_node.key.public();
    let real = d_node.store.latest_tree_head().unwrap().unwrap();
    let other = TreeHead {
        size: real.head.size + 1000,
        root: witness_core::Digest::of(b"another history"),
        ..real.head.clone()
    }
    .sign(&d_node.key)
    .unwrap();
    assert!(nodes[2].node.ingest(Gossip::TreeHead(other)).unwrap());
    let r = nodes[2].node.sync().await.unwrap();
    assert!(
        r.errors.iter().any(|(_, e)| e.contains("not consistent")),
        "fork not detected: {:?}",
        r.errors
    );
    assert!(
        nodes[2]
            .node
            .store
            .equivocating_logs()
            .unwrap()
            .contains(&d_key)
    );
    // Only C verified it so far; the others check for themselves.
    assert!(
        !nodes[0]
            .node
            .store
            .equivocating_logs()
            .unwrap()
            .contains(&d_key)
    );
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

/// Rechecks: when the assigned witnesses disagree, witnesses drawn at random
/// from the same countries capture the page again, and only versions they
/// reproduce count. A lone dissenter is overruled; a real regional
/// difference is confirmed, and alerted once it repeats.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rechecks_settle_disputes() {
    let site = content_server().await;
    let tweak = |c: &mut Config| {
        c.network.replication = 3;
        c.network.max_per_country = 2;
        c.quorum.window_secs = 2;
        c.quorum.recheck_secs = 120;
        c.quorum.recheck_size = 3;
        c.quorum.recheck_quorum = 2;
        c.quorum.split_confirmations = 2;
        c.quorum.split_rounds = 3;
    };
    // Six witnesses in Germany (the first one sees "/lie" pages its own
    // way) and six in France: enough in each country that some are left to
    // recheck after assignment (of this epoch and the last) takes its share.
    let first = spawn_with(64600, "DE", "liar-0", vec![], tweak).await;
    let boot = vec![first.endpoint.clone()];
    let mut nodes = vec![first];
    for i in 1..12u32 {
        let (country, ua) = if i < 6 {
            ("DE", format!("w-de-{i}"))
        } else {
            ("FR", format!("w-fr-{i}"))
        };
        nodes.push(spawn_with(64600 + i, country, &ua, boot.clone(), tweak).await);
    }
    sync_all(&nodes, 3).await;
    for n in &nodes {
        assert_eq!(n.node.store.peers().unwrap().len(), 11, "peer count");
    }
    let now = witness_core::now_ms();
    let (seed, _) = nodes[1]
        .node
        .epoch_seed_cached(witness_core::beacon::epoch_of(now))
        .unwrap();
    let assigned = |url: &str| -> Vec<usize> {
        let u = witness_core::target::canonical_url(url).unwrap();
        let keys: Vec<_> = nodes[1]
            .node
            .assigned(&seed, &u, now)
            .unwrap()
            .into_iter()
            .map(|c| c.key)
            .collect();
        (0..nodes.len())
            .filter(|i| keys.contains(&nodes[*i].node.key.public()))
            .collect()
    };
    // One round: the assigned witnesses capture, everyone fetches, the
    // disagreement is noticed, rechecks are asked for and made, fetched,
    // and settled.
    let round = |url: String, who: Vec<usize>, first: bool| {
        let nodes = &nodes;
        async move {
            for i in &who {
                nodes[*i].node.capture(&url, false).await.unwrap();
            }
            for n in nodes {
                n.node.refresh_url(&url).await.unwrap();
            }
            // Until a draw settles it; later rounds show the versions
            // the recent draws confirmed.
            if first {
                let v = nodes[1].node.verdict(&url).unwrap();
                assert!(
                    matches!(
                        v.evaluation.verdict,
                        Verdict::Disputed { pending: true, .. }
                    ),
                    "before rechecks: {:?}",
                    v.evaluation.verdict
                );
            }
            sync_all(nodes, 2).await;
            for n in nodes {
                n.node.refresh_url(&url).await.unwrap();
            }
            sync_all(nodes, 1).await;
        }
    };

    // A lone dissenter: the rechecks don't reproduce what it reports.
    let lie = (0..500)
        .map(|i| format!("{site}/lie/{i}"))
        .find(|u| assigned(u).contains(&0))
        .expect("a URL assigned to the dissenter");
    round(lie.clone(), assigned(&lie), true).await;
    let liar = nodes[0].node.key.public();
    for n in &nodes[1..] {
        let v = n.node.verdict(&lie).unwrap();
        assert!(v.rechecks >= 2, "rechecks counted: {}", v.rechecks);
        match &v.evaluation.verdict {
            Verdict::Agreed { group, dissenters } => {
                assert!(group.asns.len() >= 3);
                assert_eq!(dissenters, &vec![liar]);
            }
            other => panic!("expected the dissent overruled, got {other:?}"),
        }
        assert!(
            !n.node
                .store
                .alerts(50)
                .unwrap()
                .iter()
                .any(|a| a.body.kind == AlertKind::Split)
        );
    }
    // The dissenter's network is charged with a failed claim.
    let charged = nodes[1]
        .node
        .store
        .failed_claims("127.0.0.0/24", 0)
        .unwrap();
    assert_eq!(charged, 1, "one failed claim for one round");

    // A real regional difference: witnesses in France see another page,
    // and so do the French witnesses drawn to recheck it.
    let regional = format!("{site}/regional/offer");
    let who = assigned(&regional);
    round(regional.clone(), who.clone(), true).await;
    let split_alert =
        |n: &TestNode| {
            n.node.store.alerts(50).unwrap().iter().any(|a| {
                a.body.kind == AlertKind::Split && a.body.url.as_deref() == Some(&regional)
            })
        };
    for n in &nodes {
        let v = n.node.verdict(&regional).unwrap();
        match &v.evaluation.verdict {
            Verdict::Split { groups } => assert_eq!(groups.len(), 2),
            other => panic!("expected a confirmed split, got {other:?}"),
        }
        assert!(!split_alert(n), "one round is not enough for an alert");
    }
    // The same again in the next round: now it is alerted.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    round(regional.clone(), who, false).await;
    sync_all(&nodes, 1).await;
    assert!(
        nodes.iter().all(split_alert),
        "a repeated, confirmed split raises an alert everywhere"
    );
}

/// Pages change. A witness that captured a page just before its publisher
/// edited it saw a real version, and rechecks made after the edit can't
/// reproduce it. Neither that, nor a recheck draw of an earlier round
/// judged against a later one, may count against honest witnesses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edits_are_not_failed_claims() {
    let site = content_server().await;
    let tweak = |c: &mut Config| {
        c.network.replication = 3;
        c.network.max_per_country = 2;
        c.quorum.window_secs = 2;
        c.quorum.recheck_secs = 120;
        c.quorum.recheck_size = 3;
        c.quorum.recheck_quorum = 2;
    };
    let first = spawn_with(64800, "DE", "w-de-0", vec![], tweak).await;
    let boot = vec![first.endpoint.clone()];
    let mut nodes = vec![first];
    for i in 1..12u32 {
        let (country, ua) = if i < 6 {
            ("DE", format!("w-de-{i}"))
        } else {
            ("FR", format!("w-fr-{i}"))
        };
        nodes.push(spawn_with(64800 + i, country, &ua, boot.clone(), tweak).await);
    }
    sync_all(&nodes, 3).await;
    let now = witness_core::now_ms();
    let (seed, _) = nodes[1]
        .node
        .epoch_seed_cached(witness_core::beacon::epoch_of(now))
        .unwrap();
    let assigned = |url: &str| -> Vec<usize> {
        let u = witness_core::target::canonical_url(url).unwrap();
        let keys: Vec<_> = nodes[1]
            .node
            .assigned(&seed, &u, now)
            .unwrap()
            .into_iter()
            .map(|c| c.key)
            .collect();
        (0..nodes.len())
            .filter(|i| keys.contains(&nodes[*i].node.key.public()))
            .collect()
    };
    let refresh = |url: String| {
        let nodes = &nodes;
        async move {
            for n in nodes {
                n.node.refresh_url(&url).await.unwrap();
            }
        }
    };
    let charged = || {
        nodes
            .iter()
            .map(|n| n.node.store.failed_claims("127.0.0.0/24", 0).unwrap())
            .max()
            .unwrap()
    };

    // An edit in the middle of a round: the first witness captured the old
    // version, the others the new one, and so do the rechecks.
    let url = format!("{site}/edited/offer");
    let who = assigned(&url);
    for i in &who {
        nodes[*i].node.capture(&url, false).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(2100)).await;
    nodes[who[0]].node.capture(&url, false).await.unwrap();
    EDITED.store(true, Ordering::SeqCst);
    for i in &who[1..] {
        nodes[*i].node.capture(&url, false).await.unwrap();
    }
    refresh(url.clone()).await;
    sync_all(&nodes, 2).await;
    refresh(url.clone()).await;
    sync_all(&nodes, 1).await;
    let v = nodes[1].node.verdict(&url).unwrap();
    assert!(v.rechecks >= 2, "rechecks counted: {}", v.rechecks);
    assert!(
        matches!(v.evaluation.verdict, Verdict::Agreed { .. }),
        "the edited version is confirmed: {:?}",
        v.evaluation.verdict
    );
    assert_eq!(
        nodes[1].node.store.round_outcomes(&url, 4).unwrap(),
        vec!["agreed".to_string()],
        "the draw was settled"
    );
    assert_eq!(
        charged(),
        0,
        "an honest capture from before the edit was charged"
    );

    // A regional difference whose German version is then edited. The
    // draw of the first round must be judged by the versions of that
    // round, not by the next round's.
    let url = (0..500)
        .map(|i| format!("{site}/split-edited/{i}"))
        .find(|u| {
            let w = assigned(u);
            w.iter().any(|i| *i < 6) && w.iter().any(|i| *i >= 6)
        })
        .expect("a URL assigned in both countries");
    let before = charged();
    let who = assigned(&url);
    for i in &who {
        nodes[*i].node.capture(&url, false).await.unwrap();
    }
    refresh(url.clone()).await;
    // The disagreement is noticed and the rechecks are made, but not yet
    // fetched by anyone.
    sync_all(&nodes, 2).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    SPLIT_EDITED.store(true, Ordering::SeqCst);
    for i in &who {
        nodes[*i].node.capture(&url, false).await.unwrap();
    }
    refresh(url.clone()).await;
    sync_all(&nodes, 1).await;
    assert_eq!(
        charged(),
        before,
        "witnesses charged for the current version by the draw of an earlier round"
    );
    // The first round's draw was settled everywhere, by that round's
    // versions and the captures made for it: it reproduced both. (A
    // witness drawn for both rounds captured the edited page for the
    // second; that capture must not count for the first.)
    for n in &nodes {
        assert!(
            n.node
                .store
                .round_outcomes(&url, 4)
                .unwrap()
                .contains(&"split".to_string()),
            "the first round's draw was judged by its own versions and captures"
        );
    }
}

/// Rechecks cost the drawn witnesses a capture each. A witness assigned to
/// a URL (any key can find URLs it is assigned to) must not be able to make
/// them capture a round nobody disputed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rechecks_need_a_real_dispute() {
    let site = content_server().await;
    let tweak = |c: &mut Config| {
        c.network.replication = 3;
        c.network.max_per_country = 2;
        c.quorum.window_secs = 2;
        c.quorum.recheck_secs = 120;
        c.quorum.recheck_size = 3;
        c.quorum.recheck_quorum = 2;
    };
    // Eight witnesses in Germany: at most two are assigned per epoch, so
    // several are left to draw rechecks from.
    let first = spawn_with(64700, "DE", "w-de-0", vec![], tweak).await;
    let boot = vec![first.endpoint.clone()];
    let mut nodes = vec![first];
    for i in 1..8u32 {
        nodes.push(spawn_with(64700 + i, "DE", &format!("w-de-{i}"), boot.clone(), tweak).await);
    }
    sync_all(&nodes, 3).await;
    let now = witness_core::now_ms();
    let (seed, _) = nodes[1]
        .node
        .epoch_seed_cached(witness_core::beacon::epoch_of(now))
        .unwrap();
    let requester = &nodes[0].node;
    // A URL nobody requested and nobody captured, assigned to the requester.
    let url = (0..500)
        .map(|i| format!("{site}/quiet/{i}"))
        .find(|u| {
            let u = witness_core::target::canonical_url(u).unwrap();
            requester
                .assigned(&seed, &u, now)
                .unwrap()
                .iter()
                .any(|c| c.key == requester.key.public())
        })
        .expect("a URL assigned to the requester");
    let r = witness_core::statement::Signed::sign(
        witness_core::net::RecheckRequest {
            url: url.clone(),
            window_end_ms: now,
            countries: vec!["DE".into()],
            requester: requester.key.public(),
            issued_at_ms: now,
        },
        &requester.key,
    )
    .unwrap();
    assert!(requester.ingest(Gossip::Recheck(r)).unwrap());
    sync_all(&nodes, 3).await;
    let captured = nodes
        .iter()
        .filter(|n| !n.node.store.history(&url).unwrap().is_empty())
        .count();
    assert_eq!(captured, 0, "witnesses rechecked a round nobody disputed");
}

/// A log that forked into a bigger history can sign any number of honest
/// heads of the history both forks share. Gossiping those first must not
/// keep its auditors from reaching the head of the other fork.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forks_are_found_behind_a_flood_of_old_heads() {
    let site = content_server().await;
    let a = spawn(64501, "DE", "witness-a", vec![]).await;
    let d = spawn(64504, "US", "witness-d", vec![a.endpoint.clone()]).await;
    let nodes = [a, d];
    sync_all(&nodes, 2).await;
    for i in 0..12 {
        nodes[1]
            .node
            .capture(&format!("{site}/page/{i}"), false)
            .await
            .unwrap();
    }
    // A audits D and verifies its head of size 12.
    sync_all(&nodes, 1).await;
    let d_node = &nodes[1].node;
    let d_key = d_node.key.public();
    let real = d_node.store.latest_tree_head().unwrap().unwrap();
    assert_eq!(real.head.size, 12);
    // Heads of the shared history, each consistent with everything.
    for size in 1..=10u64 {
        let root = d_node
            .store
            .with_merkle(|m| m.root(size as usize))
            .unwrap()
            .unwrap();
        let h = TreeHead {
            size,
            root,
            ..real.head.clone()
        }
        .sign(&d_node.key)
        .unwrap();
        assert!(nodes[0].node.ingest(Gossip::TreeHead(h)).unwrap());
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Then the head another group of auditors saw.
    let other = TreeHead {
        size: real.head.size + 1000,
        root: witness_core::Digest::of(b"another history"),
        ..real.head.clone()
    }
    .sign(&d_node.key)
    .unwrap();
    assert!(nodes[0].node.ingest(Gossip::TreeHead(other)).unwrap());
    let r = nodes[0].node.sync().await.unwrap();
    assert!(
        r.errors.iter().any(|(_, e)| e.contains("not consistent")),
        "fork not found in the first audit after it arrived: {:?}",
        r.errors
    );
    assert!(
        nodes[0]
            .node
            .store
            .equivocating_logs()
            .unwrap()
            .contains(&d_key)
    );
}
