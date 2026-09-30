//! What one hostile client or key can make a node do. Anyone can push to a
//! witness's public API, and anyone gets into its peer table with a
//! descriptor, so CPU and storage must stay bounded and gossip must keep
//! flowing between the honest witnesses.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use keepword_core::beacon::{Beacon, round_at};
use keepword_core::net::{Alert, AlertKind, Descriptor, Gossip, PushEnvelope, WatchRequest};
use keepword_core::statement::Signed;
use keepword_core::{Keypair, now_ms};
use keepword::Node;
use keepword::config::Config;
use keepword::federation::{PushRequest, PushResponse};
use tokio::net::TcpListener;

fn new_node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.network.seeds = false;
    cfg.beacon.drand_url = None;
    Node::init(dir.path(), &cfg).unwrap();
    let node = Node::open(dir.path()).unwrap();
    (dir, node)
}

/// Push `messages` the way a peer's sync does. Returns how many were taken.
fn push(node: &Node, from: &Keypair, messages: Vec<Gossip>) -> usize {
    let envelope = Signed::sign(
        PushEnvelope {
            from: from.public(),
            to: node.key.public(),
            sent_at_ms: now_ms(),
            payload: keepword_core::net::payload_digest(&messages),
        },
        from,
    )
    .unwrap();
    node.receive_push(
        PushRequest { envelope, messages },
        "198.51.100.7".parse().unwrap(),
    )
    .unwrap()
    .accepted
}

fn descriptor(k: &Keypair, endpoint: &str) -> Signed<Descriptor> {
    Signed::sign(
        Descriptor {
            key: k.public(),
            endpoint: Some(endpoint.into()),
            vantage: Default::default(),
            issued_at_ms: now_ms(),
            software: "test".into(),
        },
        k,
    )
    .unwrap()
}

/// Beacons are accepted from anyone, since they verify on their own. Each
/// check is a BLS pairing (milliseconds), so garbage must be turned away
/// before it is checked, or one client keeps every core busy.
#[test]
fn garbage_beacons_cost_little() {
    let (_d, node) = new_node();
    let stranger = Keypair::generate().unwrap();
    let first = round_at(now_ms() - 3_600_000);
    let junk: Vec<Gossip> = (0..1000)
        .map(|i| {
            Gossip::Beacon(Beacon {
                round: first + i,
                signature: vec![7; 48],
            })
        })
        .collect();
    // What one check costs on this machine.
    let t = Instant::now();
    for i in 0..5 {
        let b = Beacon {
            round: first + i,
            signature: vec![7; 48],
        };
        assert!(b.verify().is_err());
    }
    let one = t.elapsed() / 5;
    let t = Instant::now();
    assert_eq!(push(&node, &stranger, junk), 0);
    assert!(
        t.elapsed() < one * 100,
        "1000 garbage beacons took {:?}, {one:?} per check",
        t.elapsed()
    );
}

/// Keys are free, and any key gets into the peer table with a descriptor.
/// What one of them can make every node store must be bounded.
#[test]
fn one_key_cannot_fill_the_disk() {
    let (_d, node) = new_node();
    let k = Keypair::generate().unwrap();
    assert_eq!(
        push(
            &node,
            &k,
            vec![Gossip::Descriptor(descriptor(&k, "https://k.example"))]
        ),
        1
    );
    let alert = |n: usize, at: i64| {
        Gossip::Alert(
            Signed::sign(
                Alert {
                    kind: AlertKind::SilentEdit,
                    url: Some(format!("https://victim.example/{n}")),
                    summary: "noise".into(),
                    evidence: vec![],
                    issued_at_ms: at,
                    issuer: k.public(),
                },
                &k,
            )
            .unwrap(),
        )
    };
    let mut stored = 0;
    for batch in 0..3 {
        let alerts = (0..1000)
            .map(|i| alert(batch * 1000 + i, now_ms()))
            .collect();
        stored += push(&node, &k, alerts);
    }
    assert!(
        stored <= 200,
        "one key made this node store {stored} alerts in one go"
    );
    // Alerts are kept until they are old; one dated far ahead never is.
    let (_d2, fresh) = new_node();
    push(
        &fresh,
        &k,
        vec![Gossip::Descriptor(descriptor(&k, "https://k.example"))],
    );
    let late = alert(0, now_ms() + 365 * 86_400_000);
    assert_eq!(push(&fresh, &k, vec![late]), 0, "an alert from next year");
}

/// Subtracting the times of a request must not wrap around: in release
/// builds a request "issued" 146 million years ago and expiring as long
/// after would otherwise pass for a short one and never expire.
#[test]
fn request_times_cannot_overflow() {
    let (_d, node) = new_node();
    let r = Signed::sign(
        WatchRequest {
            url: "https://example.org/".into(),
            every_secs: 600,
            render: false,
            requester: node.key.public(),
            issued_at_ms: -(1 << 62),
            expires_at_ms: (1 << 62) + 1,
        },
        &node.key,
    )
    .unwrap();
    assert!(!node.ingest(Gossip::Request(r)).unwrap());
}

struct TestNode {
    node: Arc<Node>,
    endpoint: String,
    _dir: tempfile::TempDir,
}

async fn spawn(asn: u32, peers: Vec<String>) -> TestNode {
    spawn_with(asn, peers, |_| {}).await
}

async fn spawn_with(asn: u32, peers: Vec<String>, tweak: impl FnOnce(&mut Config)) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut cfg = Config::default();
    cfg.network.allow_private_peers = true;
    cfg.vantage.asn = Some(asn);
    cfg.vantage.country = Some("DE".into());
    cfg.network.endpoint = Some(endpoint.clone());
    cfg.network.peers = peers;
    cfg.network.seeds = false;
    cfg.beacon.drand_url = None;
    cfg.beacon.allow_insecure_seed = true;
    cfg.quorum.trust_self_reported = true;
    cfg.anchor.calendars = vec![];
    tweak(&mut cfg);
    Node::init(dir.path(), &cfg).unwrap();
    let node = Arc::new(Node::open(dir.path()).unwrap());
    let app = keepword::api::router(node.clone());
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

/// Keys that announce endpoints nobody answers on must not crowd the
/// witnesses that do answer out of a node's gossip rounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_peers_dont_starve_gossip() {
    let a = spawn(64901, vec![]).await;
    let boot = vec![a.endpoint.clone()];
    let b = spawn(64902, boot.clone()).await;
    let c = spawn(64903, boot).await;
    let nodes = [a, b, c];
    for _ in 0..2 {
        for n in &nodes {
            n.node.sync().await.unwrap();
        }
    }
    let a = &nodes[0].node;
    assert_eq!(a.store.peers().unwrap().len(), 2);
    for i in 0..200 {
        let k = Keypair::generate().unwrap();
        let d = descriptor(&k, &format!("http://127.0.0.1:1/{i}"));
        a.ingest(Gossip::Descriptor(d)).unwrap();
    }
    let round = now_ms();
    a.sync().await.unwrap();
    for n in &nodes[1..] {
        let p = a.store.peer(&n.node.key.public()).unwrap().unwrap();
        assert!(
            p.last_sync.is_some_and(|t| t >= round) && p.last_error.is_none(),
            "a live peer was left out of the round"
        );
    }
}

/// Where a peer connects from places it in a network. Behind Cloudflare
/// and a reverse proxy, connections come from the proxy, and the address it
/// saw and adds to X-Forwarded-For is Cloudflare's: the node must take the
/// client address the proxy worked out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peers_behind_a_cdn_are_placed_where_they_are() {
    // The test connects from 127.0.0.1, like a proxy on the same machine.
    let seed = spawn_with(64901, vec![], |c| {
        c.network.trust_forwarded_for = true;
        c.network.client_ip_header = Some("X-Real-IP".into());
    })
    .await;
    let peer = Keypair::generate().unwrap();
    let http = reqwest::Client::new();
    let mut sent = 0;
    let mut push = async |headers: &[(&str, &str)]| {
        sent += 1;
        let envelope = Signed::sign(
            PushEnvelope {
                from: peer.public(),
                to: seed.node.key.public(),
                sent_at_ms: now_ms() + sent,
                payload: keepword_core::net::payload_digest(&[]),
            },
            &peer,
        )
        .unwrap();
        let body = serde_json::to_vec(&PushRequest {
            envelope,
            messages: vec![],
        })
        .unwrap();
        let mut req = http
            .post(format!("{}/v1/gossip", seed.endpoint))
            .header("content-type", "application/json")
            .body(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().await.unwrap().error_for_status().unwrap();
        let resp: PushResponse = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
        resp.observation.unwrap().body.ip.to_string()
    };
    // What Caddy sends with `trusted_proxies cloudflare`, `client_ip_headers
    // CF-Connecting-IP` and `header_up X-Real-IP {client_ip}`.
    let caddy = [
        ("x-forwarded-for", "9.9.9.9, 81.2.69.160, 172.70.4.1"),
        ("x-real-ip", "81.2.69.160"),
        ("cf-connecting-ip", "81.2.69.160"),
    ];
    assert_eq!(push(&caddy).await, "81.2.69.160");
    // Without the header, only the proxy's own address, which places
    // nobody; never the CDN's.
    assert_eq!(push(&caddy[..1]).await, "127.0.0.1");
    let stored = seed
        .node
        .store
        .observation(&peer.public(), &seed.node.key.public())
        .unwrap()
        .unwrap();
    assert_eq!(stored.body.ip.to_string(), "127.0.0.1");
}
