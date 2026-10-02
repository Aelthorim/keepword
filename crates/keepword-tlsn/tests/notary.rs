//! A full MPC-TLS notarization between two witnesses, against TLSNotary's
//! test server, and sessions where a witness refuses or goes quiet.

use std::sync::Arc;
use std::time::Duration;

use keepword::Node;
use keepword::config::Config;
use keepword_core::bundle::Status;
use keepword_core::statement::Signed;
use keepword_core::{Digest, now_ms};
use keepword_tlsn::{Limits, Notary, TlsnHello, VerifierService, capture_with, roots_from};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

/// A TLS 1.2 web server with TLSNotary's test certificate for
/// `test-server.io`, serving one page.
async fn serve_page(sock: DuplexStream) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                tlsn_server_fixture_certs::SERVER_CERT_DER.to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                tlsn_server_fixture_certs::SERVER_KEY_DER.to_vec(),
            )),
        )
        .unwrap();
    let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(sock)
        .await
        .unwrap();
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        n += tls.read(&mut buf[n..]).await.unwrap();
    }
    let body = format!(
        "<html><body><main><h1>Terms of Service</h1>{}</main></body></html>",
        "<p>We never sell your data.</p>".repeat(40)
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(resp.as_bytes()).await.unwrap();
    tls.shutdown().await.unwrap();
}

fn node(dir: &std::path::Path) -> Node {
    let mut cfg = Config::default();
    cfg.beacon.drand_url = Some(String::new());
    cfg.anchor.calendars = vec![];
    Node::init(dir, &cfg).unwrap();
    Node::open(dir).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notarized_capture_verifies() {
    let (pdir, vdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let prover = node(pdir.path());
    let verifier = Arc::new(node(vdir.path()));
    let roots = roots_from(&[tlsn_server_fixture_certs::CA_CERT_DER]);
    let limits = Limits {
        max_sent: 4096,
        max_recv: 64 * 1024,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vaddr = listener.local_addr().unwrap();
    let service = VerifierService::new(verifier.clone(), roots.clone(), limits, true);
    tokio::spawn(service.serve(listener));

    // The web server, over an in-memory pipe.
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve_page(server));

    let url = url::Url::parse(&format!(
        "https://{}/terms",
        tlsn_server_fixture_certs::SERVER_DOMAIN
    ))
    .unwrap();
    let notary = Notary {
        addr: vaddr,
        key: verifier.key.public(),
        roots,
        limits,
    };
    let (out, receipt) = capture_with(&prover, &notary, client, None, &url)
        .await
        .unwrap();
    assert_eq!(
        receipt.body.server_name,
        tlsn_server_fixture_certs::SERVER_DOMAIN
    );
    assert_eq!(out.record.signed.attestation.status, 200);

    let bundle = prover.bundle(&out.record, true).unwrap();
    let report = Node::verify_bundle(&bundle);
    let t = report
        .checks
        .iter()
        .find(|c| c.name == "tls notary")
        .unwrap();
    assert_eq!(t.status, Status::Pass, "{}", t.detail);
    assert!(report.ok(), "{report:?}");

    // A doctored transcript no longer matches the receipt.
    let mut forged = bundle.clone();
    let ev = forged.tlsn.as_mut().unwrap();
    let mut raw = keepword_core::bundle::Content {
        body_b64: ev.received_b64.clone(),
        ..Default::default()
    }
    .body()
    .unwrap()
    .unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    ev.received_b64 = Some(keepword_core::bundle::Content::encode(&raw));
    let t = Node::verify_bundle(&forged);
    assert_eq!(
        t.checks
            .iter()
            .find(|c| c.name == "tls notary")
            .unwrap()
            .status,
        Status::Fail
    );

    // A receipt for someone else's capture doesn't transfer.
    let mut forged = bundle.clone();
    forged.tlsn.as_mut().unwrap().receipt.body.prover = verifier.key.public();
    assert!(!Node::verify_bundle(&forged).ok());

    // The receipt also went out over the verifier's gossip.
    let out = verifier.store.gossip_since(0, 100).unwrap();
    assert!(
        out.iter()
            .any(|(_, g)| matches!(g, keepword_core::net::Gossip::TlsnReceipt(_)))
    );
}

/// A prover asking for more than the verifier allows hears why it was
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_session_is_refused_with_the_reason() {
    let (pdir, vdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let prover = node(pdir.path());
    let verifier = Arc::new(node(vdir.path()));
    let roots = roots_from(&[tlsn_server_fixture_certs::CA_CERT_DER]);
    let small = Limits {
        max_sent: 4096,
        max_recv: 16 * 1024,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vaddr = listener.local_addr().unwrap();
    tokio::spawn(
        VerifierService::new(verifier.clone(), roots.clone(), small, true).serve(listener),
    );

    let (client, _server) = tokio::io::duplex(1 << 16);
    let notary = Notary {
        addr: vaddr,
        key: verifier.key.public(),
        roots,
        limits: Limits {
            max_recv: 64 * 1024,
            ..small
        },
    };
    let url = url::Url::parse("https://test-server.io/terms").unwrap();
    let err = capture_with(&prover, &notary, client, None, &url)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("data limits too large"),
        "{err:#}"
    );
}

/// Reads until the peer closes the connection, which must still be open at
/// `open_until`. Time is paused in the tests using this, and whenever a
/// test waits, even on I/O, the clock jumps to the next timer: so this can
/// tell whether a connection was open at a deadline but not when it
/// closed, and the deadline has to be set before connecting, with no other
/// timer pending.
async fn closes_after(sock: &mut TcpStream, open_until: Instant) {
    let mut buf = vec![0u8; 1 << 16];
    let mut drain =
        std::pin::pin!(async { while sock.read(&mut buf).await.is_ok_and(|n| n > 0) {} });
    let early = tokio::time::timeout_at(open_until, drain.as_mut()).await;
    assert!(early.is_err(), "the connection closed too early");
    tokio::time::timeout(Duration::from_secs(24 * 3600), drain)
        .await
        .expect("the connection was never closed");
}

/// A verifier hangs up on a connection that never says what it wants, and
/// on a prover that goes quiet in the session, once their timeouts run out.
#[tokio::test(start_paused = true)]
async fn verifier_hangs_up_on_silent_provers() {
    let (pdir, vdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let prover = node(pdir.path());
    let verifier = Arc::new(node(vdir.path()));
    let vkey = verifier.key.public();
    let roots = roots_from(&[tlsn_server_fixture_certs::CA_CERT_DER]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vaddr = listener.local_addr().unwrap();
    tokio::spawn(VerifierService::new(verifier, roots, Limits::default(), true).serve(listener));

    // The request timeout is 30 seconds.
    let open_until = Instant::now() + Duration::from_secs(29);
    let mut quiet = TcpStream::connect(vaddr).await.unwrap();
    closes_after(&mut quiet, open_until).await;

    let hello = Signed::sign(
        TlsnHello {
            prover: prover.key.public(),
            verifier: vkey,
            nonce: Digest::of(b"quiet"),
            sent_at_ms: now_ms(),
        },
        &prover.key,
    )
    .unwrap();
    let hello = serde_json::to_vec(&hello).unwrap();
    // The session timeout is ten minutes.
    let open_until = Instant::now() + Duration::from_secs(9 * 60);
    let mut quiet = TcpStream::connect(vaddr).await.unwrap();
    quiet.write_u8(b'P').await.unwrap();
    quiet
        .write_all(&(hello.len() as u32).to_be_bytes())
        .await
        .unwrap();
    quiet.write_all(&hello).await.unwrap();
    closes_after(&mut quiet, open_until).await;
}

/// A capture gives up on a verifier that goes quiet, and hangs up on it.
#[tokio::test(start_paused = true)]
async fn capture_gives_up_on_a_silent_verifier() {
    let (pdir, vdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let prover = node(pdir.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let notary = Notary {
        addr: listener.local_addr().unwrap(),
        key: node(vdir.path()).key.public(),
        roots: roots_from(&[tlsn_server_fixture_certs::CA_CERT_DER]),
        limits: Limits::default(),
    };
    // Takes the hello and the session, and never answers. The session
    // timeout is ten minutes.
    let open_until = Instant::now() + Duration::from_secs(9 * 60);
    let mut verifier = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        closes_after(&mut sock, open_until).await;
    });

    let (client, _server) = tokio::io::duplex(1 << 16);
    let url = url::Url::parse("https://test-server.io/terms").unwrap();
    let err = tokio::select! {
        r = capture_with(&prover, &notary, client, None, &url) => r.unwrap_err(),
        r = &mut verifier => panic!("the capture never gave up: {r:?}"),
    };
    assert!(format!("{err:#}").contains("timed out"), "{err:#}");
    verifier.await.unwrap();
}
