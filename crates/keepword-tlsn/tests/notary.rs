//! A full MPC-TLS notarization between two witnesses, against TLSNotary's
//! test server.

use std::sync::Arc;

use keepword::Node;
use keepword::config::Config;
use keepword_core::bundle::Status;
use keepword_tlsn::{Limits, Notary, VerifierService, capture_with, roots_from};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

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
