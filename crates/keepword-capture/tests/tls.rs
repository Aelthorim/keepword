//! TLS evidence: the leaf certificate fingerprint and server address are
//! recorded on direct connections.

use std::sync::Arc;

use keepword_capture::{HttpCapturer, HttpConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn records_certificate_fingerprint() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let body = "<html><body><p>hi</p></body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    let capturer = HttpCapturer::new(HttpConfig {
        allow_private: true,
        extra_roots_der: vec![cert_der.to_vec()],
        ..HttpConfig::default()
    })
    .unwrap();
    let url = url::Url::parse(&format!("https://localhost:{port}/")).unwrap();
    let c = capturer.capture(&url).await.unwrap();

    assert_eq!(c.status, 200);
    let want: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
    assert_eq!(c.cert_sha256, Some(want));
    assert!(c.server_ip.unwrap().is_loopback());
    assert!(c.headers.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        !String::from_utf8_lossy(&c.headers)
            .to_ascii_lowercase()
            .contains("connection:")
    );
    assert_eq!(c.body, b"<html><body><p>hi</p></body></html>");
}
