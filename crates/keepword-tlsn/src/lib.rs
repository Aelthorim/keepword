//! TLSNotary proof tier (docs/DESIGN.md §6.7).
//!
//! A witness (the prover) fetches a page through an MPC-TLS session run
//! jointly with a second witness (the verifier). The verifier never sees the
//! session keys alone, but it checks the server's certificate chain and name
//! and learns the plaintext the prover reveals. It then signs a
//! [`TlsnReceipt`]. With the receipt and the received transcript, anyone can
//! check that the prover's attestation describes bytes that really came from
//! that server, so fabricating a capture needs two colluding witnesses.
//!
//! Wire protocol on the verifier's TCP port:
//! - `P` + length-prefixed signed [`TlsnHello`], then the TLSNotary session;
//! - `R` + length-prefixed nonce, answered with a length-prefixed
//!   `Option<Signed<TlsnReceipt>>`.

use std::collections::HashMap;
use std::future::IntoFuture;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use keepword_capture::Captured;
use keepword_capture::netpolicy::is_public;
use keepword_core::encoding::Encoder;
use keepword_core::httpmsg::parse_response;
use keepword_core::net::{Gossip, TlsnReceipt};
use keepword_core::statement::{Signed, Statement};
use keepword_core::{CaptureMethod, Digest, WitnessKey, now_ms};
use keepword::config::Retain;
use keepword::{Node, Outcome};
use serde::{Deserialize, Serialize};
use tlsn::Session;
use tlsn::config::prove::ProveConfig;
use tlsn::config::prover::ProverConfig;
use tlsn::config::tls::TlsClientConfig;
use tlsn::config::tls_commit::mpc::MpcTlsConfig;
use tlsn::config::verifier::VerifierConfig;
use tlsn::connection::ServerName;
use tlsn::verifier::{VerifierCommitStart, VerifierOutput};
use tlsn::webpki::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use url::Url;

pub use tlsn::webpki::CertificateDer;

/// MPC cost grows with the bytes exchanged, so both sides agree on limits
/// up front. The verifier refuses anything larger than its own limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_sent: usize,
    pub max_recv: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_sent: 4 * 1024,
            max_recv: 256 * 1024,
        }
    }
}

/// Mozilla's root store, which both sides use in production.
pub fn mozilla_roots() -> RootCertStore {
    RootCertStore::mozilla()
}

pub fn roots_from(ders: &[&[u8]]) -> RootCertStore {
    RootCertStore {
        roots: ders.iter().map(|d| CertificateDer(d.to_vec())).collect(),
    }
}

/// Opens a notarization session; signed by the prover so a verifier only
/// serves witnesses it knows, and a hello can't be replayed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsnHello {
    pub prover: WitnessKey,
    pub verifier: WitnessKey,
    pub nonce: Digest,
    pub sent_at_ms: i64,
}

impl Statement for TlsnHello {
    const DOMAIN: &'static str = "keepword/tlsn-hello/v1";
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.prover.0)
            .fixed(&self.verifier.0)
            .fixed(self.nonce.as_bytes())
            .i64(self.sent_at_ms);
    }
    fn signer(&self) -> WitnessKey {
        self.prover
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, b: &[u8]) -> Result<()> {
    w.write_all(&(b.len() as u32).to_be_bytes()).await?;
    w.write_all(b).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        bail!("frame too large");
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

/// What the prover learned from the session.
pub struct Proven {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
}

/// Prover side of one MPC-TLS session: fetch `path` from `server_name` over
/// `server`, with the verifier on the other end of `verifier`, and reveal
/// the whole transcript and the server identity.
pub async fn prove<V, S>(
    verifier: V,
    server: S,
    server_name: &str,
    path: &str,
    user_agent: &str,
    roots: RootCertStore,
    limits: Limits,
) -> Result<Proven>
where
    V: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(verifier.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(limits.max_sent)
                .max_recv_data(limits.max_recv)
                .build()?,
        )
        .await?;
    let (tls, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(server_name.try_into()?))
            .root_store(roots)
            .build()?,
        server.compat(),
    )?;
    let tls = TokioIo::new(tls.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls).await?;
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(path)
        .header("Host", server_name)
        .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        // TLSNotary can't prove compressed bodies.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", user_agent)
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    resp.into_body().collect().await?;

    let mut prover = prover_task.await??;
    let sent = prover.transcript().sent().to_vec();
    let received = prover.transcript().received().to_vec();
    let mut cfg = ProveConfig::builder(prover.transcript());
    cfg.server_identity();
    cfg.reveal_sent(&(0..sent.len()))?;
    cfg.reveal_recv(&(0..received.len()))?;
    let cfg = cfg.build()?;
    prover.prove(&cfg).await?;
    prover.close().await?;
    handle.close();
    driver_task.await??;
    Ok(Proven { sent, received })
}

/// What the verifier checked.
pub struct Verified {
    pub server_name: String,
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
}

/// Verifier side of one session. Requires the server identity and the full
/// transcript to be revealed.
pub async fn verify<P>(prover: P, roots: RootCertStore, limits: Limits) -> Result<Verified>
where
    P: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(prover.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(VerifierConfig::builder().root_store(roots).build()?)?;
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(v) => {
            let cfg = v.config();
            if cfg.max_sent_data() > limits.max_sent || cfg.max_recv_data() > limits.max_recv {
                v.reject(Some("data limits too large")).await?;
                bail!("prover asked for larger limits than this verifier allows");
            }
            v.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(v) => {
            v.reject(Some("only MPC-TLS is supported")).await?;
            bail!("prover asked for proxy mode");
        }
    };
    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() {
        let v = verifier
            .reject(Some("the server identity must be revealed"))
            .await?;
        v.close().await?;
        bail!("prover did not reveal the server identity");
    }
    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;
    verifier.close().await?;
    handle.close();
    driver_task.await??;

    let ServerName::Dns(name) = server_name.ok_or_else(|| anyhow!("no server name revealed"))?;
    let transcript = transcript.ok_or_else(|| anyhow!("no transcript revealed"))?;
    if !transcript.is_complete() {
        bail!("prover revealed only part of the transcript");
    }
    Ok(Verified {
        server_name: name.as_str().to_string(),
        sent: transcript.sent_unsafe().to_vec(),
        received: transcript.received_unsafe().to_vec(),
    })
}

/// A witness's notarization service.
pub struct VerifierService {
    node: Arc<Node>,
    roots: RootCertStore,
    limits: Limits,
    /// Accept provers that aren't known peers.
    open: bool,
    receipts: Mutex<HashMap<Digest, Signed<TlsnReceipt>>>,
}

impl VerifierService {
    pub fn new(node: Arc<Node>, roots: RootCertStore, limits: Limits, open: bool) -> Arc<Self> {
        Arc::new(VerifierService {
            node,
            roots,
            limits,
            open,
            receipts: Mutex::new(HashMap::new()),
        })
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (sock, peer) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.handle(sock).await {
                    eprintln!("tlsn session from {peer}: {e:#}");
                }
            });
        }
    }

    async fn handle(&self, mut sock: TcpStream) -> Result<()> {
        sock.set_nodelay(true)?;
        match sock.read_u8().await? {
            b'P' => {
                let hello: Signed<TlsnHello> =
                    serde_json::from_slice(&read_frame(&mut sock, 4096).await?)?;
                let h = &hello.body;
                hello.verify().context("hello signature")?;
                if h.verifier != self.node.key.public()
                    || (h.sent_at_ms - now_ms()).abs() > 5 * 60_000
                {
                    bail!("hello not addressed to this witness, or stale");
                }
                if h.prover == self.node.key.public() {
                    bail!("a witness cannot notarize itself");
                }
                if !self.open && self.node.store.peer(&h.prover)?.is_none() {
                    bail!("prover {} is not a known peer", h.prover.short());
                }
                if self
                    .receipts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .contains_key(&h.nonce)
                {
                    bail!("nonce reused");
                }
                let v = verify(sock, self.roots.clone(), self.limits).await?;
                let receipt = Signed::sign(
                    TlsnReceipt {
                        prover: h.prover,
                        server_name: v.server_name,
                        sent_hash: Digest::of(&v.sent),
                        received_hash: Digest::of(&v.received),
                        received_len: v.received.len() as u64,
                        verified_at_ms: now_ms(),
                        verifier: self.node.key.public(),
                    },
                    &self.node.key,
                )?;
                self.node.publish(Gossip::TlsnReceipt(receipt.clone()))?;
                self.receipts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(h.nonce, receipt);
                Ok(())
            }
            b'R' => {
                let nonce: Digest = serde_json::from_slice(&read_frame(&mut sock, 256).await?)?;
                let r = self
                    .receipts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&nonce)
                    .cloned();
                write_frame(&mut sock, &serde_json::to_vec(&r)?).await
            }
            _ => bail!("unknown request"),
        }
    }
}

async fn fetch_receipt(verifier: SocketAddr, nonce: Digest) -> Result<Signed<TlsnReceipt>> {
    // The verifier signs after the session closes; give it a moment.
    for _ in 0..50 {
        let mut s = TcpStream::connect(verifier).await?;
        s.write_u8(b'R').await?;
        write_frame(&mut s, &serde_json::to_vec(&nonce)?).await?;
        let r: Option<Signed<TlsnReceipt>> =
            serde_json::from_slice(&read_frame(&mut s, 64 * 1024).await?)?;
        if let Some(r) = r {
            return Ok(r);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("verifier did not produce a receipt")
}

/// The witness that notarizes a capture.
#[derive(Clone)]
pub struct Notary {
    /// Its notarization service address.
    pub addr: SocketAddr,
    pub key: WitnessKey,
    pub roots: RootCertStore,
    pub limits: Limits,
}

/// Capture `url` with `notary` verifying the TLS session, over an
/// already-open connection to the server. Commits the attestation to the
/// node's log and stores the receipt (and, with full retention, the
/// transcript).
pub async fn capture_with(
    node: &Node,
    notary: &Notary,
    server: impl AsyncRead + AsyncWrite + Send + Unpin + 'static,
    server_ip: Option<IpAddr>,
    url: &Url,
) -> Result<(Outcome, Signed<TlsnReceipt>)> {
    if url.scheme() != "https" {
        bail!("TLSNotary needs an https URL");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL has no host"))?
        .to_string();
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let beacon = node.capture_beacon().await;

    let mut nonce_seed = [0u8; 32];
    nonce_seed[..8].copy_from_slice(&now_ms().to_be_bytes());
    let nonce = Digest::tagged(
        "keepword tlsn-nonce v1",
        &[&nonce_seed, &node.key.sign(url.as_str().as_bytes()).0],
    );
    let hello = Signed::sign(
        TlsnHello {
            prover: node.key.public(),
            verifier: notary.key,
            nonce,
            sent_at_ms: now_ms(),
        },
        &node.key,
    )?;
    let mut vs = TcpStream::connect(notary.addr)
        .await
        .context("connecting to the verifier")?;
    vs.set_nodelay(true)?;
    vs.write_u8(b'P').await?;
    write_frame(&mut vs, &serde_json::to_vec(&hello)?).await?;

    let ua = node
        .config
        .capture
        .user_agent
        .clone()
        .unwrap_or_else(|| keepword_capture::HttpConfig::default().user_agent);
    let proven = prove(
        vs,
        server,
        &host,
        &path,
        &ua,
        notary.roots.clone(),
        notary.limits,
    )
    .await?;
    let fetched_at_ms = now_ms();
    let receipt = fetch_receipt(notary.addr, nonce).await?;
    let r = &receipt.body;
    receipt.verify().context("receipt signature")?;
    if r.verifier != notary.key
        || r.prover != node.key.public()
        || r.received_hash != Digest::of(&proven.received)
        || r.sent_hash != Digest::of(&proven.sent)
        || !r.server_name.eq_ignore_ascii_case(&host)
    {
        bail!("the verifier's receipt does not match this session");
    }

    let resp = parse_response(&proven.received)?;
    let captured = Captured {
        method: CaptureMethod::Http,
        requested_url: url.clone(),
        final_url: url.clone(),
        redirects: vec![],
        fetched_at_ms,
        status: resp.status,
        content_type: resp.content_type,
        headers: resp.header_block,
        body: resp.body,
        cert_sha256: None,
        server_ip,
    };
    let out = node.commit(captured, beacon)?;
    if node.config.content.retain == Retain::Full {
        node.store.blobs.put(&proven.received)?;
    }
    node.store.tlsn_insert(&out.record.id, &receipt)?;
    Ok((out, receipt))
}

/// Resolve and connect to an https URL's server, honouring the node's
/// private-address policy.
pub async fn connect_server(node: &Node, url: &Url) -> Result<(TcpStream, IpAddr)> {
    let host = url.host_str().ok_or_else(|| anyhow!("URL has no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    let addr = addrs
        .into_iter()
        .find(|a| node.config.capture.allow_private_addresses || is_public(a.ip()))
        .ok_or_else(|| anyhow!("{host} resolves only to non-public addresses"))?;
    let s = TcpStream::connect(addr).await?;
    s.set_nodelay(true)?;
    Ok((s, addr.ip()))
}
