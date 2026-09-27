//! Raw HTTP(S) capture.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::LOCATION;
use reqwest::redirect::Policy;
use sha2::{Digest as _, Sha256};
use url::Url;
use witness_core::{now_ms, CaptureMethod};

use crate::netpolicy::{is_public, PublicOnlyResolver};
use crate::{CaptureError, Captured};

#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub user_agent: String,
    pub timeout: Duration,
    pub max_body_bytes: usize,
    pub max_redirects: usize,
    /// Use HTTP(S)_PROXY from the environment. Off by default: a proxy
    /// changes the vantage point, and a TLS-intercepting one replaces the
    /// server's certificate with its own.
    pub use_system_proxy: bool,
    /// Allow loopback, private and link-local targets. Only for tests and
    /// deliberate LAN monitoring.
    pub allow_private: bool,
    /// Extra trusted root certificates (DER), for private PKI and tests.
    pub extra_roots_der: Vec<Vec<u8>>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            user_agent: concat!(
                "Mozilla/5.0 (compatible; Witness/",
                env!("CARGO_PKG_VERSION"),
                "; +https://github.com/aelthorim/witness)"
            )
            .into(),
            timeout: Duration::from_secs(30),
            max_body_bytes: 32 * 1024 * 1024,
            max_redirects: 10,
            use_system_proxy: false,
            allow_private: false,
            extra_roots_der: Vec::new(),
        }
    }
}

pub struct HttpCapturer {
    client: reqwest::Client,
    cfg: HttpConfig,
}

/// Hop-by-hop headers describe the connection, not the resource, and the body
/// we record is already de-chunked, so they are left out of the header block.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

impl HttpCapturer {
    pub fn new(cfg: HttpConfig) -> Result<Self, CaptureError> {
        let mut b = reqwest::Client::builder()
            .user_agent(&cfg.user_agent)
            .timeout(cfg.timeout)
            .redirect(Policy::none())
            .tls_info(true)
            // No Accept-Encoding: the body we hash is the body as served,
            // not a decompressed variant of it.
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();
        if !cfg.use_system_proxy {
            b = b.no_proxy();
        }
        if !cfg.allow_private {
            b = b.dns_resolver(Arc::new(PublicOnlyResolver));
        }
        for der in &cfg.extra_roots_der {
            let cert = reqwest::Certificate::from_der(der)
                .map_err(|e| CaptureError::Setup(e.to_string()))?;
            b = b.add_root_certificate(cert);
        }
        let client = b.build().map_err(|e| CaptureError::Setup(e.to_string()))?;
        Ok(HttpCapturer { client, cfg })
    }

    pub async fn capture(&self, url: &Url) -> Result<Captured, CaptureError> {
        let mut current = url.clone();
        let mut redirects = Vec::new();
        loop {
            self.check_target(&current)?;
            let resp = self
                .client
                .get(current.clone())
                .header(
                    reqwest::header::ACCEPT,
                    "text/html,application/xhtml+xml,*/*;q=0.8",
                )
                .send()
                .await
                .map_err(|e| CaptureError::Fetch(error_chain(&e)))?;

            if resp.status().is_redirection() {
                if let Some(loc) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) {
                    let next = current
                        .join(loc)
                        .map_err(|_| CaptureError::Fetch(format!("bad redirect target {loc:?}")))?;
                    if redirects.len() >= self.cfg.max_redirects {
                        return Err(CaptureError::Fetch("too many redirects".into()));
                    }
                    redirects.push(std::mem::replace(&mut current, next));
                    continue;
                }
            }
            return self.record(url, current, redirects, resp).await;
        }
    }

    fn check_target(&self, u: &Url) -> Result<(), CaptureError> {
        if u.scheme() != "http" && u.scheme() != "https" {
            return Err(CaptureError::Refused(format!(
                "scheme {} not allowed",
                u.scheme()
            )));
        }
        if self.cfg.allow_private {
            return Ok(());
        }
        let ip = match u.host() {
            Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
            Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
            _ => None,
        };
        match ip {
            Some(ip) if !is_public(ip) => Err(CaptureError::Refused(format!(
                "{ip} is not a public address"
            ))),
            _ => Ok(()),
        }
    }

    async fn record(
        &self,
        requested: &Url,
        final_url: Url,
        redirects: Vec<Url>,
        mut resp: reqwest::Response,
    ) -> Result<Captured, CaptureError> {
        let fetched_at_ms = now_ms();
        let status = resp.status();
        // Through a proxy, the peer address is the proxy's, and reqwest
        // doesn't expose the tunnelled TLS session, so both stay empty.
        let server_ip = resp
            .remote_addr()
            .map(|a| a.ip())
            .filter(|_| !self.cfg.use_system_proxy);
        let cert_sha256 = resp
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|t| t.peer_certificate())
            .map(|der| Sha256::digest(der).into());

        let mut headers = format!(
            "{:?} {} {}\r\n",
            resp.version(),
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        )
        .into_bytes();
        for (name, value) in resp.headers() {
            if HOP_BY_HOP.contains(&name.as_str()) {
                continue;
            }
            headers.extend_from_slice(name.as_str().as_bytes());
            headers.extend_from_slice(b": ");
            headers.extend_from_slice(value.as_bytes());
            headers.extend_from_slice(b"\r\n");
        }
        headers.extend_from_slice(b"\r\n");

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| CaptureError::Fetch(error_chain(&e)))?
        {
            if body.len() + chunk.len() > self.cfg.max_body_bytes {
                return Err(CaptureError::TooLarge(self.cfg.max_body_bytes));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(Captured {
            method: CaptureMethod::Http,
            requested_url: requested.clone(),
            final_url,
            redirects,
            fetched_at_ms,
            status: status.as_u16(),
            content_type,
            headers,
            body,
            cert_sha256,
            server_ip,
        })
    }
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}
