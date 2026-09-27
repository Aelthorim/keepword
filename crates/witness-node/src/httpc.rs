//! HTTP client for peers and external services (drand, OpenTimestamps
//! calendars, Esplora). Responses are size-limited, and peer endpoints come
//! from untrusted descriptors, so private addresses are refused unless the
//! node is configured for LAN use.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use witness_capture::netpolicy::PublicOnlyResolver;

pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
}

impl Http {
    pub fn new(allow_private: bool, use_system_proxy: bool) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .user_agent(concat!("witness/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10));
        if !use_system_proxy {
            b = b.no_proxy();
        }
        if !allow_private {
            b = b.dns_resolver(Arc::new(PublicOnlyResolver));
        }
        Ok(Http { client: b.build()? })
    }

    async fn read(resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
        let status = resp.status();
        let mut resp = resp;
        if resp.content_length().is_some_and(|l| l as usize > max) {
            bail!("response too large");
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > max {
                bail!("response too large");
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let text = String::from_utf8_lossy(&body[..body.len().min(300)]).into_owned();
            return Err(anyhow!(HttpStatus(status.as_u16(), text)));
        }
        Ok(body)
    }

    pub async fn get_bytes(&self, url: &str, max: usize) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        Self::read(resp, max)
            .await
            .with_context(|| format!("GET {url}"))
    }

    pub async fn post_bytes(
        &self,
        url: &str,
        body: Vec<u8>,
        accept: &str,
        max: usize,
    ) -> Result<Vec<u8>> {
        let resp = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, accept)
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        Self::read(resp, max)
            .await
            .with_context(|| format!("POST {url}"))
    }

    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let b = self.get_bytes(url, MAX_RESPONSE).await?;
        serde_json::from_slice(&b).with_context(|| format!("decoding {url}"))
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body)?)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let b = Self::read(resp, MAX_RESPONSE)
            .await
            .with_context(|| format!("POST {url}"))?;
        serde_json::from_slice(&b).with_context(|| format!("decoding {url}"))
    }
}

/// A non-2xx response, so callers can tell "not found" from failures.
#[derive(Debug)]
pub struct HttpStatus(pub u16, pub String);

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}: {}", self.0, self.1)
    }
}

impl std::error::Error for HttpStatus {}

pub fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.chain()
        .find_map(|c| c.downcast_ref::<HttpStatus>())
        .map(|s| s.0)
}

/// Join a base URL and a path without doubling slashes.
pub fn join(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}
