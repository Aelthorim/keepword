//! Capturing pages as evidence.

mod http;
pub mod netpolicy;
#[cfg(feature = "render")]
mod render;
pub mod warc;

use std::net::IpAddr;

use keepword_core::CaptureMethod;
use url::Url;

pub use http::{HttpCapturer, HttpConfig};
#[cfg(feature = "render")]
pub use render::{RenderCapturer, RenderConfig};

/// Everything observed during one capture, before signing.
#[derive(Clone, Debug)]
pub struct Captured {
    pub method: CaptureMethod,
    pub requested_url: Url,
    pub final_url: Url,
    pub redirects: Vec<Url>,
    pub fetched_at_ms: i64,
    pub status: u16,
    pub content_type: Option<String>,
    /// Status line and end-to-end headers, CRLF-separated, ending in a blank
    /// line. Empty for rendered captures.
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub cert_sha256: Option<[u8; 32]>,
    pub server_ip: Option<IpAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("client setup failed: {0}")]
    Setup(String),
    #[error("fetch failed: {0}")]
    Fetch(String),
    #[error("refused: {0}")]
    Refused(String),
    #[error("response body larger than {0} bytes")]
    TooLarge(usize),
    #[error("browser: {0}")]
    Browser(String),
}
