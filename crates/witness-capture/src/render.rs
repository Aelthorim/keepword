//! Headless-browser capture for pages that only exist after JavaScript runs.
//!
//! The browser resolves hosts itself, so the public-address policy of the HTTP
//! capturer does not apply to sub-resources. Only render URLs the operator
//! chose, or run the browser in a network namespace without LAN access.

use std::path::PathBuf;
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use futures::StreamExt;
use url::Url;
use witness_core::{CaptureMethod, now_ms};

use crate::{CaptureError, Captured};

#[derive(Clone, Debug)]
pub struct RenderConfig {
    /// Chrome/Chromium binary; auto-detected when `None`.
    pub executable: Option<PathBuf>,
    pub user_agent: Option<String>,
    pub timeout: Duration,
    /// Extra time after the load event for late scripts.
    pub settle: Duration,
}

impl Default for RenderConfig {
    fn default() -> Self {
        RenderConfig {
            executable: None,
            user_agent: None,
            timeout: Duration::from_secs(45),
            settle: Duration::from_secs(2),
        }
    }
}

pub struct RenderCapturer {
    cfg: RenderConfig,
}

fn err(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Browser(e.to_string())
}

impl RenderCapturer {
    pub fn new(cfg: RenderConfig) -> Self {
        RenderCapturer { cfg }
    }

    pub async fn capture(&self, url: &Url) -> Result<Captured, CaptureError> {
        tokio::time::timeout(self.cfg.timeout, self.capture_inner(url))
            .await
            .map_err(|_| CaptureError::Browser("timed out".into()))?
    }

    async fn capture_inner(&self, url: &Url) -> Result<Captured, CaptureError> {
        let mut b = BrowserConfig::builder().no_sandbox();
        if let Some(exe) = &self.cfg.executable {
            b = b.chrome_executable(exe);
        }
        if let Some(ua) = &self.cfg.user_agent {
            b = b.arg(format!("--user-agent={ua}"));
        }
        let (mut browser, mut handler) = Browser::launch(b.build().map_err(err)?)
            .await
            .map_err(err)?;
        let events = tokio::spawn(async move { while handler.next().await.is_some() {} });

        let result = async {
            let page = browser.new_page(url.as_str()).await.map_err(err)?;
            page.wait_for_navigation().await.map_err(err)?;
            tokio::time::sleep(self.cfg.settle).await;
            let html = page.content().await.map_err(err)?;
            let final_url = page
                .url()
                .await
                .map_err(err)?
                .and_then(|u| Url::parse(&u).ok())
                .unwrap_or_else(|| url.clone());
            Ok::<_, CaptureError>((html, final_url))
        }
        .await;

        let _ = browser.close().await;
        let _ = browser.wait().await;
        events.abort();
        let (html, final_url) = result?;

        Ok(Captured {
            method: CaptureMethod::Rendered,
            requested_url: url.clone(),
            final_url,
            redirects: vec![],
            fetched_at_ms: now_ms(),
            // The DevTools protocol doesn't give us a trustworthy status for
            // the document; 0 means "not observed".
            status: 0,
            content_type: Some("text/html; charset=utf-8".into()),
            headers: Vec::new(),
            body: html.into_bytes(),
            cert_sha256: None,
            server_ip: None,
        })
    }
}
