//! A single Witness node: capture → normalize → sign → log, plus change
//! detection, evidence bundles and self-audit.

pub mod config;
pub mod web;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use url::Url;
use witness_capture::{Captured, HttpCapturer};
use witness_core::bundle::{Bundle, Content, Report, Status};
use witness_core::{
    format_ms, merkle, now_ms, target, Attestation, CaptureMethod, Digest, Keypair, SignedTreeHead,
};
use witness_normalize::diff::{self, Change};
use witness_normalize::{Normalizer, SiteRules};
use witness_store::{ChangeRow, Record, Store};

use crate::config::{Config, Retain};

pub struct Node {
    pub dir: PathBuf,
    pub config: Config,
    pub key: Keypair,
    pub store: Store,
    normalizer: Normalizer,
    http: HttpCapturer,
}

/// Result of one capture.
#[derive(Debug, Serialize)]
pub struct Outcome {
    pub record: Record,
    pub tree_head: SignedTreeHead,
    pub previous: Option<Digest>,
    pub change: Option<ChangeInfo>,
}

#[derive(Debug, Serialize)]
pub struct ChangeInfo {
    pub summary: String,
    pub silent: bool,
    /// Present when both versions' normalized text was retained.
    pub diff: Option<Change>,
}

impl Node {
    pub fn open(dir: &Path) -> Result<Self> {
        let config = Config::load(dir)?;
        let key = config::load_key(dir)?;
        let store = Store::open(dir).context("opening store")?;
        let normalizer = Normalizer::new(config.rules.clone())?;
        let http = HttpCapturer::new(config.http())?;
        Ok(Node {
            dir: dir.to_path_buf(),
            config,
            key,
            store,
            normalizer,
            http,
        })
    }

    pub fn init(dir: &Path, config: &Config) -> Result<Keypair> {
        std::fs::create_dir_all(dir)?;
        if dir.join(config::CONFIG_FILE).exists() {
            bail!("{} is already initialized", dir.display());
        }
        let key = config::create_key(dir)?;
        config.save(dir)?;
        Store::open(dir)?;
        Ok(key)
    }

    pub async fn capture(&self, url: &str, render: bool) -> Result<Outcome> {
        let url = target::canonical_url(url)?;
        let captured = if render {
            self.render(&url).await?
        } else {
            self.http.capture(&url).await?
        };
        self.commit(captured)
    }

    #[cfg(feature = "render")]
    async fn render(&self, url: &Url) -> Result<Captured> {
        let cfg = witness_capture::RenderConfig {
            executable: self.config.capture.chrome.clone(),
            user_agent: self.config.capture.user_agent.clone(),
            ..Default::default()
        };
        Ok(witness_capture::RenderCapturer::new(cfg)
            .capture(url)
            .await?)
    }

    #[cfg(not(feature = "render"))]
    async fn render(&self, _url: &Url) -> Result<Captured> {
        bail!("this build has no headless browser support; rebuild with `--features render`")
    }

    /// Sign, store and log a capture, then compare it with the previous one.
    pub fn commit(&self, c: Captured) -> Result<Outcome> {
        let norm = self.normalizer.normalize(
            &c.final_url,
            c.content_type.as_deref(),
            &c.body,
            c.fetched_at_ms,
        );
        let attestation = Attestation {
            url: c.requested_url.to_string(),
            final_url: c.final_url.to_string(),
            redirects: c.redirects.iter().map(Url::to_string).collect(),
            fetched_at_ms: c.fetched_at_ms,
            method: c.method,
            status: c.status,
            content_type: c.content_type.clone(),
            headers_hash: Digest::of(&c.headers),
            body_hash: Digest::of(&c.body),
            body_len: c.body.len() as u64,
            norm: Some(norm.commitment),
            cert_sha256: c.cert_sha256,
            server_ip: c.server_ip,
            vantage: self.config.vantage(),
            witness: self.key.public(),
        };
        let signed = attestation.sign(&self.key)?;

        match self.config.content.retain {
            Retain::Full => {
                self.store.blobs.put(&c.headers)?;
                self.store.blobs.put(&c.body)?;
                self.store.blobs.put(norm.text.as_bytes())?;
            }
            Retain::Normalized => {
                self.store.blobs.put(&c.headers)?;
                self.store.blobs.put(norm.text.as_bytes())?;
            }
            Retain::None => {}
        }

        let prev = self.store.latest(&signed.attestation.url, c.method)?;
        let (record, tree_head) = self.store.commit(&signed, &self.key, now_ms())?;
        let change = match &prev {
            Some(p) => self.detect_change(p, &record)?,
            None => None,
        };
        Ok(Outcome {
            record,
            tree_head,
            previous: prev.map(|p| p.id),
            change,
        })
    }

    fn detect_change(&self, prev: &Record, cur: &Record) -> Result<Option<ChangeInfo>> {
        let (a, b) = (&prev.signed.attestation, &cur.signed.attestation);
        if !witness_core::quorum::comparable(a, b) {
            // Normalizer version or site rules changed; hashes aren't comparable.
            return Ok(None);
        }
        if a.comparison_hash() == b.comparison_hash() && a.status == b.status {
            return Ok(None);
        }
        let diff = match (self.normalized_text(a)?, self.normalized_text(b)?) {
            (Some(old), Some(new)) => diff::diff(&old, &new),
            _ => None,
        };
        let mut summary = match &diff {
            Some(d) => d.summary(),
            None if a.comparison_hash() != b.comparison_hash() => {
                "content changed (normalized text not retained)".to_string()
            }
            None => "status changed".to_string(),
        };
        if a.status != b.status {
            summary = format!("status {} → {}; {summary}", a.status, b.status);
        }
        // Without the text we can't look for a notice, so don't call it silent.
        let silent = diff.as_ref().is_some_and(Change::is_silent);
        let row = ChangeRow {
            seq: 0,
            url: b.url.clone(),
            from_id: prev.id,
            to_id: cur.id,
            detected_at: now_ms(),
            silent,
            added: diff.as_ref().map_or(0, |d| d.added as u64),
            removed: diff.as_ref().map_or(0, |d| d.removed as u64),
            summary: summary.clone(),
        };
        self.store.record_change(&row)?;
        Ok(Some(ChangeInfo {
            summary,
            silent,
            diff,
        }))
    }

    pub fn normalized_text(&self, a: &Attestation) -> Result<Option<String>> {
        let Some(n) = a.norm else { return Ok(None) };
        Ok(self
            .store
            .blobs
            .get(&n.hash)?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    /// Resolve a user-supplied reference: a full or prefix attestation ID, or
    /// a URL (optionally at a point in time).
    pub fn resolve(&self, reference: &str, at_ms: Option<i64>) -> Result<Record> {
        if reference.contains("://") {
            let url = target::canonical_url(reference)?;
            let rec = match at_ms {
                Some(t) => self.store.at(url.as_str(), t)?,
                None => self.store.history(url.as_str())?.pop(),
            };
            return rec.ok_or_else(|| match at_ms {
                Some(t) => anyhow!("no capture of {url} at or before {}", format_ms(t)),
                None => anyhow!("no capture of {url}"),
            });
        }
        let mut matches = self.store.find_prefix(reference)?;
        match matches.len() {
            0 => bail!("no attestation with ID {reference}"),
            1 => Ok(matches.remove(0)),
            _ => bail!("ID prefix {reference} is ambiguous"),
        }
    }

    /// Build a bundle proving a record's inclusion in the current log.
    pub fn bundle(&self, rec: &Record, with_content: bool) -> Result<Bundle> {
        let leaves = self.store.leaves()?;
        let head = self
            .store
            .latest_tree_head()?
            .ok_or_else(|| anyhow!("log is empty"))?;
        let size = head.head.size as usize;
        let proof = merkle::inclusion_proof(&leaves[..size], rec.leaf_index as usize)
            .ok_or_else(|| anyhow!("record is not in the latest tree head"))?;
        let mut b = Bundle::new(rec.signed.clone());
        b.inclusion = Some(witness_core::bundle::Inclusion {
            leaf_index: rec.leaf_index,
            proof,
            tree_head: head,
        });
        if with_content {
            let a = &rec.signed.attestation;
            let get = |d: &Digest| -> Result<Option<String>> {
                Ok(self.store.blobs.get(d)?.map(|b| Content::encode(&b)))
            };
            let rules = self.rules_for_profile(a);
            b.content = Some(Content {
                headers_b64: get(&a.headers_hash)?,
                body_b64: get(&a.body_hash)?,
                normalized: self.normalized_text(a)?,
                norm_rules: rules.map(|r| serde_json::to_value(r).expect("rules serialize")),
            });
        }
        Ok(b)
    }

    /// The site rules behind an attestation's normalizer profile, if the
    /// current configuration still produces that profile.
    fn rules_for_profile(&self, a: &Attestation) -> Option<SiteRules> {
        let n = a.norm?;
        let url = Url::parse(&a.final_url).ok()?;
        let rules = self.normalizer.rules_for(&url);
        (witness_normalize::profile(rules) == n.profile)
            .then(|| rules.cloned())
            .flatten()
    }

    /// Everything `Bundle::verify` checks, plus re-running normalization.
    pub fn verify_bundle(bundle: &Bundle) -> Report {
        let mut report = bundle.verify();
        let a = &bundle.attestation.attestation;
        let content = bundle.content.clone().unwrap_or_default();
        let (Some(n), Some(Ok(body))) = (a.norm, content.body()) else {
            report.push(
                "renormalize",
                Status::Skip,
                "needs the body and a norm commitment",
            );
            return report;
        };
        let rules: Option<SiteRules> = match content
            .norm_rules
            .clone()
            .map(serde_json::from_value)
            .transpose()
        {
            Ok(r) => r,
            Err(e) => {
                report.push(
                    "renormalize",
                    Status::Fail,
                    format!("bad rules in bundle: {e}"),
                );
                return report;
            }
        };
        if witness_normalize::profile(rules.as_ref()) != n.profile {
            report.push(
                "renormalize",
                Status::Skip,
                "attestation used a different normalizer version or rules",
            );
            return report;
        }
        let Ok(url) = Url::parse(&a.final_url) else {
            report.push("renormalize", Status::Fail, "final URL does not parse");
            return report;
        };
        let out = witness_normalize::normalize_with(
            rules.as_ref(),
            &url,
            a.content_type.as_deref(),
            &body,
            a.fetched_at_ms,
        );
        if out.commitment.hash == n.hash {
            report.push(
                "renormalize",
                Status::Pass,
                "body normalizes to the attested norm hash",
            );
        } else {
            report.push(
                "renormalize",
                Status::Fail,
                "body does not normalize to the attested norm hash",
            );
        }
        report
    }

    /// Check the whole local log: every tree head is validly signed and
    /// consistent with the next, the latest matches the leaves, every indexed
    /// attestation verifies and sits at its leaf, and retained blobs are intact.
    pub fn audit(&self) -> Result<Report> {
        let mut r = Report::default();
        let leaves = self.store.leaves()?;
        let heads = self.store.tree_heads()?;
        let me = self.key.public();

        let mut bad_heads = 0;
        for (i, h) in heads.iter().enumerate() {
            let ok = h.verify().is_ok()
                && h.head.log == me
                && h.head.size as usize <= leaves.len()
                && merkle::root(&leaves[..h.head.size as usize]) == h.head.root;
            if !ok {
                bad_heads += 1;
            }
            if let Some(next) = heads.get(i + 1) {
                let proof = merkle::consistency_proof(
                    &leaves[..next.head.size as usize],
                    h.head.size as usize,
                )
                .unwrap_or_default();
                if h.verify_extension(next, &proof).is_err() {
                    bad_heads += 1;
                }
            }
        }
        if bad_heads == 0 {
            r.push(
                "tree heads",
                Status::Pass,
                format!("{} heads, all signed and consistent", heads.len()),
            );
        } else {
            r.push(
                "tree heads",
                Status::Fail,
                format!("{bad_heads} problems across {} heads", heads.len()),
            );
        }
        match heads.last() {
            Some(h) if h.head.size as usize == leaves.len() => r.push(
                "latest head",
                Status::Pass,
                format!("covers all {} leaves", leaves.len()),
            ),
            Some(h) => r.push(
                "latest head",
                Status::Fail,
                format!("covers {} of {} leaves", h.head.size, leaves.len()),
            ),
            None if leaves.is_empty() => r.push("latest head", Status::Skip, "log is empty"),
            None => r.push("latest head", Status::Fail, "leaves exist but no tree head"),
        }

        let (mut atts, mut bad_atts, mut blobs, mut bad_blobs) = (0, 0, 0, 0);
        for s in self.store.urls()? {
            for rec in self.store.history(&s.url)? {
                atts += 1;
                let at_leaf = leaves.get(rec.leaf_index as usize)
                    == Some(&merkle::leaf_hash(rec.id.as_bytes()));
                if rec.signed.verify().is_err() || rec.signed.id() != rec.id || !at_leaf {
                    bad_atts += 1;
                }
                let a = &rec.signed.attestation;
                for d in [
                    Some(a.headers_hash),
                    Some(a.body_hash),
                    a.norm.map(|n| n.hash),
                ]
                .into_iter()
                .flatten()
                {
                    match self.store.blobs.get(&d) {
                        Ok(Some(_)) => blobs += 1,
                        Ok(None) => {}
                        Err(_) => bad_blobs += 1,
                    }
                }
            }
        }
        if bad_atts == 0 {
            r.push(
                "attestations",
                Status::Pass,
                format!("{atts} verified and found in the log"),
            );
        } else {
            r.push(
                "attestations",
                Status::Fail,
                format!("{bad_atts} of {atts} failed"),
            );
        }
        if bad_blobs == 0 {
            r.push(
                "blobs",
                Status::Pass,
                format!("{blobs} retained blob reads intact"),
            );
        } else {
            r.push("blobs", Status::Fail, format!("{bad_blobs} corrupt blobs"));
        }
        Ok(r)
    }
}

/// Parse `--at` values: RFC 3339, or a bare date meaning the end of that day
/// in UTC.
pub fn parse_time(s: &str) -> Result<i64> {
    use time::format_description::well_known::Rfc3339;
    if let Ok(t) = time::OffsetDateTime::parse(s, &Rfc3339) {
        return Ok((t.unix_timestamp_nanos() / 1_000_000) as i64);
    }
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    let d = time::Date::parse(s, &fmt)
        .map_err(|_| anyhow!("expected RFC 3339 time or YYYY-MM-DD, got {s:?}"))?;
    let end = d
        .with_hms_milli(23, 59, 59, 999)
        .expect("valid time")
        .assume_utc();
    Ok((end.unix_timestamp_nanos() / 1_000_000) as i64)
}

/// Method name for display.
pub fn method_name(m: CaptureMethod) -> &'static str {
    match m {
        CaptureMethod::Http => "http",
        CaptureMethod::Rendered => "rendered",
    }
}
