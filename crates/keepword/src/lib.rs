//! A single Keepword node: capture → normalize → sign → log, plus change
//! detection, evidence bundles and self-audit.

pub mod anchor;
pub mod api;
pub mod beacon;
pub mod config;
pub mod consensus;
pub mod daemon;
pub mod federation;
pub mod httpc;
pub mod recheck;
pub mod sysdir;
pub mod vantage;
pub mod web;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use keepword_capture::{Captured, HttpCapturer};
use keepword_core::bundle::{Bundle, Content, Report, Status};
use keepword_core::{
    Attestation, CaptureMethod, Digest, Keypair, SignedTreeHead, format_ms, merkle, now_ms, target,
};
use keepword_normalize::diff::{self, Change};
use keepword_normalize::{Normalizer, SiteRules};
use keepword_store::{ChangeRow, Record, Store};
use serde::Serialize;
use url::Url;

use crate::config::{Config, Retain};

pub struct Node {
    pub dir: PathBuf,
    pub config: Config,
    pub key: Keypair,
    pub store: Store,
    normalizer: Normalizer,
    http: HttpCapturer,
    /// Client for peers and external services.
    pub net: httpc::Http,
    pub asn_db: Option<vantage::AsnDb>,
    /// This node's signed descriptor; see `Node::descriptor`.
    descriptor: Mutex<keepword_core::statement::Signed<keepword_core::net::Descriptor>>,
    seen_envelopes: Mutex<HashMap<Digest, i64>>,
    sched: Mutex<federation::Schedule>,
    /// What others may still make this node store and check this hour.
    limits: Mutex<federation::Limits>,
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

/// Whether `url`'s host is one of `hosts` or a subdomain of one.
pub fn host_listed(hosts: &[String], url: &Url) -> bool {
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    hosts
        .iter()
        .map(|h| h.trim_start_matches('.').to_ascii_lowercase())
        .any(|h| !h.is_empty() && (host == h || host.ends_with(&format!(".{h}"))))
}

impl Node {
    pub fn open(dir: &Path) -> Result<Self> {
        let config = Config::load(dir)?;
        let key = config::load_key(dir)?;
        let store = Store::open(dir).context("opening store")?;
        let normalizer = Normalizer::new(config.rules.clone())?;
        let http = HttpCapturer::new(config.http())?;
        let net = httpc::Http::new(
            config.network.allow_private_peers,
            config.capture.use_system_proxy,
        )?;
        let asn_db = config
            .quorum
            .asn_db
            .as_deref()
            .map(vantage::AsnDb::load)
            .transpose()?;
        let placeholder = keepword_core::statement::Signed::sign(
            keepword_core::net::Descriptor {
                key: key.public(),
                endpoint: None,
                vantage: Default::default(),
                issued_at_ms: 0,
                software: String::new(),
            },
            &key,
        )?;
        let mut node = Node {
            dir: dir.to_path_buf(),
            config,
            key,
            store,
            normalizer,
            http,
            net,
            asn_db,
            descriptor: Mutex::new(placeholder),
            seen_envelopes: Mutex::new(HashMap::new()),
            sched: Mutex::new(Default::default()),
            limits: Mutex::new(Default::default()),
        };
        node.descriptor = Mutex::new(node.build_descriptor()?);
        Ok(node)
    }

    pub fn init(dir: &Path, config: &Config) -> Result<Keypair> {
        // Before anything is written: a node whose config doesn't load
        // can't be fixed with `keepword config`, nor initialized again.
        config.validate()?;
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
        // Fetched before the page, so the capture provably happened after it.
        let beacon = self.capture_beacon().await;
        let captured = if render {
            self.render(&url).await?
        } else {
            self.http.capture(&url).await?
        };
        self.commit(captured, beacon)
    }

    #[cfg(feature = "render")]
    async fn render(&self, url: &Url) -> Result<Captured> {
        // Chromium resolves hosts itself, so the capturer's resolver can't
        // protect it. Check the page's own address here; sub-resources and
        // DNS rebinding are why network requests only render when the
        // operator opts in (network.render_requests).
        if !self.config.capture.allow_private_addresses {
            let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
            let port = url.port_or_known_default().unwrap_or(443);
            let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
            if let Some(a) = addrs
                .iter()
                .find(|a| !keepword_capture::netpolicy::is_public(a.ip()))
            {
                bail!(
                    "{host} resolves to {}, which is not a public address",
                    a.ip()
                );
            }
        }
        let cfg = keepword_capture::RenderConfig {
            executable: self.config.capture.chrome.clone(),
            user_agent: self.config.capture.user_agent.clone(),
            ..Default::default()
        };
        Ok(keepword_capture::RenderCapturer::new(cfg)
            .capture(url)
            .await?)
    }

    #[cfg(not(feature = "render"))]
    async fn render(&self, _url: &Url) -> Result<Captured> {
        bail!("this build has no headless browser support; rebuild with `--features render`")
    }

    /// Sign, store and log a capture, then compare it with the previous one.
    pub fn commit(
        &self,
        c: Captured,
        beacon: Option<keepword_core::beacon::Beacon>,
    ) -> Result<Outcome> {
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
            beacon,
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
        if !keepword_core::quorum::comparable(a, b) {
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
        if silent {
            self.raise_alert(
                keepword_core::net::AlertKind::SilentEdit,
                Some(&b.url),
                summary.clone(),
                vec![prev.id, cur.id],
            )?;
        }
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
        let log_size = self.store.with_merkle(|m| m.len())? as u64;
        // Prefer the largest tree head other witnesses have cosigned; the
        // latest head is usually too new to have cosignatures yet.
        let cosigned = self
            .store
            .cosigned_sizes(&self.key.public())?
            .into_iter()
            .filter(|(size, _)| *size > rec.leaf_index && *size <= log_size)
            .find_map(|(size, _)| self.store.tree_head_at(size).ok().flatten())
            .filter(|h| !self.store.cosigs_for(h).unwrap_or_default().is_empty());
        let head = match cosigned {
            Some(h) => h,
            None => self
                .store
                .latest_tree_head()?
                .ok_or_else(|| anyhow!("log is empty"))?,
        };
        let size = head.head.size as usize;
        let proof = self
            .store
            .with_merkle(|m| m.inclusion_proof(size, rec.leaf_index as usize))?
            .ok_or_else(|| anyhow!("record is not in the latest tree head"))?;
        let mut b = Bundle::new(rec.signed.clone());
        let cosignatures = self.store.cosigs_for(&head)?;
        b.inclusion = Some(keepword_core::bundle::Inclusion {
            leaf_index: rec.leaf_index,
            proof,
            tree_head: head,
            cosignatures,
        });
        self.attach_anchor(&mut b, rec.leaf_index)?;
        if let Some(receipt) = self.store.tlsn_for(&rec.id)? {
            let received_b64 = if with_content {
                self.store
                    .blobs
                    .get(&receipt.body.received_hash)?
                    .map(|b| Content::encode(&b))
            } else {
                None
            };
            b.tlsn = Some(keepword_core::bundle::TlsnEvidence {
                receipt,
                received_b64,
            });
        }
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
        (keepword_normalize::profile(rules) == n.profile)
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
        if keepword_normalize::profile(rules.as_ref()) != n.profile {
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
        let out = keepword_normalize::normalize_with(
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

        // A head per capture: roots and proofs from the whole log each time
        // would take time in the square of its size.
        let mut tree = merkle::MerkleCache::new();
        for leaf in &leaves {
            tree.push(*leaf);
        }
        let mut bad_heads = 0;
        for (i, h) in heads.iter().enumerate() {
            let ok = h.verify().is_ok()
                && h.head.log == me
                && tree.root(h.head.size as usize) == Some(h.head.root);
            if !ok {
                bad_heads += 1;
            }
            if let Some(next) = heads.get(i + 1) {
                // None, when leaves are missing: that head is bad already.
                let proof = tree
                    .consistency_proof(h.head.size as usize, next.head.size as usize)
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
