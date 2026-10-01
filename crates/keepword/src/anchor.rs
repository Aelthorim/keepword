//! Anchoring tree heads in Bitcoin through OpenTimestamps calendars.

use anyhow::{Context, Result, bail};
use keepword_core::bundle::{Anchor, Bundle, Report, Status, anchor_digest};
use keepword_core::now_ms;
use keepword_core::ots::{self, Attestation, DetachedTimestamp};
use keepword_store::net::AnchorRow;
use serde::Deserialize;

use crate::Node;
use crate::httpc::{Http, join, status_of};

const OTS_ACCEPT: &str = "application/vnd.opentimestamps.v1";
const MAX_OTS: usize = 64 * 1024;

#[derive(Debug, Default, serde::Serialize)]
pub struct UpgradeReport {
    pub checked: usize,
    pub upgraded: usize,
    pub confirmed: usize,
    /// Calendars and explorers that failed; the rest went ahead.
    pub errors: Vec<String>,
}

impl Node {
    /// Submit the latest tree head to the calendars. Returns `None` when it
    /// is already anchored (or the log is empty).
    pub async fn anchor_submit(&self) -> Result<Option<AnchorRow>> {
        let Some(head) = self.store.latest_tree_head()? else {
            return Ok(None);
        };
        if self
            .store
            .anchors()?
            .iter()
            .any(|a| a.size == head.head.size)
        {
            return Ok(None);
        }
        if self.config.anchor.calendars.is_empty() {
            bail!("no OpenTimestamps calendars configured");
        }
        let digest = anchor_digest(&head);
        let mut d = DetachedTimestamp::new(digest);
        let mut errors = Vec::new();
        for cal in &self.config.anchor.calendars {
            let resp = self
                .net
                .post_bytes(&join(cal, "/digest"), digest.to_vec(), OTS_ACCEPT, MAX_OTS)
                .await;
            match resp.and_then(|b| Ok(ots::parse_calendar_response(&digest, &b)?)) {
                Ok(t) => d.timestamp.merge(t)?,
                Err(e) => errors.push(format!("{cal}: {e:#}")),
            }
        }
        if d.timestamp.claims().is_empty() {
            bail!("no calendar accepted the digest: {}", errors.join("; "));
        }
        let row = AnchorRow {
            size: head.head.size,
            head,
            ots: d.to_bytes(),
            status: "pending".into(),
            height: None,
            updated_at: now_ms(),
        };
        self.store.anchor_upsert(&row)?;
        Ok(Some(row))
    }

    /// Ask calendars for completed proofs of pending anchors, and check any
    /// Bitcoin attestation against the chain.
    pub async fn anchor_upgrade(&self) -> Result<UpgradeReport> {
        let mut rep = UpgradeReport::default();
        for mut row in self.store.anchors()? {
            if row.status == "confirmed" {
                continue;
            }
            rep.checked += 1;
            let mut d = DetachedTimestamp::from_bytes(&row.ots)?;
            let mut changed = false;
            // A calendar that can't be reached or answers nonsense only
            // holds up its own proof, not the others' or other anchors'.
            for claim in d.timestamp.claims() {
                let Attestation::Pending { uri } = &claim.attestation else {
                    continue;
                };
                let url = join(uri, &format!("/timestamp/{}", hex::encode(&claim.msg)));
                let upgrade = match self.net.get_bytes(&url, MAX_OTS).await {
                    Ok(body) => {
                        ots::parse_calendar_response(&claim.msg, &body).map_err(anyhow::Error::from)
                    }
                    Err(e) => Err(e),
                };
                match upgrade {
                    Ok(t) => {
                        if let Some(node) = d.timestamp.node_mut(&claim.msg) {
                            node.merge(t)?;
                            changed = true;
                        }
                    }
                    // Not in a block yet.
                    Err(e) if status_of(&e) == Some(404) => {}
                    Err(e) => rep.errors.push(format!("calendar {uri}: {e:#}")),
                }
            }
            if changed {
                rep.upgraded += 1;
                row.ots = d.to_bytes();
            }
            // Keep the completed proof even while the explorer is down.
            if let Some(esplora) = self.config.anchor.esplora() {
                for claim in d.timestamp.claims() {
                    let (Attestation::Bitcoin { height }, Some(root)) =
                        (&claim.attestation, claim.bitcoin_merkle_root_hex())
                    else {
                        continue;
                    };
                    match check_block(&self.net, esplora, *height, &root).await {
                        Ok(true) => {
                            row.status = "confirmed".into();
                            row.height = Some(*height);
                            rep.confirmed += 1;
                            break;
                        }
                        Ok(false) => {}
                        Err(e) => rep.errors.push(format!("block {height}: {e:#}")),
                    }
                }
            }
            row.updated_at = now_ms();
            self.store.anchor_upsert(&row)?;
        }
        Ok(rep)
    }

    /// Attach the best anchor covering this bundle's attestation.
    pub fn attach_anchor(&self, b: &mut Bundle, leaf_index: u64) -> Result<()> {
        let Some(row) = self.store.anchor_covering(leaf_index)? else {
            return Ok(());
        };
        let size = row.size as usize;
        let Some(proof) = self
            .store
            .with_merkle(|m| m.inclusion_proof(size, leaf_index as usize))?
        else {
            return Ok(());
        };
        b.anchor = Some(Anchor {
            tree_head: row.head,
            leaf_index,
            proof,
            ots_b64: keepword_core::bundle::Content::encode(&row.ots),
        });
        Ok(())
    }
}

#[derive(Deserialize)]
struct EsploraBlock {
    merkle_root: String,
}

/// Does block `height` have this Merkle root (explorer byte order)?
pub async fn check_block(
    http: &Http,
    esplora: &str,
    height: u64,
    merkle_root_hex: &str,
) -> Result<bool> {
    let hash = http
        .get_bytes(&join(esplora, &format!("/block-height/{height}")), 1024)
        .await
        .context("looking up block hash")?;
    let hash = String::from_utf8_lossy(&hash).trim().to_string();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("explorer returned a malformed block hash");
    }
    let block: EsploraBlock = http
        .get_json(&join(esplora, &format!("/block/{hash}")))
        .await?;
    Ok(block.merkle_root.eq_ignore_ascii_case(merkle_root_hex))
}

/// Check a bundle's Bitcoin anchor against a block explorer and add the
/// result to the report.
pub async fn verify_anchor_online(http: &Http, esplora: &str, b: &Bundle, report: &mut Report) {
    let Some(anchor) = &b.anchor else { return };
    let Ok(claims) = anchor.claims() else { return };
    let btc: Vec<(u64, String)> = claims
        .iter()
        .filter_map(|c| match c.attestation {
            Attestation::Bitcoin { height } => Some((height, c.bitcoin_merkle_root_hex()?)),
            _ => None,
        })
        .collect();
    if btc.is_empty() {
        return;
    }
    for (height, root) in &btc {
        match check_block(http, esplora, *height, root).await {
            Ok(true) => {
                report.push(
                    "bitcoin",
                    Status::Pass,
                    format!("tree head existed by Bitcoin block {height}"),
                );
                return;
            }
            Ok(false) => {}
            Err(e) => {
                report.push(
                    "bitcoin",
                    Status::Skip,
                    format!("could not reach explorer: {e:#}"),
                );
                return;
            }
        }
    }
    report.push(
        "bitcoin",
        Status::Fail,
        "no claimed block has the committed Merkle root",
    );
}
