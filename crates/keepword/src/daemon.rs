//! Background loops for `keepword serve`.

use std::sync::Arc;
use std::time::Duration;

use keepword_core::format_ms;
use keepword_core::now_ms;

use crate::Node;

pub async fn federation_loop(node: Arc<Node>, log: impl Fn(String)) -> anyhow::Result<()> {
    let every = Duration::from_secs(node.config.network.sync_interval_secs.max(5));
    loop {
        match node.sync().await {
            Ok(r) => {
                if r.new_attestations > 0 || r.gossip_in > 0 || !r.errors.is_empty() {
                    log(format!(
                        "{}  sync: {}/{} peers, {} new attestations, {} messages in",
                        format_ms(now_ms()),
                        r.synced,
                        r.peers,
                        r.new_attestations,
                        r.gossip_in
                    ));
                }
                for (who, e) in r.errors {
                    log(format!("  peer {who}: {e}"));
                }
            }
            Err(e) => log(format!("{}  sync failed: {e:#}", format_ms(now_ms()))),
        }
        tokio::time::sleep(every).await;
    }
}

pub async fn anchor_loop(node: Arc<Node>, log: impl Fn(String)) -> anyhow::Result<()> {
    let every = Duration::from_secs(node.config.anchor.interval_secs.max(60));
    loop {
        match node.anchor_submit().await {
            Ok(Some(a)) => log(format!(
                "{}  anchored tree head of size {}",
                format_ms(now_ms()),
                a.size
            )),
            Ok(None) => {}
            Err(e) => log(format!("{}  anchoring failed: {e:#}", format_ms(now_ms()))),
        }
        match node.anchor_upgrade().await {
            Ok(r) => {
                for e in &r.errors {
                    log(format!("{}  anchor upgrade: {e}", format_ms(now_ms())));
                }
                if r.confirmed > 0 {
                    log(format!(
                        "{}  {} anchors confirmed in Bitcoin",
                        format_ms(now_ms()),
                        r.confirmed
                    ));
                }
            }
            Err(e) => log(format!(
                "{}  anchor upgrade failed: {e:#}",
                format_ms(now_ms())
            )),
        }
        tokio::time::sleep(every).await;
    }
}
