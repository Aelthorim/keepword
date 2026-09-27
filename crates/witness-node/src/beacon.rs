//! Fetching drand beacons. Beacons verify offline, so they are also shared
//! over gossip: a node without drand access can use one a peer fetched.

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use witness_core::beacon::{self, Beacon, QUICKNET_CHAIN_HASH};
use witness_core::net::Gossip;
use witness_core::{Digest, now_ms};

use crate::Node;
use crate::httpc::join;

#[derive(Deserialize)]
struct DrandResponse {
    round: u64,
    signature: String,
    #[serde(default)]
    randomness: Option<String>,
}

/// A beacon newer than this is reused for captures instead of fetching.
const FRESH_MS: i64 = 60_000;

impl Node {
    /// Fetch and verify a quicknet beacon (`None` = latest).
    pub async fn fetch_beacon(&self, round: Option<u64>) -> Result<Beacon> {
        let base = self
            .config
            .beacon
            .drand()
            .ok_or_else(|| anyhow!("no drand_url configured"))?;
        let which = round.map_or("latest".to_string(), |r| r.to_string());
        let r: DrandResponse = self
            .net
            .get_json(&join(
                base,
                &format!("{QUICKNET_CHAIN_HASH}/public/{which}"),
            ))
            .await?;
        let b = Beacon {
            round: r.round,
            signature: hex::decode(&r.signature)?,
        };
        b.verify()
            .map_err(|_| anyhow!("drand returned a beacon that does not verify"))?;
        if round.is_some_and(|want| want != b.round) {
            bail!(
                "drand returned round {} instead of {}",
                b.round,
                round.unwrap_or_default()
            );
        }
        if r.randomness.is_some_and(|x| x != b.randomness().to_hex()) {
            bail!("drand randomness does not match its signature");
        }
        self.store.beacon_insert(&b)?;
        self.publish(Gossip::Beacon(b.clone()))?;
        Ok(b)
    }

    /// The beacon to embed in a capture: a fresh stored one, a newly fetched
    /// one, or the newest stored one if drand is unreachable.
    pub async fn capture_beacon(&self) -> Option<Beacon> {
        let now = now_ms();
        let stored = self.store.beacon_latest().ok().flatten();
        if let Some(b) = &stored {
            if now - b.time_ms() <= FRESH_MS && b.time_ms() <= now {
                return stored;
            }
        }
        if self.config.beacon.drand().is_some() {
            if let Ok(b) = self.fetch_beacon(None).await {
                if b.time_ms() <= now + FRESH_MS {
                    return Some(b);
                }
            }
        }
        stored.filter(|b| b.time_ms() <= now)
    }

    /// The assignment seed for an epoch, fetching its beacon if needed.
    pub async fn epoch_seed(&self, epoch: u64) -> Result<(Digest, bool)> {
        let round = beacon::epoch_round(epoch);
        if self.store.beacon(round)?.is_none()
            && beacon::round_time_ms(round) <= now_ms()
            && self.config.beacon.drand().is_some()
        {
            let _ = self.fetch_beacon(Some(round)).await;
        }
        self.epoch_seed_cached(epoch)
    }
}
