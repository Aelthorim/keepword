//! Node configuration (`witness.toml`) and key file.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use witness_capture::HttpConfig;
use witness_core::{Keypair, Vantage};
use witness_normalize::SiteRules;

pub const CONFIG_FILE: &str = "witness.toml";

/// Witnesses a new node dials to join the public network when it knows
/// few peers. Any witness works as a seed; these are ones run by the
/// project. After joining, a node learns the rest through gossip.
pub const DEFAULT_SEEDS: &[&str] = &["https://w1.kxnode.net"];
pub const KEY_FILE: &str = "witness.key";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub vantage: VantageConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub content: ContentConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub beacon: BeaconConfig,
    #[serde(default)]
    pub quorum: QuorumConfig,
    #[serde(default)]
    pub anchor: AnchorConfig,
    /// Per-site normalization rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SiteRules>,
}

/// Federation with other witnesses (docs/DESIGN.md §6).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    /// Public base URL of this node's API. Leave unset for a node that can't
    /// accept connections; it still pushes and pulls but isn't mirrored.
    pub endpoint: Option<String>,
    /// Peer base URLs to bootstrap from, in addition to the default seeds.
    pub peers: Vec<String>,
    /// Also bootstrap from the project's default seeds (`DEFAULT_SEEDS`).
    /// Turn off to run a separate network. Never used together with
    /// `allow_private_peers`, so a LAN test network stays private.
    pub seeds: bool,
    pub sync_interval_secs: u64,
    /// Witnesses assigned per watch request.
    pub replication: usize,
    pub max_per_country: usize,
    /// Max active watch requests accepted from one requester.
    pub max_requests_per_requester: u64,
    pub max_peers: usize,
    /// Peers exchanged gossip with each round, chosen at random. Every
    /// peer is still reached, over a few hops.
    pub gossip_fanout: usize,
    /// Auditors per log. Each audits the log's checkpoints for consistency
    /// and cosigns them. Must be the same on every witness.
    pub audit_logs: usize,
    /// This node's log publishes a checkpoint (the latest head at the start
    /// of each interval) for auditors to cosign; 0 = every head.
    pub checkpoint_interval_secs: u64,
    /// How often this node audits and cosigns each log it audits.
    pub cosign_interval_secs: u64,
    /// Serve raw blobs to peers, for these hosts only (and their subdomains).
    pub serve_content_hosts: Vec<String>,
    /// Use the last X-Forwarded-For address, the one your proxy added, as
    /// the client IP (only behind a reverse proxy you control). Only taken
    /// from connections from this machine or a private network, where
    /// such a proxy sits.
    pub trust_forwarded_for: bool,
    /// Let peers and network services (drand, calendars, Esplora) be on
    /// private addresses. Peer endpoints come from untrusted descriptors, so
    /// only enable this for a closed network on a LAN.
    pub allow_private_peers: bool,
    /// Never capture these hosts (and their subdomains) for network
    /// requests, e.g. for legal reasons. Requests are still relayed.
    pub decline_hosts: Vec<String>,
    /// Render network requests that ask for it in the headless browser.
    /// Chromium resolves sub-resources itself, past this node's
    /// public-address checks, so only enable it with the browser sandboxed
    /// away from your LAN.
    pub render_requests: bool,
    /// Most URLs this node captures for the network at once.
    pub max_request_watches: usize,
    /// Requests per minute the public API answers from one address (an
    /// IPv6 /64 counts as one), in bursts of up to as many; 0 = no limit.
    /// Addresses on this machine or a private network aren't limited unless
    /// `trust_forwarded_for` reveals the real client behind them.
    pub api_requests_per_minute: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            endpoint: None,
            peers: vec![],
            seeds: true,
            sync_interval_secs: 60,
            replication: 5,
            max_per_country: 2,
            max_requests_per_requester: 50,
            max_peers: 2000,
            gossip_fanout: 16,
            audit_logs: 16,
            checkpoint_interval_secs: 3600,
            cosign_interval_secs: 3600,
            serve_content_hosts: vec![],
            trust_forwarded_for: false,
            allow_private_peers: false,
            decline_hosts: vec![],
            render_requests: false,
            max_request_watches: 200,
            api_requests_per_minute: 600,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BeaconConfig {
    /// drand HTTP API base; beacons can also arrive over gossip. Set to ""
    /// to disable.
    pub drand_url: Option<String>,
    /// Without a beacon, assignment falls back to a predictable seed. Only
    /// acceptable for private test networks.
    pub allow_insecure_seed: bool,
}

impl BeaconConfig {
    /// The drand API, unless disabled (`drand_url = ""`).
    pub fn drand(&self) -> Option<&str> {
        self.drand_url.as_deref().filter(|u| !u.is_empty())
    }
}

impl Default for BeaconConfig {
    fn default() -> Self {
        BeaconConfig {
            drand_url: Some("https://api.drand.sh".into()),
            allow_insecure_seed: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QuorumConfig {
    pub window_secs: u64,
    pub min_asns: usize,
    pub min_dissent_asns: usize,
    /// ip2asn-combined.tsv from iptoasn.com, for corroborating vantage.
    pub asn_db: Option<PathBuf>,
    /// Independent observer networks needed to corroborate a witness's
    /// location this node hasn't seen connect itself (see docs/DESIGN.md
    /// §6.3).
    pub min_observers: usize,
    /// Count self-reported ASNs. Only for test networks.
    pub trust_self_reported: bool,
    /// Rechecks drawn per country when witnesses disagree. Must be the same
    /// on every witness.
    pub recheck_size: usize,
    /// Independent networks that must reproduce a version for it to count.
    pub recheck_quorum: usize,
    /// How long after a disputed round rechecks may run.
    pub recheck_secs: u64,
    /// A split alert needs this many confirmed splits…
    pub split_confirmations: usize,
    /// …among this many most recent settled rounds.
    pub split_rounds: usize,
    /// Most rechecks this node captures per hour.
    pub max_rechecks_per_hour: u64,
    /// Witnesses connecting from a network prefix (/24, /48) whose claims
    /// failed rechecks this often in a week are left out of verdicts.
    pub max_failed_claims: u64,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        QuorumConfig {
            window_secs: 600,
            min_asns: 3,
            min_dissent_asns: 2,
            asn_db: None,
            min_observers: 2,
            trust_self_reported: false,
            recheck_size: 5,
            recheck_quorum: 3,
            recheck_secs: 1800,
            split_confirmations: 3,
            split_rounds: 4,
            max_rechecks_per_hour: 30,
            max_failed_claims: 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnchorConfig {
    /// OpenTimestamps calendars; empty disables anchoring.
    pub calendars: Vec<String>,
    /// Esplora-compatible API for checking Bitcoin block headers ("" to
    /// disable).
    pub esplora_url: Option<String>,
    pub interval_secs: u64,
}

impl AnchorConfig {
    pub fn esplora(&self) -> Option<&str> {
        self.esplora_url.as_deref().filter(|u| !u.is_empty())
    }
}

impl Default for AnchorConfig {
    fn default() -> Self {
        AnchorConfig {
            calendars: vec![
                "https://a.pool.opentimestamps.org".into(),
                "https://b.pool.opentimestamps.org".into(),
                "https://a.pool.eternitywall.com".into(),
            ],
            esplora_url: Some("https://blockstream.info/api".into()),
            interval_secs: 3600,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VantageConfig {
    /// Autonomous system this node fetches from, e.g. 3320 for Deutsche Telekom.
    pub asn: Option<u32>,
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureConfig {
    pub user_agent: Option<String>,
    pub timeout_secs: u64,
    pub max_body_mib: usize,
    pub use_system_proxy: bool,
    pub allow_private_addresses: bool,
    /// Chrome/Chromium binary for rendered captures.
    pub chrome: Option<PathBuf>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            user_agent: None,
            timeout_secs: 30,
            max_body_mib: 32,
            use_system_proxy: false,
            allow_private_addresses: false,
            chrome: None,
        }
    }
}

/// What this node keeps after capturing. Hashes, attestations and the log
/// are always kept; they contain no page content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Retain {
    /// Headers, raw body and normalized text: full evidence and diffs.
    Full,
    /// Headers and normalized text only: diffs work, raw bytes are dropped.
    Normalized,
    /// Nothing but hashes: edits are detected but can't be shown.
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ContentConfig {
    pub retain: Retain,
}

impl Default for ContentConfig {
    fn default() -> Self {
        ContentConfig {
            retain: Retain::Full,
        }
    }
}

impl NetworkConfig {
    /// The peers to bootstrap from: `peers`, plus the default seeds unless
    /// disabled or this is a private network.
    pub fn bootstrap(&self) -> Vec<String> {
        let own = self
            .endpoint
            .as_deref()
            .map(|e| e.trim_end_matches('/').to_string());
        let mut out: Vec<String> = self.peers.clone();
        if self.seeds && !self.allow_private_peers {
            out.extend(DEFAULT_SEEDS.iter().map(|s| s.to_string()));
        }
        let mut seen = std::collections::HashSet::new();
        out.retain(|p| {
            let p = p.trim_end_matches('/').to_string();
            Some(&p) != own.as_ref() && seen.insert(p)
        });
        out
    }
}

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(CONFIG_FILE);
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading {} (run `witness init` first?)", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(c) = &self.vantage.country {
            if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_uppercase()) {
                bail!("vantage.country must be an upper-case ISO 3166 code like \"DE\"");
            }
        }
        for (name, url) in [
            ("network.endpoint", self.network.endpoint.as_deref()),
            ("beacon.drand_url", self.beacon.drand()),
            ("anchor.esplora_url", self.anchor.esplora()),
        ] {
            if let Some(u) = url {
                let ok =
                    url::Url::parse(u).is_ok_and(|u| u.scheme() == "http" || u.scheme() == "https");
                if !ok {
                    bail!("{name} must be an http(s) URL, got {u:?}");
                }
            }
        }
        Ok(())
    }

    /// Read a setting by dotted path, e.g. `network.endpoint`.
    pub fn get_path(&self, key: &str) -> Result<serde_json::Value> {
        let mut v = serde_json::to_value(self)?;
        for part in key.split('.') {
            v = v
                .get(part)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no setting {key:?}"))?;
        }
        Ok(v)
    }

    /// Set a setting by dotted path. `raw` is read as a TOML value
    /// (`true`, `3`, `["a", "b"]`, `"text"`); anything that isn't one is
    /// taken as a string. `None` unsets it. The result must still be a valid
    /// configuration, so typos and wrong types are rejected.
    pub fn set_path(&mut self, key: &str, raw: Option<&str>) -> Result<()> {
        let value = match raw {
            None => serde_json::Value::Null,
            Some(r) => match toml::from_str::<toml::Table>(&format!("v = {r}")) {
                Ok(mut t) => serde_json::to_value(t.remove("v").expect("parsed key"))?,
                Err(_) => serde_json::Value::String(r.to_string()),
            },
        };
        let mut root = serde_json::to_value(&*self)?;
        let mut cur = &mut root;
        let parts: Vec<&str> = key.split('.').collect();
        for (i, part) in parts.iter().enumerate() {
            let obj = cur
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("{key:?} is not a setting"))?;
            if i + 1 == parts.len() {
                obj.insert(part.to_string(), value);
                break;
            }
            cur = obj
                .get_mut(*part)
                .ok_or_else(|| anyhow::anyhow!("no setting section {part:?}"))?;
        }
        let updated: Config =
            serde_json::from_value(root).with_context(|| format!("invalid value for {key}"))?;
        updated.validate()?;
        *self = updated;
        Ok(())
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self)?;
        fs::write(dir.join(CONFIG_FILE), text)?;
        Ok(())
    }

    pub fn vantage(&self) -> Vantage {
        Vantage {
            asn: self.vantage.asn,
            country: self.vantage.country.clone(),
        }
    }

    pub fn http(&self) -> HttpConfig {
        let mut h = HttpConfig {
            timeout: Duration::from_secs(self.capture.timeout_secs),
            max_body_bytes: self.capture.max_body_mib * 1024 * 1024,
            use_system_proxy: self.capture.use_system_proxy,
            allow_private: self.capture.allow_private_addresses,
            ..HttpConfig::default()
        };
        if let Some(ua) = &self.capture.user_agent {
            h.user_agent = ua.clone();
        }
        h
    }
}

pub fn create_key(dir: &Path) -> Result<Keypair> {
    let path = dir.join(KEY_FILE);
    if path.exists() {
        bail!(
            "{} already exists; refusing to overwrite a witness identity",
            path.display()
        );
    }
    let kp = Keypair::generate()?;
    write_private(&path, format!("{}\n", hex_encode(&kp.seed())).as_bytes())?;
    Ok(kp)
}

pub fn load_key(dir: &Path) -> Result<Keypair> {
    let path = dir.join(KEY_FILE);
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = hex_decode(text.trim()).context("key file is not hex")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must hold 32 bytes"))?;
    Ok(Keypair::from_seed(&seed))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../docs/witness.example.toml");
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.vantage.asn, Some(3320));
        assert_eq!(cfg.rules.len(), 1);
        assert!(cfg.beacon.drand().is_some());
        let off: Config = toml::from_str("[beacon]\ndrand_url = \"\"\n").unwrap();
        assert!(off.beacon.drand().is_none());
    }

    #[test]
    fn bootstrap_list() {
        let mut n = NetworkConfig {
            endpoint: Some("https://me.example/".into()),
            peers: vec![
                "https://a.example".into(),
                "https://a.example/".into(),
                "https://me.example".into(),
            ],
            ..Default::default()
        };
        let with_seeds = n.bootstrap();
        assert_eq!(with_seeds[0], "https://a.example");
        assert_eq!(with_seeds.len(), 1 + DEFAULT_SEEDS.len());
        n.seeds = false;
        assert_eq!(n.bootstrap(), vec!["https://a.example".to_string()]);
        // A private network never dials the public seeds.
        n.seeds = true;
        n.allow_private_peers = true;
        assert_eq!(n.bootstrap(), vec!["https://a.example".to_string()]);
    }

    #[test]
    fn set_and_get_paths() {
        let mut c = Config::default();
        c.set_path("network.endpoint", Some("https://w.example.org"))
            .unwrap();
        c.set_path(
            "network.peers",
            Some(r#"["https://a.example", "https://b.example"]"#),
        )
        .unwrap();
        c.set_path("vantage.asn", Some("3320")).unwrap();
        c.set_path("vantage.country", Some("DE")).unwrap();
        c.set_path("network.trust_forwarded_for", Some("true"))
            .unwrap();
        c.set_path("content.retain", Some("normalized")).unwrap();
        assert_eq!(c.network.endpoint.as_deref(), Some("https://w.example.org"));
        assert_eq!(c.network.peers.len(), 2);
        assert_eq!(c.vantage.asn, Some(3320));
        assert!(c.network.trust_forwarded_for);
        assert_eq!(c.content.retain, Retain::Normalized);
        assert_eq!(c.get_path("vantage.asn").unwrap(), serde_json::json!(3320));

        // Typos, wrong types and invalid values are rejected and change nothing.
        assert!(c.set_path("network.endpont", Some("x")).is_err());
        assert!(c.set_path("vantage.asn", Some("\"many\"")).is_err());
        assert!(c.set_path("vantage.country", Some("de")).is_err());
        assert!(c.set_path("network.endpoint", Some("ftp://x")).is_err());
        assert!(c.set_path("nosuch.key", Some("1")).is_err());
        assert_eq!(c.vantage.asn, Some(3320));

        c.set_path("network.endpoint", None).unwrap();
        assert!(c.network.endpoint.is_none());
        // Round-trips through the file format.
        let back: Config = toml::from_str(&toml::to_string_pretty(&c).unwrap()).unwrap();
        assert_eq!(back.vantage.asn, Some(3320));
    }
}
