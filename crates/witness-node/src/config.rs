//! Node configuration (`witness.toml`) and key file.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use witness_capture::HttpConfig;
use witness_core::{Keypair, Vantage};
use witness_normalize::SiteRules;

pub const CONFIG_FILE: &str = "witness.toml";
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
    /// Per-site normalization rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SiteRules>,
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

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(CONFIG_FILE);
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading {} (run `witness init` first?)", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if let Some(c) = &cfg.vantage.country {
            if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_uppercase()) {
                bail!("vantage.country must be an upper-case ISO 3166 code like \"DE\"");
            }
        }
        Ok(cfg)
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
