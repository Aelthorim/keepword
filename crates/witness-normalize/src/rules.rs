//! Per-site normalization rules.

use scraper::Selector;
use serde::{Deserialize, Serialize};

/// Extra rules for one host and its subdomains. Rules are part of the
/// normalizer profile that attestations commit to, so changing them yields a
/// new profile rather than silently changing old hashes' meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteRules {
    pub host: String,
    /// CSS selectors for elements to drop (live tickers, comment counts...).
    #[serde(default)]
    pub remove: Vec<String>,
    /// CSS selector for the content root, when `<main>` / `<article>`
    /// detection picks the wrong element.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid CSS selector {selector:?} in rules for {host}")]
pub struct RuleError {
    pub host: String,
    pub selector: String,
}

impl SiteRules {
    pub fn validate(&self) -> Result<(), RuleError> {
        for s in self.remove.iter().chain(self.root.iter()) {
            Selector::parse(s).map_err(|_| RuleError {
                host: self.host.clone(),
                selector: s.clone(),
            })?;
        }
        Ok(())
    }

    pub fn matches(&self, host: &str) -> bool {
        let want = self.host.trim_start_matches('.').to_ascii_lowercase();
        host == want || host.ends_with(&format!(".{want}"))
    }

    pub(crate) fn remove_selectors(&self) -> impl Iterator<Item = Selector> + '_ {
        self.remove.iter().filter_map(|s| Selector::parse(s).ok())
    }

    pub(crate) fn root_selector(&self) -> Option<Selector> {
        self.root.as_deref().and_then(|s| Selector::parse(s).ok())
    }
}
