//! Diffs between normalized captures, and silent-edit classification.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

/// Phrases publishers use to flag an edit. If an edit adds none of these and
/// doesn't move the machine-readable modification date, it is "silent".
static UPDATE_NOTICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(\b(updated?|last modified|zuletzt (geändert|aktualisiert)|correction|corrected|clarification|editor'?s note|this (article|story|post) (has been|was) (updated|amended|changed)|aktualisiert|aktualisierung|korrektur|berichtigung|richtigstellung|anmerkung der redaktion|in einer früheren version|mise à jour|rectificatif)\b|\b(update|stand):)",
    )
    .expect("valid regex")
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Disclosure {
    /// The page itself signals the change.
    Disclosed { reasons: Vec<String> },
    /// Content changed with no visible or machine-readable notice.
    Silent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    pub added: usize,
    pub removed: usize,
    pub disclosure: Disclosure,
    /// Unified diff of the normalized text.
    pub unified: String,
    /// Line-level operations for rendering.
    pub ops: Vec<Op>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Op {
    pub tag: OpTag,
    pub line: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpTag {
    Equal,
    Insert,
    Delete,
}

impl Change {
    pub fn is_silent(&self) -> bool {
        self.disclosure == Disclosure::Silent
    }

    pub fn summary(&self) -> String {
        let kind = match &self.disclosure {
            Disclosure::Silent => "silent edit".to_string(),
            Disclosure::Disclosed { reasons } => format!("disclosed edit ({})", reasons.join("; ")),
        };
        format!("{kind}: +{} -{} lines", self.added, self.removed)
    }
}

/// Diff two normalized texts. Returns `None` when they are identical.
pub fn diff(old: &str, new: &str) -> Option<Change> {
    if old == new {
        return None;
    }
    let td = TextDiff::from_lines(old, new);
    let mut ops = Vec::new();
    let (mut added, mut removed) = (0, 0);
    let mut reasons = Vec::new();
    for c in td.iter_all_changes() {
        let line = c.value().trim_end_matches('\n').to_string();
        let tag = match c.tag() {
            ChangeTag::Equal => OpTag::Equal,
            ChangeTag::Insert => {
                added += 1;
                if let Some(date) = line.strip_prefix("modified: ") {
                    reasons.push(format!("modification date now {date}"));
                } else if let Some(m) = UPDATE_NOTICE.find(&line) {
                    reasons.push(format!("notice {:?}", m.as_str()));
                }
                OpTag::Insert
            }
            ChangeTag::Delete => {
                removed += 1;
                OpTag::Delete
            }
        };
        ops.push(Op { tag, line });
    }
    reasons.dedup();
    let disclosure = if reasons.is_empty() {
        Disclosure::Silent
    } else {
        Disclosure::Disclosed { reasons }
    };
    let unified = td
        .unified_diff()
        .context_radius(3)
        .header("before", "after")
        .to_string();
    Some(Change {
        added,
        removed,
        disclosure,
        unified,
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_none() {
        assert!(diff("a\nb\n", "a\nb\n").is_none());
    }

    #[test]
    fn silent_edit() {
        let c = diff("h1: X\np: said yes\n", "h1: X\np: said no\n").unwrap();
        assert!(c.is_silent());
        assert_eq!((c.added, c.removed), (1, 1));
        assert!(c.unified.contains("-p: said yes"));
    }

    #[test]
    fn disclosed_by_notice_or_date() {
        let c = diff("p: a\n", "p: b\np: Update: we corrected the figure.\n").unwrap();
        assert!(!c.is_silent());
        let c = diff("modified: 1\np: a\n", "modified: 2\np: b\n").unwrap();
        assert!(!c.is_silent(), "{c:?}");
        let c = diff("p: a\n", "p: b\np: Dieser Artikel wurde aktualisiert.\n").unwrap();
        assert!(!c.is_silent());
        let c = diff(
            "p: Stand: 27.09.2026 10:15 Uhr\np: a\n",
            "p: Stand: 27.09.2026 11:30 Uhr\np: b\n",
        )
        .unwrap();
        assert!(!c.is_silent(), "{c:?}");
        let c = diff("p: a\n", "p: b\np: UPDATE: figures revised\n").unwrap();
        assert!(!c.is_silent());
    }

    #[test]
    fn removing_a_notice_is_not_disclosure() {
        let c = diff("p: Correction: x\np: a\n", "p: a\n").unwrap();
        assert!(c.is_silent());
    }
}
