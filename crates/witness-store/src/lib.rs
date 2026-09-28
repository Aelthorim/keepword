//! Local storage for a witness node: blobs on disk, an SQLite index, and the
//! append-only Merkle log of attestation IDs.

pub mod blobs;
pub mod net;

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use witness_core::{
    CaptureMethod, Digest, Keypair, SignedAttestation, SignedTreeHead, TreeHead, merkle,
};

pub use blobs::BlobStore;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("corrupt store: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Protocol(#[from] witness_core::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

const SCHEMA_VERSION: i64 = 3;

const SCHEMA: &str = r#"
CREATE TABLE attestations (
    id           BLOB PRIMARY KEY,
    url          TEXT NOT NULL,
    fetched_at   INTEGER NOT NULL,
    method       INTEGER NOT NULL,
    comparison   BLOB NOT NULL,
    body_hash    BLOB NOT NULL,
    headers_hash BLOB NOT NULL,
    norm_hash    BLOB,
    json         TEXT NOT NULL
);
CREATE INDEX attestations_url ON attestations(url, fetched_at);

-- Append-only. Leaves are attestation IDs, so erasing an attestation row
-- leaves the log intact.
CREATE TABLE log_leaves (
    idx INTEGER PRIMARY KEY,
    id  BLOB NOT NULL UNIQUE
);

CREATE TABLE tree_heads (
    size INTEGER PRIMARY KEY,
    json TEXT NOT NULL
);

CREATE TABLE watch (
    url         TEXT PRIMARY KEY,
    every_secs  INTEGER NOT NULL,
    render      INTEGER NOT NULL DEFAULT 0,
    added_at    INTEGER NOT NULL,
    last_run    INTEGER,
    last_error  TEXT
);

CREATE TABLE changes (
    seq         INTEGER PRIMARY KEY,
    url         TEXT NOT NULL,
    from_id     BLOB NOT NULL,
    to_id       BLOB NOT NULL,
    detected_at INTEGER NOT NULL,
    silent      INTEGER NOT NULL,
    added       INTEGER NOT NULL,
    removed     INTEGER NOT NULL,
    summary     TEXT NOT NULL
);
CREATE INDEX changes_url ON changes(url, detected_at);
"#;

/// A stored attestation with its position in the log.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub id: Digest,
    pub leaf_index: u64,
    pub signed: SignedAttestation,
}

#[derive(Clone, Debug, Serialize)]
pub struct Watch {
    pub url: String,
    pub every_secs: u64,
    pub render: bool,
    pub added_at: i64,
    pub last_run: Option<i64>,
    pub last_error: Option<String>,
    /// Set when the watch exists because the network assigned this node a
    /// watch request; such watches expire with the request.
    pub request_id: Option<Digest>,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChangeRow {
    pub seq: i64,
    pub url: String,
    pub from_id: Digest,
    pub to_id: Digest,
    pub detected_at: i64,
    pub silent: bool,
    pub added: u64,
    pub removed: u64,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UrlSummary {
    pub url: String,
    pub captures: u64,
    pub versions: u64,
    pub last_capture: i64,
    pub changes: u64,
    pub silent_changes: u64,
}

pub struct Store {
    db: Mutex<Connection>,
    pub blobs: BlobStore,
}

pub(crate) fn digest(row: &Row<'_>, i: usize) -> rusqlite::Result<Digest> {
    let b: Vec<u8> = row.get(i)?;
    Digest::from_slice(&b).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Blob, "digest".into())
    })
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let conn = Connection::open(dir.join("index.sqlite"))?;
        // `witness serve` and CLI commands may share a data directory.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // Gossip and mirroring write a lot; NORMAL is crash-safe in WAL mode
        // and only risks the last transactions on power loss. Log appends
        // switch to FULL (see `commit`).
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match v {
            0..=2 => {
                let tx = conn.unchecked_transaction()?;
                if v == 0 {
                    tx.execute_batch(SCHEMA)?;
                }
                if v <= 1 {
                    tx.execute_batch(net::SCHEMA_V2)?;
                }
                tx.execute_batch(net::SCHEMA_V3)?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                tx.commit()?;
            }
            SCHEMA_VERSION => {}
            other => {
                return Err(StoreError::Corrupt(format!(
                    "index schema version {other} is newer than this build supports"
                )));
            }
        }
        Ok(Store {
            db: Mutex::new(conn),
            blobs: BlobStore::open(dir.join("blobs"))?,
        })
    }

    pub(crate) fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Index an attestation, append it to the log and sign the new tree head,
    /// all in one transaction.
    pub fn commit(
        &self,
        sa: &SignedAttestation,
        key: &Keypair,
        now_ms: i64,
    ) -> Result<(Record, SignedTreeHead)> {
        sa.verify()?;
        let id = sa.id();
        let mut db = self.db();
        // A tree head is published as soon as it is signed. Losing it to a
        // power cut and later signing a different head of the same size would
        // look exactly like equivocation, so log appends are fully durable.
        db.pragma_update(None, "synchronous", "FULL")?;
        let result = Self::commit_tx(&mut db, sa, &id, key, now_ms);
        db.pragma_update(None, "synchronous", "NORMAL")?;
        result
    }

    fn commit_tx(
        db: &mut Connection,
        sa: &SignedAttestation,
        id: &Digest,
        key: &Keypair,
        now_ms: i64,
    ) -> Result<(Record, SignedTreeHead)> {
        let a = &sa.attestation;
        let id = *id;
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO attestations (id, url, fetched_at, method, comparison, body_hash, headers_hash, norm_hash, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id.as_bytes(),
                a.url,
                a.fetched_at_ms,
                a.method.code(),
                a.comparison_hash().as_bytes(),
                a.body_hash.as_bytes(),
                a.headers_hash.as_bytes(),
                a.norm.map(|n| n.hash.0.to_vec()),
                serde_json::to_string(sa)?,
            ],
        )?;
        let size: i64 = tx.query_row("SELECT COUNT(*) FROM log_leaves", [], |r| r.get(0))?;
        tx.execute(
            "INSERT INTO log_leaves (idx, id) VALUES (?1, ?2)",
            params![size, id.as_bytes()],
        )?;
        let leaves = load_leaves(&tx)?;
        let head = TreeHead {
            log: key.public(),
            size: leaves.len() as u64,
            root: merkle::root(&leaves),
            timestamp_ms: now_ms.max(a.fetched_at_ms),
        }
        .sign(key)?;
        tx.execute(
            "INSERT INTO tree_heads (size, json) VALUES (?1, ?2)",
            params![head.head.size as i64, serde_json::to_string(&head)?],
        )?;
        tx.commit()?;
        Ok((
            Record {
                id,
                leaf_index: size as u64,
                signed: sa.clone(),
            },
            head,
        ))
    }

    /// Leaf hashes of the whole log, in order.
    pub fn leaves(&self) -> Result<Vec<Digest>> {
        load_leaves(&self.db())
    }

    /// Attestation IDs at log positions `start..end`.
    pub fn leaf_ids_range(&self, start: u64, end: u64) -> Result<Vec<Digest>> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT id FROM log_leaves WHERE idx >= ?1 AND idx < ?2 ORDER BY idx")?;
        let rows = st.query_map(params![start as i64, end as i64], |r| digest(r, 0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// URLs whose captures reference a blob.
    pub fn urls_referencing(&self, d: &Digest) -> Result<Vec<String>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT DISTINCT url FROM attestations WHERE body_hash = ?1 OR headers_hash = ?1 OR norm_hash = ?1",
        )?;
        let rows = st.query_map([d.as_bytes()], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn leaf_index(&self, id: &Digest) -> Result<Option<u64>> {
        Ok(self
            .db()
            .query_row(
                "SELECT idx FROM log_leaves WHERE id = ?1",
                [id.as_bytes()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|i| i as u64))
    }

    pub fn latest_tree_head(&self) -> Result<Option<SignedTreeHead>> {
        let json: Option<String> = self
            .db()
            .query_row(
                "SELECT json FROM tree_heads ORDER BY size DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        json.map(|j| serde_json::from_str(&j).map_err(Into::into))
            .transpose()
    }

    pub fn tree_head_at(&self, size: u64) -> Result<Option<SignedTreeHead>> {
        let json: Option<String> = self
            .db()
            .query_row(
                "SELECT json FROM tree_heads WHERE size = ?1",
                [size as i64],
                |r| r.get(0),
            )
            .optional()?;
        json.map(|j| serde_json::from_str(&j).map_err(Into::into))
            .transpose()
    }

    pub fn tree_heads(&self) -> Result<Vec<SignedTreeHead>> {
        let db = self.db();
        let mut st = db.prepare("SELECT json FROM tree_heads ORDER BY size")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|j| Ok(serde_json::from_str(&j?)?)).collect()
    }

    fn records(&self, sql: &str, p: impl rusqlite::Params) -> Result<Vec<Record>> {
        let db = self.db();
        let mut st = db.prepare(sql)?;
        let rows = st.query_map(p, |r| {
            Ok((digest(r, 0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
        })?;
        rows.map(|row| {
            let (id, idx, json) = row?;
            Ok(Record {
                id,
                leaf_index: idx as u64,
                signed: serde_json::from_str(&json)?,
            })
        })
        .collect()
    }

    const SELECT: &'static str =
        "SELECT a.id, l.idx, a.json FROM attestations a JOIN log_leaves l ON l.id = a.id";

    pub fn get(&self, id: &Digest) -> Result<Option<Record>> {
        Ok(self
            .records(
                &format!("{} WHERE a.id = ?1", Self::SELECT),
                [id.as_bytes()],
            )?
            .pop())
    }

    /// Find an attestation by ID prefix (hex), for CLI convenience.
    pub fn find_prefix(&self, prefix: &str) -> Result<Vec<Record>> {
        if prefix.len() < 4 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(vec![]);
        }
        let pattern = format!("{}%", prefix.to_ascii_lowercase());
        self.records(
            &format!("{} WHERE lower(hex(a.id)) LIKE ?1 LIMIT 10", Self::SELECT),
            [pattern],
        )
    }

    /// All captures of a URL, oldest first.
    pub fn history(&self, url: &str) -> Result<Vec<Record>> {
        self.records(
            &format!(
                "{} WHERE a.url = ?1 ORDER BY a.fetched_at, l.idx",
                Self::SELECT
            ),
            [url],
        )
    }

    pub fn latest(&self, url: &str, method: CaptureMethod) -> Result<Option<Record>> {
        Ok(self
            .records(
                &format!(
                    "{} WHERE a.url = ?1 AND a.method = ?2 ORDER BY a.fetched_at DESC, l.idx DESC LIMIT 1",
                    Self::SELECT
                ),
                params![url, method.code()],
            )?
            .pop())
    }

    /// The last capture at or before `at_ms`.
    pub fn at(&self, url: &str, at_ms: i64) -> Result<Option<Record>> {
        Ok(self
            .records(
                &format!(
                    "{} WHERE a.url = ?1 AND a.fetched_at <= ?2 ORDER BY a.fetched_at DESC, l.idx DESC LIMIT 1",
                    Self::SELECT
                ),
                params![url, at_ms],
            )?
            .pop())
    }

    pub fn urls(&self) -> Result<Vec<UrlSummary>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT a.url, COUNT(*), COUNT(DISTINCT a.comparison), MAX(a.fetched_at),
                    (SELECT COUNT(*) FROM changes c WHERE c.url = a.url),
                    (SELECT COUNT(*) FROM changes c WHERE c.url = a.url AND c.silent = 1)
             FROM attestations a GROUP BY a.url ORDER BY MAX(a.fetched_at) DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(UrlSummary {
                url: r.get(0)?,
                captures: r.get::<_, i64>(1)? as u64,
                versions: r.get::<_, i64>(2)? as u64,
                last_capture: r.get(3)?,
                changes: r.get::<_, i64>(4)? as u64,
                silent_changes: r.get::<_, i64>(5)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn record_change(&self, c: &ChangeRow) -> Result<i64> {
        let db = self.db();
        db.execute(
            "INSERT INTO changes (url, from_id, to_id, detected_at, silent, added, removed, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                c.url,
                c.from_id.as_bytes(),
                c.to_id.as_bytes(),
                c.detected_at,
                c.silent,
                c.added as i64,
                c.removed as i64,
                c.summary
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    pub fn changes(&self, url: Option<&str>, limit: u32) -> Result<Vec<ChangeRow>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT seq, url, from_id, to_id, detected_at, silent, added, removed, summary FROM changes
             WHERE (?1 IS NULL OR url = ?1) ORDER BY detected_at DESC, seq DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![url, limit], |r| {
            Ok(ChangeRow {
                seq: r.get(0)?,
                url: r.get(1)?,
                from_id: digest(r, 2)?,
                to_id: digest(r, 3)?,
                detected_at: r.get(4)?,
                silent: r.get(5)?,
                added: r.get::<_, i64>(6)? as u64,
                removed: r.get::<_, i64>(7)? as u64,
                summary: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn watch_add(&self, url: &str, every_secs: u64, render: bool, now_ms: i64) -> Result<()> {
        self.db().execute(
            "INSERT INTO watch (url, every_secs, render, added_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(url) DO UPDATE SET every_secs = excluded.every_secs, render = excluded.render,
                request_id = NULL, expires_at = NULL",
            params![url, every_secs as i64, render, now_ms],
        )?;
        Ok(())
    }

    pub fn watch_remove(&self, url: &str) -> Result<bool> {
        Ok(self
            .db()
            .execute("DELETE FROM watch WHERE url = ?1", [url])?
            > 0)
    }

    pub fn watches(&self) -> Result<Vec<Watch>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT url, every_secs, render, added_at, last_run, last_error, request_id, expires_at
             FROM watch ORDER BY url",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Watch {
                url: r.get(0)?,
                every_secs: r.get::<_, i64>(1)? as u64,
                render: r.get(2)?,
                added_at: r.get(3)?,
                last_run: r.get(4)?,
                last_error: r.get(5)?,
                request_id: r
                    .get::<_, Option<Vec<u8>>>(6)?
                    .and_then(|b| Digest::from_slice(&b)),
                expires_at: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn watch_mark(&self, url: &str, at_ms: i64, error: Option<&str>) -> Result<()> {
        self.db().execute(
            "UPDATE watch SET last_run = ?2, last_error = ?3 WHERE url = ?1",
            params![url, at_ms, error],
        )?;
        Ok(())
    }

    /// Delete stored content for a URL (erasure request). Blobs still
    /// referenced by other URLs' captures are kept. With `forget`, the
    /// attestation rows go too; the log keeps only their opaque IDs, so every
    /// other inclusion proof stays valid. Returns (blobs deleted, rows deleted).
    pub fn purge(&self, url: &str, forget: bool) -> Result<(usize, usize)> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let hashes: Vec<(Digest, Digest, Option<Vec<u8>>)> = {
            let mut st = tx.prepare(
                "SELECT body_hash, headers_hash, norm_hash FROM attestations WHERE url = ?1",
            )?;
            let rows = st.query_map([url], |r| Ok((digest(r, 0)?, digest(r, 1)?, r.get(2)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut candidates: Vec<Digest> = Vec::new();
        for (b, h, n) in hashes {
            candidates.push(b);
            candidates.push(h);
            if let Some(n) = n.as_deref().and_then(Digest::from_slice) {
                candidates.push(n);
            }
        }
        candidates.sort();
        candidates.dedup();
        let mut deleted = 0;
        for d in candidates {
            let shared: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM attestations WHERE url != ?2
                   AND (body_hash = ?1 OR headers_hash = ?1 OR norm_hash = ?1))",
                params![d.as_bytes(), url],
                |r| r.get(0),
            )?;
            if !shared && self.blobs.delete(&d)? {
                deleted += 1;
            }
        }
        let rows = if forget {
            tx.execute("DELETE FROM changes WHERE url = ?1", [url])?;
            tx.execute("DELETE FROM watch WHERE url = ?1", [url])?;
            tx.execute("DELETE FROM attestations WHERE url = ?1", [url])?
        } else {
            0
        };
        tx.commit()?;
        Ok((deleted, rows))
    }
}

fn load_leaves(conn: &Connection) -> Result<Vec<Digest>> {
    let mut st = conn.prepare("SELECT id FROM log_leaves ORDER BY idx")?;
    let rows = st.query_map([], |r| digest(r, 0))?;
    rows.map(|d| Ok(merkle::leaf_hash(d?.as_bytes()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_core::{Attestation, Vantage};

    fn att(kp: &Keypair, url: &str, body: &[u8], t: i64) -> SignedAttestation {
        Attestation {
            url: url.into(),
            final_url: url.into(),
            redirects: vec![],
            fetched_at_ms: t,
            method: CaptureMethod::Http,
            status: 200,
            content_type: None,
            headers_hash: Digest::of(b"h"),
            body_hash: Digest::of(body),
            body_len: body.len() as u64,
            norm: None,
            cert_sha256: None,
            server_ip: None,
            vantage: Vantage::default(),
            witness: kp.public(),
            beacon: None,
        }
        .sign(kp)
        .unwrap()
    }

    #[test]
    fn log_grows_consistently_and_survives_erasure() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let kp = Keypair::generate().unwrap();

        let mut heads = vec![];
        for i in 0..5 {
            let url = if i % 2 == 0 {
                "https://a.example/"
            } else {
                "https://b.example/"
            };
            let sa = att(&kp, url, format!("v{i}").as_bytes(), i);
            s.blobs.put(format!("v{i}").as_bytes()).unwrap();
            let (rec, head) = s.commit(&sa, &kp, 100 + i).unwrap();
            assert_eq!(rec.leaf_index, i as u64);
            heads.push(head);
        }
        let leaves = s.leaves().unwrap();
        for w in heads.windows(2) {
            let p = merkle::consistency_proof(
                &leaves[..w[1].head.size as usize],
                w[0].head.size as usize,
            )
            .unwrap();
            w[0].verify_extension(&w[1], &p).unwrap();
        }
        assert_eq!(s.history("https://a.example/").unwrap().len(), 3);
        assert_eq!(
            s.at("https://a.example/", 1)
                .unwrap()
                .unwrap()
                .signed
                .attestation
                .fetched_at_ms,
            0
        );

        let (blobs, rows) = s.purge("https://a.example/", true).unwrap();
        assert_eq!((blobs, rows), (3, 3));
        assert!(s.history("https://a.example/").unwrap().is_empty());
        // The log is untouched: same leaves, same root.
        assert_eq!(s.leaves().unwrap(), leaves);
        assert_eq!(
            s.latest_tree_head().unwrap().unwrap().head.root,
            merkle::root(&leaves)
        );
        // Remaining records still prove inclusion.
        let b = s
            .latest("https://b.example/", CaptureMethod::Http)
            .unwrap()
            .unwrap();
        let p = merkle::inclusion_proof(&leaves, b.leaf_index as usize).unwrap();
        let root = merkle::root(&leaves);
        assert!(merkle::verify_inclusion(
            &merkle::leaf_hash(b.id.as_bytes()),
            b.leaf_index,
            leaves.len() as u64,
            &p,
            &root
        ));
    }

    #[test]
    fn migrates_v1_databases() {
        let t = tempfile::tempdir().unwrap();
        {
            let c = Connection::open(t.path().join("index.sqlite")).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
            c.execute(
                "INSERT INTO watch (url, every_secs, render, added_at) VALUES ('https://a.example/', 60, 0, 1)",
                [],
            )
            .unwrap();
        }
        let s = Store::open(t.path()).unwrap();
        let w = s.watches().unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].request_id.is_none());
        assert!(s.peers().unwrap().is_empty());
        assert!(
            !s.request_cancelled(&Digest::of(b"r"), &Keypair::generate().unwrap().public())
                .unwrap()
        );
        drop(s);
        // Opening again is a no-op.
        Store::open(t.path()).unwrap();
    }

    #[test]
    fn migrates_v2_databases() {
        let t = tempfile::tempdir().unwrap();
        {
            let c = Connection::open(t.path().join("index.sqlite")).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute_batch(net::SCHEMA_V2).unwrap();
            c.pragma_update(None, "user_version", 2).unwrap();
        }
        let s = Store::open(t.path()).unwrap();
        assert!(s.peers().unwrap().is_empty());
        assert!(!s.peer_evict_one(0).unwrap());
    }

    #[test]
    fn rejects_bad_signature() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let kp = Keypair::generate().unwrap();
        let mut sa = att(&kp, "https://a.example/", b"x", 0);
        sa.attestation.status = 500;
        assert!(s.commit(&sa, &kp, 0).is_err());
        assert!(s.leaves().unwrap().is_empty());
    }
}
