//! Storage for the network layer: peers, mirrored logs, gossip, watch
//! requests, cosignatures, observations, alerts, beacons, anchors and
//! reputation.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use witness_core::beacon::Beacon;
use witness_core::net::{
    Alert, Cosignature, Descriptor, Gossip, Observation, TlsnReceipt, WatchRequest,
};
use witness_core::statement::Signed;
use witness_core::{Digest, SignedAttestation, SignedTreeHead, WitnessKey};

use crate::{Result, Store, StoreError};

pub(crate) const SCHEMA_V2: &str = r#"
ALTER TABLE watch ADD COLUMN request_id BLOB;
ALTER TABLE watch ADD COLUMN expires_at INTEGER;

CREATE TABLE peers (
    key         BLOB PRIMARY KEY,
    descriptor  TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    endpoint    TEXT,
    first_seen  INTEGER NOT NULL,
    last_sync   INTEGER,
    last_error  TEXT,
    pushed_seq  INTEGER NOT NULL DEFAULT 0,
    pulled_seq  INTEGER NOT NULL DEFAULT 0,
    head        TEXT
);

-- Mirror of each peer's log: its leaf IDs in order.
CREATE TABLE peer_leaves (
    peer BLOB NOT NULL,
    idx  INTEGER NOT NULL,
    id   BLOB NOT NULL,
    PRIMARY KEY (peer, idx)
);

CREATE TABLE foreign_attestations (
    id         BLOB PRIMARY KEY,
    witness    BLOB NOT NULL,
    url        TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    json       TEXT NOT NULL
);
CREATE INDEX foreign_url ON foreign_attestations(url, fetched_at);

-- Every gossip message seen, which doubles as the outbox peers pull from.
CREATE TABLE gossip (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    id          BLOB NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    json        TEXT NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE requests (
    id         BLOB PRIMARY KEY,
    url        TEXT NOT NULL,
    requester  BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    json       TEXT NOT NULL
);

CREATE TABLE cosignatures (
    log      BLOB NOT NULL,
    size     INTEGER NOT NULL,
    cosigner BLOB NOT NULL,
    root     BLOB NOT NULL,
    json     TEXT NOT NULL,
    PRIMARY KEY (log, size, cosigner)
);

CREATE TABLE observations (
    subject     BLOB NOT NULL,
    observer    BLOB NOT NULL,
    observed_at INTEGER NOT NULL,
    ip          TEXT NOT NULL,
    json        TEXT NOT NULL,
    PRIMARY KEY (subject, observer)
);

CREATE TABLE equivocations (
    id          BLOB PRIMARY KEY,
    log         BLOB NOT NULL,
    json        TEXT NOT NULL,
    detected_at INTEGER NOT NULL
);

CREATE TABLE alerts (
    id        BLOB PRIMARY KEY,
    kind      TEXT NOT NULL,
    url       TEXT,
    issuer    BLOB NOT NULL,
    issued_at INTEGER NOT NULL,
    json      TEXT NOT NULL
);
CREATE INDEX alerts_time ON alerts(issued_at);

CREATE TABLE beacons (
    round INTEGER PRIMARY KEY,
    json  TEXT NOT NULL
);

CREATE TABLE anchors (
    size       INTEGER PRIMARY KEY,
    head       TEXT NOT NULL,
    ots        BLOB NOT NULL,
    status     TEXT NOT NULL,
    height     INTEGER,
    updated_at INTEGER NOT NULL
);

-- TLSNotary receipts for this node's own attestations.
CREATE TABLE tlsn_proofs (
    attestation BLOB PRIMARY KEY,
    receipt     TEXT NOT NULL
);

-- One reputation event per witness, URL and quorum window.
CREATE TABLE reputation (
    peer   BLOB NOT NULL,
    url    TEXT NOT NULL,
    window INTEGER NOT NULL,
    delta  REAL NOT NULL,
    at     INTEGER NOT NULL,
    PRIMARY KEY (peer, url, window)
);
"#;

pub(crate) const SCHEMA_V3: &str = r#"
-- When a peer last synced without error, for evicting dead peers.
ALTER TABLE peers ADD COLUMN last_ok INTEGER;

-- Requests their requester withdrew. Kept until the request would have
-- expired, so a peer re-sending it can't bring it back.
CREATE TABLE request_cancels (
    request    BLOB NOT NULL,
    requester  BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (request, requester)
);
"#;

/// What this node captures for the active requests on one URL: the
/// shortest interval and the latest expiry among them.
pub(crate) const SCHEMA_V4: &str = r#"
-- Logs are no longer mirrored leaf by leaf; auditors check consistency
-- proofs between checkpoints instead.
DROP TABLE peer_leaves;

-- Checkpoint heads seen over gossip. Two with the same log and size but
-- different roots prove the log showed different histories.
CREATE TABLE log_heads (
    log         BLOB NOT NULL,
    size        INTEGER NOT NULL,
    root        BLOB NOT NULL,
    json        TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (log, size)
);

-- When a cosignature was made, for pruning superseded ones.
ALTER TABLE cosignatures ADD COLUMN at INTEGER;
"#;

pub(crate) const SCHEMA_V5: &str = r#"
-- Recheck requests for disputed URLs, one row per requester.
CREATE TABLE disputes (
    url         TEXT NOT NULL,
    window_end  INTEGER NOT NULL,
    signer      BLOB NOT NULL,
    countries   TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (url, window_end, signer)
);

-- Rechecks this node was drawn for.
CREATE TABLE recheck_jobs (
    url        TEXT NOT NULL,
    window_end INTEGER NOT NULL,
    added_at   INTEGER NOT NULL,
    done_at    INTEGER,
    PRIMARY KEY (url, window_end)
);

-- The settled verdict of each comparison round, for confirming splits
-- across rounds.
CREATE TABLE round_outcomes (
    url        TEXT NOT NULL,
    window_end INTEGER NOT NULL,
    outcome    TEXT NOT NULL,
    at         INTEGER NOT NULL,
    PRIMARY KEY (url, window_end)
);

-- Versions that rechecks didn't reproduce, by the network prefix the
-- reporting witness was seen connecting from. Keys are free, addresses
-- aren't.
CREATE TABLE failed_claims (
    prefix     TEXT NOT NULL,
    url        TEXT NOT NULL,
    window_end INTEGER NOT NULL,
    at         INTEGER NOT NULL,
    PRIMARY KEY (prefix, url, window_end)
);

-- Whether this node has checked a gossiped head against the log's head it
-- audited itself (a consistency proof between the two sizes).
ALTER TABLE log_heads ADD COLUMN checked INTEGER NOT NULL DEFAULT 0;

-- Logs that couldn't prove two of their own heads consistent: they showed
-- different auditors different histories. Established by this node's own
-- verification only.
CREATE TABLE inconsistent_logs (
    log         BLOB PRIMARY KEY,
    detail      TEXT NOT NULL,
    detected_at INTEGER NOT NULL
);
"#;

/// How long pruned data is kept.
pub struct Retention {
    /// Cosignatures superseded by a newer one from the same cosigner.
    pub cosignatures_ms: i64,
    pub observations_ms: i64,
    pub alerts_ms: i64,
    pub beacons_ms: i64,
    /// Attestations fetched from other witnesses.
    pub foreign_ms: i64,
    pub reputation_ms: i64,
    pub log_heads_ms: i64,
    pub disputes_ms: i64,
    pub outcomes_ms: i64,
    pub failed_claims_ms: i64,
}

impl Default for Retention {
    fn default() -> Self {
        const DAY: i64 = 86_400_000;
        Retention {
            cosignatures_ms: 2 * DAY,
            observations_ms: 30 * DAY,
            alerts_ms: 180 * DAY,
            beacons_ms: 7 * DAY,
            foreign_ms: 90 * DAY,
            reputation_ms: 60 * DAY,
            log_heads_ms: 7 * DAY,
            disputes_ms: 2 * DAY,
            outcomes_ms: 30 * DAY,
            failed_claims_ms: 7 * DAY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestWatch {
    pub url: String,
    pub every_secs: u64,
    pub render: bool,
    /// One of the requests, for display.
    pub request: Digest,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Peer {
    pub key: WitnessKey,
    pub descriptor: Signed<Descriptor>,
    pub endpoint: Option<String>,
    pub first_seen: i64,
    pub last_sync: Option<i64>,
    pub last_error: Option<String>,
    /// Last sync without error.
    pub last_ok: Option<i64>,
    pub pushed_seq: i64,
    pub pulled_seq: i64,
    pub head: Option<SignedTreeHead>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnchorRow {
    pub size: u64,
    pub head: SignedTreeHead,
    pub ots: Vec<u8>,
    pub status: String,
    pub height: Option<u64>,
    pub updated_at: i64,
}

fn key_of(b: &[u8]) -> Option<WitnessKey> {
    b.try_into().ok().map(WitnessKey)
}

fn json<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    Ok(serde_json::from_str(s)?)
}

impl Store {
    // ------------------------------------------------------------- peers

    /// Insert or refresh a peer from a verified descriptor. Older
    /// descriptors never replace newer ones. Returns true if stored.
    pub fn peer_upsert(&self, d: &Signed<Descriptor>, now_ms: i64) -> Result<bool> {
        let n = self.db().execute(
            "INSERT INTO peers (key, descriptor, issued_at, endpoint, first_seen) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(key) DO UPDATE SET descriptor = excluded.descriptor, issued_at = excluded.issued_at,
                endpoint = excluded.endpoint
             WHERE excluded.issued_at > peers.issued_at",
            params![
                d.body.key.0.as_slice(),
                serde_json::to_string(d)?,
                d.body.issued_at_ms,
                d.body.endpoint,
                now_ms
            ],
        )?;
        Ok(n > 0)
    }

    fn peer_rows(&self, filter: &str, p: impl rusqlite::Params) -> Result<Vec<Peer>> {
        let db = self.db();
        let mut st = db.prepare(&format!(
            "SELECT key, descriptor, endpoint, first_seen, last_sync, last_error, pushed_seq, pulled_seq, head, last_ok
             FROM peers {filter} ORDER BY first_seen, key"
        ))?;
        let rows = st.query_map(p, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<i64>>(9)?,
            ))
        })?;
        rows.map(|row| {
            let (
                k,
                d,
                endpoint,
                first_seen,
                last_sync,
                last_error,
                pushed_seq,
                pulled_seq,
                head,
                last_ok,
            ) = row?;
            Ok(Peer {
                key: key_of(&k).ok_or_else(|| StoreError::Corrupt("peer key".into()))?,
                descriptor: json(&d)?,
                endpoint,
                first_seen,
                last_sync,
                last_error,
                last_ok,
                pushed_seq,
                pulled_seq,
                head: head.as_deref().map(json).transpose()?,
            })
        })
        .collect()
    }

    pub fn peers(&self) -> Result<Vec<Peer>> {
        self.peer_rows("", [])
    }

    pub fn peer(&self, key: &WitnessKey) -> Result<Option<Peer>> {
        Ok(self.peer_rows("WHERE key = ?1", [key.0.as_slice()])?.pop())
    }

    pub fn peer_mark_sync(&self, key: &WitnessKey, at_ms: i64, error: Option<&str>) -> Result<()> {
        self.db().execute(
            "UPDATE peers SET last_sync = ?2, last_error = ?3,
                last_ok = CASE WHEN ?3 IS NULL THEN ?2 ELSE last_ok END
             WHERE key = ?1",
            params![key.0.as_slice(), at_ms, error],
        )?;
        Ok(())
    }

    /// Make room in a full peer table by dropping the least useful peer:
    /// one that equivocated, has no endpoint, or hasn't synced in a day
    /// (or ever, an hour after we learned of it). Returns whether a peer
    /// was dropped.
    pub fn peer_evict_one(&self, now_ms: i64) -> Result<bool> {
        let n = self.db().execute(
            "DELETE FROM peers WHERE key = (
                SELECT key FROM peers
                WHERE key IN (SELECT log FROM equivocations)
                   OR endpoint IS NULL
                   OR (last_ok IS NULL AND first_seen < ?1)
                   OR last_ok < ?2
                ORDER BY key IN (SELECT log FROM equivocations) DESC,
                         endpoint IS NULL DESC,
                         COALESCE(last_ok, first_seen)
                LIMIT 1)",
            params![now_ms - 3_600_000, now_ms - 86_400_000],
        )?;
        Ok(n > 0)
    }

    /// Forget a peer.
    pub fn peer_remove(&self, key: &WitnessKey) -> Result<bool> {
        Ok(self
            .db()
            .execute("DELETE FROM peers WHERE key = ?1", [key.0.as_slice()])?
            > 0)
    }

    pub fn peer_set_cursors(
        &self,
        key: &WitnessKey,
        pushed: Option<i64>,
        pulled: Option<i64>,
    ) -> Result<()> {
        let db = self.db();
        if let Some(p) = pushed {
            db.execute(
                "UPDATE peers SET pushed_seq = ?2 WHERE key = ?1",
                params![key.0.as_slice(), p],
            )?;
        }
        if let Some(p) = pulled {
            db.execute(
                "UPDATE peers SET pulled_seq = ?2 WHERE key = ?1",
                params![key.0.as_slice(), p],
            )?;
        }
        Ok(())
    }

    /// Record the latest head of a peer's log this node has verified.
    pub fn peer_set_head(&self, key: &WitnessKey, head: &SignedTreeHead) -> Result<()> {
        self.db().execute(
            "UPDATE peers SET head = ?2 WHERE key = ?1",
            params![key.0.as_slice(), serde_json::to_string(head)?],
        )?;
        Ok(())
    }

    /// Remember a checkpoint head seen over gossip. Returns a stored head
    /// of the same log and size with a different root, if there is one.
    pub fn log_head_insert(
        &self,
        h: &SignedTreeHead,
        now_ms: i64,
    ) -> Result<Option<SignedTreeHead>> {
        let db = self.db();
        let existing: Option<String> = db
            .query_row(
                "SELECT json FROM log_heads WHERE log = ?1 AND size = ?2 AND root != ?3",
                params![
                    h.head.log.0.as_slice(),
                    h.head.size as i64,
                    h.head.root.as_bytes()
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(j) = existing {
            return Ok(Some(json(&j)?));
        }
        db.execute(
            "INSERT OR IGNORE INTO log_heads (log, size, root, json, received_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                h.head.log.0.as_slice(),
                h.head.size as i64,
                h.head.root.as_bytes(),
                serde_json::to_string(h)?,
                now_ms
            ],
        )?;
        Ok(None)
    }

    /// Gossiped heads of `log` this node hasn't yet checked against its
    /// own audit, oldest first, with when each was received.
    pub fn log_heads_unchecked(
        &self,
        log: &WitnessKey,
        limit: u32,
    ) -> Result<Vec<(SignedTreeHead, i64)>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT json, received_at FROM log_heads WHERE log = ?1 AND checked = 0
             ORDER BY received_at LIMIT ?2",
        )?;
        let rows = st.query_map(params![log.0.as_slice(), limit], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        rows.map(|r| {
            let (j, at) = r?;
            Ok((json(&j)?, at))
        })
        .collect()
    }

    pub fn log_head_mark_checked(&self, log: &WitnessKey, size: u64) -> Result<()> {
        self.db().execute(
            "UPDATE log_heads SET checked = 1 WHERE log = ?1 AND size = ?2",
            params![log.0.as_slice(), size as i64],
        )?;
        Ok(())
    }

    /// Record that `log` failed to prove its heads consistent. Returns
    /// whether this is news.
    pub fn inconsistency_insert(
        &self,
        log: &WitnessKey,
        detail: &str,
        now_ms: i64,
    ) -> Result<bool> {
        Ok(self.db().execute(
            "INSERT OR IGNORE INTO inconsistent_logs (log, detail, detected_at) VALUES (?1, ?2, ?3)",
            params![log.0.as_slice(), detail, now_ms],
        )? > 0)
    }

    // --------------------------------------------- foreign attestations

    pub fn foreign_insert(&self, sa: &SignedAttestation) -> Result<bool> {
        let a = &sa.attestation;
        let n = self.db().execute(
            "INSERT OR IGNORE INTO foreign_attestations (id, witness, url, fetched_at, json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                sa.id().as_bytes(),
                a.witness.0.as_slice(),
                a.url,
                a.fetched_at_ms,
                serde_json::to_string(sa)?
            ],
        )?;
        Ok(n > 0)
    }

    pub fn foreign_for_url(&self, url: &str, since_ms: i64) -> Result<Vec<SignedAttestation>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT json FROM foreign_attestations WHERE url = ?1 AND fetched_at >= ?2 ORDER BY fetched_at",
        )?;
        let rows = st.query_map(params![url, since_ms], |r| r.get::<_, String>(0))?;
        rows.map(|j| json(&j?)).collect()
    }

    pub fn foreign_urls_since(&self, since_ms: i64) -> Result<Vec<String>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT DISTINCT url FROM foreign_attestations WHERE fetched_at >= ?1
             UNION SELECT DISTINCT url FROM attestations WHERE fetched_at >= ?1",
        )?;
        let rows = st.query_map([since_ms], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn foreign_count(&self) -> Result<u64> {
        Ok(self
            .db()
            .query_row("SELECT COUNT(*) FROM foreign_attestations", [], |r| {
                r.get::<_, i64>(0)
            })? as u64)
    }

    // ------------------------------------------------------------ gossip

    /// Record a message. Returns its outbox sequence number, or `None` if
    /// it was already known.
    pub fn gossip_insert(&self, g: &Gossip, now_ms: i64) -> Result<Option<i64>> {
        let db = self.db();
        let n = db.execute(
            "INSERT OR IGNORE INTO gossip (id, kind, json, received_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                g.id().as_bytes(),
                g.kind(),
                serde_json::to_string(g)?,
                now_ms
            ],
        )?;
        Ok((n > 0).then(|| db.last_insert_rowid()))
    }

    pub fn gossip_seen(&self, id: &Digest) -> Result<bool> {
        Ok(self.db().query_row(
            "SELECT EXISTS(SELECT 1 FROM gossip WHERE id = ?1)",
            [id.as_bytes()],
            |r| r.get(0),
        )?)
    }

    pub fn gossip_since(&self, after_seq: i64, limit: u32) -> Result<Vec<(i64, Gossip)>> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT seq, json FROM gossip WHERE seq > ?1 ORDER BY seq LIMIT ?2")?;
        let rows = st.query_map(params![after_seq, limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, j) = row?;
            Ok((seq, json(&j)?))
        })
        .collect()
    }

    /// Forget messages older than `before_ms`. Their IDs are forgotten too,
    /// so a very late duplicate would be accepted once more; receivers
    /// dedupe by content anyway.
    /// Drop old messages from the outbox. Requests and cancellations are
    /// kept until `requests_before_ms`, since a request can run for weeks
    /// and witnesses joining later still need to hear of it.
    pub fn gossip_prune(&self, before_ms: i64, requests_before_ms: i64) -> Result<usize> {
        Ok(self.db().execute(
            "DELETE FROM gossip WHERE received_at < ?2
                OR (received_at < ?1 AND kind NOT IN ('request', 'cancel'))",
            params![before_ms, requests_before_ms],
        )?)
    }

    // ---------------------------------------------------------- requests

    pub fn request_insert(&self, r: &Signed<WatchRequest>) -> Result<bool> {
        let n = self.db().execute(
            "INSERT OR IGNORE INTO requests (id, url, requester, expires_at, json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                r.id().as_bytes(),
                r.body.url,
                r.body.requester.0.as_slice(),
                r.body.expires_at_ms,
                serde_json::to_string(r)?
            ],
        )?;
        Ok(n > 0)
    }

    pub fn requests_active(&self, now_ms: i64) -> Result<Vec<Signed<WatchRequest>>> {
        let db = self.db();
        let mut st = db.prepare("SELECT json FROM requests WHERE expires_at > ?1 ORDER BY url")?;
        let rows = st.query_map([now_ms], |r| r.get::<_, String>(0))?;
        rows.map(|j| json(&j?)).collect()
    }

    pub fn requests_active_by(&self, requester: &WitnessKey, now_ms: i64) -> Result<u64> {
        Ok(self.db().query_row(
            "SELECT COUNT(*) FROM requests WHERE requester = ?1 AND expires_at > ?2",
            params![requester.0.as_slice(), now_ms],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    pub fn request(&self, id: &Digest) -> Result<Option<Signed<WatchRequest>>> {
        let db = self.db();
        let mut st = db.prepare("SELECT json FROM requests WHERE id = ?1")?;
        let mut rows = st.query_map([id.as_bytes()], |r| r.get::<_, String>(0))?;
        rows.next().transpose()?.map(|j| json(&j)).transpose()
    }

    pub fn requests_by(
        &self,
        requester: &WitnessKey,
        now_ms: i64,
    ) -> Result<Vec<Signed<WatchRequest>>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT json FROM requests WHERE requester = ?1 AND expires_at > ?2 ORDER BY url",
        )?;
        let rows = st.query_map(params![requester.0.as_slice(), now_ms], |r| {
            r.get::<_, String>(0)
        })?;
        rows.map(|j| json(&j?)).collect()
    }

    pub fn requests_prune(&self, now_ms: i64) -> Result<usize> {
        let db = self.db();
        db.execute(
            "DELETE FROM request_cancels WHERE expires_at <= ?1",
            [now_ms],
        )?;
        Ok(db.execute("DELETE FROM requests WHERE expires_at <= ?1", [now_ms])?)
    }

    /// Record that `requester` withdrew request `id`, and drop the request
    /// if we hold it and it is theirs. Returns true if the cancellation is
    /// new.
    pub fn request_cancel(
        &self,
        id: &Digest,
        requester: &WitnessKey,
        expires_at_ms: i64,
    ) -> Result<bool> {
        let db = self.db();
        let n = db.execute(
            "INSERT OR IGNORE INTO request_cancels (request, requester, expires_at) VALUES (?1, ?2, ?3)",
            params![id.as_bytes(), requester.0.as_slice(), expires_at_ms],
        )?;
        db.execute(
            "DELETE FROM requests WHERE id = ?1 AND requester = ?2",
            params![id.as_bytes(), requester.0.as_slice()],
        )?;
        Ok(n > 0)
    }

    /// Whether `requester` withdrew request `id`.
    pub fn request_cancelled(&self, id: &Digest, requester: &WitnessKey) -> Result<bool> {
        Ok(self.db().query_row(
            "SELECT COUNT(*) FROM request_cancels WHERE request = ?1 AND requester = ?2",
            params![id.as_bytes(), requester.0.as_slice()],
            |r| r.get::<_, i64>(0),
        )? > 0)
    }

    /// Add or update the watch that serves the network's requests for a
    /// URL. A user's own watch on the same URL takes precedence and is left
    /// alone.
    pub fn watch_for_request(&self, w: &RequestWatch, now_ms: i64) -> Result<()> {
        self.db().execute(
            "INSERT INTO watch (url, every_secs, render, added_at, request_id, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(url) DO UPDATE SET every_secs = excluded.every_secs,
                render = excluded.render, request_id = excluded.request_id,
                expires_at = excluded.expires_at
             WHERE watch.request_id IS NOT NULL",
            params![
                w.url,
                w.every_secs as i64,
                w.render,
                now_ms,
                w.request.as_bytes(),
                w.expires_at_ms
            ],
        )?;
        Ok(())
    }

    /// Drop request-driven watches that expired or are no longer assigned.
    pub fn watch_drop_requested(&self, keep_urls: &[String], now_ms: i64) -> Result<usize> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT url, expires_at FROM watch WHERE request_id IS NOT NULL")?;
        let rows: Vec<(String, Option<i64>)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut n = 0;
        for (url, exp) in rows {
            if exp.is_some_and(|e| e <= now_ms) || !keep_urls.contains(&url) {
                n += db.execute(
                    "DELETE FROM watch WHERE url = ?1 AND request_id IS NOT NULL",
                    [&url],
                )?;
            }
        }
        Ok(n)
    }

    // ------------------------------------------------------ cosignatures

    pub fn cosig_insert(&self, c: &Signed<Cosignature>) -> Result<bool> {
        let n = self.db().execute(
            "INSERT OR IGNORE INTO cosignatures (log, size, cosigner, root, json, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                c.body.log.0.as_slice(),
                c.body.size as i64,
                c.body.cosigner.0.as_slice(),
                c.body.root.as_bytes(),
                serde_json::to_string(c)?,
                c.body.timestamp_ms
            ],
        )?;
        Ok(n > 0)
    }

    pub fn cosigs_for(&self, head: &SignedTreeHead) -> Result<Vec<Signed<Cosignature>>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT json FROM cosignatures WHERE log = ?1 AND size = ?2 AND root = ?3 ORDER BY cosigner",
        )?;
        let rows = st.query_map(
            params![
                head.head.log.0.as_slice(),
                head.head.size as i64,
                head.head.root.as_bytes()
            ],
            |r| r.get::<_, String>(0),
        )?;
        rows.map(|j| json(&j?)).collect()
    }

    /// Cosigned heads of `log`, largest first, with their cosigner counts.
    pub fn cosigned_sizes(&self, log: &WitnessKey) -> Result<Vec<(u64, u64)>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT size, COUNT(DISTINCT cosigner) FROM cosignatures WHERE log = ?1 GROUP BY size ORDER BY size DESC",
        )?;
        let rows = st.query_map([log.0.as_slice()], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ------------------------------------------------------ observations

    pub fn observation_upsert(&self, o: &Signed<Observation>) -> Result<bool> {
        let n = self.db().execute(
            "INSERT INTO observations (subject, observer, observed_at, ip, json) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(subject, observer) DO UPDATE SET observed_at = excluded.observed_at,
                ip = excluded.ip, json = excluded.json
             WHERE excluded.observed_at > observations.observed_at",
            params![
                o.body.subject.0.as_slice(),
                o.body.observer.0.as_slice(),
                o.body.observed_at_ms,
                o.body.ip.to_string(),
                serde_json::to_string(o)?
            ],
        )?;
        Ok(n > 0)
    }

    /// The latest observation `observer` made of `subject`.
    pub fn observation(
        &self,
        subject: &WitnessKey,
        observer: &WitnessKey,
    ) -> Result<Option<Signed<Observation>>> {
        let j: Option<String> = self
            .db()
            .query_row(
                "SELECT json FROM observations WHERE subject = ?1 AND observer = ?2",
                params![subject.0.as_slice(), observer.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        j.as_deref().map(json).transpose()
    }

    pub fn observations_of(
        &self,
        subject: &WitnessKey,
        since_ms: i64,
    ) -> Result<Vec<Signed<Observation>>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT json FROM observations WHERE subject = ?1 AND observed_at >= ?2 ORDER BY observer",
        )?;
        let rows = st.query_map(params![subject.0.as_slice(), since_ms], |r| {
            r.get::<_, String>(0)
        })?;
        rows.map(|j| json(&j?)).collect()
    }

    // ---------------------------------------------- equivocations, alerts

    pub fn equivocation_insert(
        &self,
        a: &SignedTreeHead,
        b: &SignedTreeHead,
        now_ms: i64,
    ) -> Result<bool> {
        let g = Gossip::Equivocation {
            a: a.clone(),
            b: b.clone(),
        };
        let n = self.db().execute(
            "INSERT OR IGNORE INTO equivocations (id, log, json, detected_at) VALUES (?1, ?2, ?3, ?4)",
            params![g.id().as_bytes(), a.head.log.0.as_slice(), serde_json::to_string(&g)?, now_ms],
        )?;
        Ok(n > 0)
    }

    /// Logs shown to have told different auditors different histories:
    /// by two signed heads of the same size (proof anyone can check), or by
    /// failing to prove two of its heads consistent to this node.
    pub fn equivocating_logs(&self) -> Result<Vec<WitnessKey>> {
        let db = self.db();
        let mut st =
            db.prepare("SELECT log FROM equivocations UNION SELECT log FROM inconsistent_logs")?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .filter_map(|b| key_of(b))
            .collect())
    }

    pub fn alert_insert(&self, a: &Signed<Alert>) -> Result<bool> {
        let kind = serde_json::to_value(a.body.kind)?;
        let n = self.db().execute(
            "INSERT OR IGNORE INTO alerts (id, kind, url, issuer, issued_at, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                a.id().as_bytes(),
                kind.as_str().unwrap_or(""),
                a.body.url,
                a.body.issuer.0.as_slice(),
                a.body.issued_at_ms,
                serde_json::to_string(a)?
            ],
        )?;
        Ok(n > 0)
    }

    pub fn alerts(&self, limit: u32) -> Result<Vec<Signed<Alert>>> {
        let db = self.db();
        let mut st = db.prepare("SELECT json FROM alerts ORDER BY issued_at DESC LIMIT ?1")?;
        let rows = st.query_map([limit], |r| r.get::<_, String>(0))?;
        rows.map(|j| json(&j?)).collect()
    }

    /// Whether `issuer` already raised an alert of `kind` for `url` since
    /// `since_ms`.
    pub fn alert_exists(
        &self,
        kind: &str,
        url: &str,
        issuer: &WitnessKey,
        since_ms: i64,
    ) -> Result<bool> {
        Ok(self.db().query_row(
            "SELECT EXISTS(SELECT 1 FROM alerts WHERE kind = ?1 AND url = ?2 AND issuer = ?3 AND issued_at >= ?4)",
            params![kind, url, issuer.0.as_slice(), since_ms],
            |r| r.get(0),
        )?)
    }

    // ------------------------------------------------------------ beacons

    pub fn beacon_insert(&self, b: &Beacon) -> Result<()> {
        self.db().execute(
            "INSERT OR IGNORE INTO beacons (round, json) VALUES (?1, ?2)",
            params![b.round as i64, serde_json::to_string(b)?],
        )?;
        Ok(())
    }

    pub fn beacon(&self, round: u64) -> Result<Option<Beacon>> {
        let j: Option<String> = self
            .db()
            .query_row(
                "SELECT json FROM beacons WHERE round = ?1",
                [round as i64],
                |r| r.get(0),
            )
            .optional()?;
        j.as_deref().map(json).transpose()
    }

    pub fn beacon_latest(&self) -> Result<Option<Beacon>> {
        let j: Option<String> = self
            .db()
            .query_row(
                "SELECT json FROM beacons ORDER BY round DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        j.as_deref().map(json).transpose()
    }

    // ------------------------------------------------------------ anchors

    pub fn anchor_upsert(&self, a: &AnchorRow) -> Result<()> {
        self.db().execute(
            "INSERT INTO anchors (size, head, ots, status, height, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(size) DO UPDATE SET ots = excluded.ots, status = excluded.status,
                height = excluded.height, updated_at = excluded.updated_at",
            params![
                a.size as i64,
                serde_json::to_string(&a.head)?,
                a.ots,
                a.status,
                a.height.map(|h| h as i64),
                a.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn anchors(&self) -> Result<Vec<AnchorRow>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT size, head, ots, status, height, updated_at FROM anchors ORDER BY size DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (size, head, ots, status, height, updated_at) = row?;
            Ok(AnchorRow {
                size: size as u64,
                head: json(&head)?,
                ots,
                status,
                height: height.map(|h| h as u64),
                updated_at,
            })
        })
        .collect()
    }

    /// The best anchor covering leaf `index`: the smallest confirmed one,
    /// else the smallest pending one.
    pub fn anchor_covering(&self, index: u64) -> Result<Option<AnchorRow>> {
        let mut all: Vec<AnchorRow> = self
            .anchors()?
            .into_iter()
            .filter(|a| a.size > index)
            .collect();
        all.sort_by_key(|a| (a.status != "confirmed", a.size));
        Ok(all.into_iter().next())
    }

    // ----------------------------------------------------------- rechecks

    /// Store a recheck request. Returns true if it's new.
    pub fn dispute_insert(
        &self,
        url: &str,
        window_end: i64,
        signer: &WitnessKey,
        countries: &[String],
        now_ms: i64,
    ) -> Result<bool> {
        Ok(self.db().execute(
            "INSERT OR IGNORE INTO disputes (url, window_end, signer, countries, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                url,
                window_end,
                signer.0.as_slice(),
                serde_json::to_string(countries)?,
                now_ms
            ],
        )? > 0)
    }

    /// Whether `signer` already asked for a recheck of this round.
    pub fn dispute_by(&self, url: &str, window_end: i64, signer: &WitnessKey) -> Result<bool> {
        Ok(self.db().query_row(
            "SELECT EXISTS(SELECT 1 FROM disputes WHERE url = ?1 AND window_end = ?2 AND signer = ?3)",
            params![url, window_end, signer.0.as_slice()],
            |r| r.get(0),
        )?)
    }

    /// Rounds of `url` with recheck requests since `since_ms` (by window
    /// end), with the union of the countries asked for.
    pub fn disputes_for(&self, url: &str, since_ms: i64) -> Result<Vec<(i64, Vec<String>)>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT window_end, countries FROM disputes WHERE url = ?1 AND window_end >= ?2
             ORDER BY window_end",
        )?;
        let rows = st.query_map(params![url, since_ms], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out: Vec<(i64, Vec<String>)> = Vec::new();
        for row in rows {
            let (end, c) = row?;
            let c: Vec<String> = json(&c)?;
            match out.last_mut() {
                Some((e, all)) if *e == end => {
                    for x in c {
                        if !all.contains(&x) {
                            all.push(x);
                        }
                    }
                }
                _ => out.push((end, c)),
            }
        }
        Ok(out)
    }

    /// Queue a recheck this node was drawn for. Returns true if new.
    pub fn recheck_job_add(&self, url: &str, window_end: i64, now_ms: i64) -> Result<bool> {
        Ok(self.db().execute(
            "INSERT OR IGNORE INTO recheck_jobs (url, window_end, added_at) VALUES (?1, ?2, ?3)",
            params![url, window_end, now_ms],
        )? > 0)
    }

    /// Rechecks still to do, oldest first.
    pub fn recheck_jobs_pending(&self, limit: u32) -> Result<Vec<(String, i64)>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT url, window_end FROM recheck_jobs WHERE done_at IS NULL
             ORDER BY added_at LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn recheck_job_done(&self, url: &str, window_end: i64, now_ms: i64) -> Result<()> {
        self.db().execute(
            "UPDATE recheck_jobs SET done_at = ?3 WHERE url = ?1 AND window_end = ?2",
            params![url, window_end, now_ms],
        )?;
        Ok(())
    }

    /// Rechecks done since `since_ms`, for the hourly budget.
    pub fn rechecks_done_since(&self, since_ms: i64) -> Result<u64> {
        Ok(self.db().query_row(
            "SELECT COUNT(*) FROM recheck_jobs WHERE done_at >= ?1",
            [since_ms],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    /// Record a round's settled verdict. Returns true if it's new.
    pub fn round_outcome_set(
        &self,
        url: &str,
        window_end: i64,
        outcome: &str,
        now_ms: i64,
    ) -> Result<bool> {
        Ok(self.db().execute(
            "INSERT OR IGNORE INTO round_outcomes (url, window_end, outcome, at) VALUES (?1, ?2, ?3, ?4)",
            params![url, window_end, outcome, now_ms],
        )? > 0)
    }

    /// The last `n` settled outcomes for `url`, newest first.
    pub fn round_outcomes(&self, url: &str, n: u32) -> Result<Vec<String>> {
        let db = self.db();
        let mut st = db.prepare(
            "SELECT outcome FROM round_outcomes WHERE url = ?1 ORDER BY window_end DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![url, n], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn failed_claim_add(
        &self,
        prefix: &str,
        url: &str,
        window_end: i64,
        now_ms: i64,
    ) -> Result<()> {
        self.db().execute(
            "INSERT OR IGNORE INTO failed_claims (prefix, url, window_end, at) VALUES (?1, ?2, ?3, ?4)",
            params![prefix, url, window_end, now_ms],
        )?;
        Ok(())
    }

    pub fn failed_claims(&self, prefix: &str, since_ms: i64) -> Result<u64> {
        Ok(self.db().query_row(
            "SELECT COUNT(*) FROM failed_claims WHERE prefix = ?1 AND at >= ?2",
            params![prefix, since_ms],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    // ------------------------------------------------------------ pruning

    /// Delete network data that is no longer needed. Evidence this node
    /// signed (its log, attestations, anchors) is never touched. Returns
    /// the number of rows deleted.
    pub fn prune(&self, now_ms: i64, keep: &Retention) -> Result<usize> {
        let db = self.db();
        let mut n = 0;
        // A cosigner's newest cosignature of a log vouches for everything
        // before it; older ones only matter while bundles may still pick
        // them.
        n += db.execute(
            "DELETE FROM cosignatures WHERE (at IS NULL OR at < ?1) AND size < (
                SELECT MAX(c2.size) FROM cosignatures c2
                WHERE c2.log = cosignatures.log AND c2.cosigner = cosignatures.cosigner)",
            [now_ms - keep.cosignatures_ms],
        )?;
        n += db.execute(
            "DELETE FROM observations WHERE observed_at < ?1",
            [now_ms - keep.observations_ms],
        )?;
        n += db.execute(
            "DELETE FROM alerts WHERE issued_at < ?1",
            [now_ms - keep.alerts_ms],
        )?;
        n += db.execute(
            "DELETE FROM beacons WHERE round < ?1",
            [witness_core::beacon::round_at(now_ms - keep.beacons_ms) as i64],
        )?;
        n += db.execute(
            "DELETE FROM foreign_attestations WHERE fetched_at < ?1",
            [now_ms - keep.foreign_ms],
        )?;
        n += db.execute(
            "DELETE FROM reputation WHERE at < ?1",
            [now_ms - keep.reputation_ms],
        )?;
        n += db.execute(
            "DELETE FROM log_heads WHERE received_at < ?1",
            [now_ms - keep.log_heads_ms],
        )?;
        n += db.execute(
            "DELETE FROM disputes WHERE received_at < ?1",
            [now_ms - keep.disputes_ms],
        )?;
        n += db.execute(
            "DELETE FROM recheck_jobs WHERE added_at < ?1",
            [now_ms - keep.disputes_ms],
        )?;
        n += db.execute(
            "DELETE FROM round_outcomes WHERE at < ?1",
            [now_ms - keep.outcomes_ms],
        )?;
        n += db.execute(
            "DELETE FROM failed_claims WHERE at < ?1",
            [now_ms - keep.failed_claims_ms],
        )?;
        Ok(n)
    }

    // -------------------------------------------------------------- tlsn

    pub fn tlsn_insert(&self, attestation: &Digest, receipt: &Signed<TlsnReceipt>) -> Result<()> {
        self.db().execute(
            "INSERT OR REPLACE INTO tlsn_proofs (attestation, receipt) VALUES (?1, ?2)",
            params![attestation.as_bytes(), serde_json::to_string(receipt)?],
        )?;
        Ok(())
    }

    pub fn tlsn_for(&self, attestation: &Digest) -> Result<Option<Signed<TlsnReceipt>>> {
        let j: Option<String> = self
            .db()
            .query_row(
                "SELECT receipt FROM tlsn_proofs WHERE attestation = ?1",
                [attestation.as_bytes()],
                |r| r.get(0),
            )
            .optional()?;
        j.as_deref().map(json).transpose()
    }

    // --------------------------------------------------------- reputation

    pub fn reputation_record(
        &self,
        peer: &WitnessKey,
        url: &str,
        window: i64,
        delta: f64,
        at_ms: i64,
    ) -> Result<bool> {
        let n = self.db().execute(
            "INSERT OR IGNORE INTO reputation (peer, url, window, delta, at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![peer.0.as_slice(), url, window, delta, at_ms],
        )?;
        Ok(n > 0)
    }

    /// Reputation per witness: event deltas with a 14-day half-life.
    pub fn reputation_scores(&self, now_ms: i64) -> Result<HashMap<WitnessKey, f64>> {
        let db = self.db();
        let mut st = db.prepare("SELECT peer, delta, at FROM reputation")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, f64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out: HashMap<WitnessKey, f64> = HashMap::new();
        const HALF_LIFE_MS: f64 = 14.0 * 86_400_000.0;
        for row in rows {
            let (k, delta, at) = row?;
            if let Some(k) = key_of(&k) {
                let age = (now_ms - at).max(0) as f64;
                *out.entry(k).or_default() += delta * 0.5f64.powf(age / HALF_LIFE_MS);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_core::Keypair;
    use witness_core::net::Descriptor;

    fn peer(s: &Store, endpoint: Option<&str>, now: i64) -> WitnessKey {
        let kp = Keypair::generate().unwrap();
        let d = Signed::sign(
            Descriptor {
                key: kp.public(),
                endpoint: endpoint.map(str::to_string),
                vantage: Default::default(),
                issued_at_ms: now,
                software: "t".into(),
            },
            &kp,
        )
        .unwrap();
        s.peer_upsert(&d, now).unwrap();
        kp.public()
    }

    #[test]
    fn evicts_the_least_useful_peer() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let hour = 3_600_000;
        let now = 100 * hour;
        let healthy = peer(&s, Some("https://a.example"), now - 50 * hour);
        s.peer_mark_sync(&healthy, now - hour, None).unwrap();
        let fresh = peer(&s, Some("https://b.example"), now);
        // Nothing to evict: one peer is healthy, the other brand new.
        assert!(!s.peer_evict_one(now).unwrap());

        let dead = peer(&s, Some("https://c.example"), now - 2 * hour);
        s.peer_mark_sync(&dead, now - hour, Some("connection refused"))
            .unwrap();
        let hidden = peer(&s, None, now);
        // Endpoint-less peers go first, then ones that never synced.
        assert!(s.peer_evict_one(now).unwrap());
        assert!(s.peer(&hidden).unwrap().is_none());
        assert!(s.peer_evict_one(now).unwrap());
        assert!(s.peer(&dead).unwrap().is_none());
        assert!(!s.peer_evict_one(now).unwrap());
        assert!(s.peer(&healthy).unwrap().is_some());
        assert!(s.peer(&fresh).unwrap().is_some());
        // A peer that stopped answering a day ago is evictable too.
        assert!(s.peer_evict_one(now + 30 * hour).unwrap());
    }

    #[test]
    fn cancellations_outlive_the_request_row() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let kp = Keypair::generate().unwrap();
        let other = Keypair::generate().unwrap();
        let r = Signed::sign(
            WatchRequest {
                url: "https://a.example/".into(),
                every_secs: 600,
                render: false,
                requester: kp.public(),
                issued_at_ms: 0,
                expires_at_ms: 1000,
            },
            &kp,
        )
        .unwrap();
        s.request_insert(&r).unwrap();
        // Someone else's cancellation doesn't touch it.
        s.request_cancel(&r.id(), &other.public(), 1000).unwrap();
        assert_eq!(s.requests_active(0).unwrap().len(), 1);
        assert!(!s.request_cancelled(&r.id(), &kp.public()).unwrap());

        assert!(s.request_cancel(&r.id(), &kp.public(), 1000).unwrap());
        assert!(!s.request_cancel(&r.id(), &kp.public(), 1000).unwrap());
        assert!(s.requests_active(0).unwrap().is_empty());
        assert!(s.request_cancelled(&r.id(), &kp.public()).unwrap());
        s.requests_prune(1000).unwrap();
        assert!(!s.request_cancelled(&r.id(), &kp.public()).unwrap());
    }

    fn head(kp: &Keypair, size: u64, root: &[u8], t: i64) -> SignedTreeHead {
        witness_core::TreeHead {
            log: kp.public(),
            size,
            root: Digest::of(root),
            timestamp_ms: t,
        }
        .sign(kp)
        .unwrap()
    }

    #[test]
    fn conflicting_checkpoints_are_caught() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let kp = Keypair::generate().unwrap();
        let a = head(&kp, 5, b"a", 1);
        assert!(s.log_head_insert(&a, 1).unwrap().is_none());
        assert!(s.log_head_insert(&a, 2).unwrap().is_none());
        assert!(
            s.log_head_insert(&head(&kp, 6, b"c", 2), 2)
                .unwrap()
                .is_none()
        );
        let other = s.log_head_insert(&head(&kp, 5, b"b", 3), 3).unwrap();
        assert_eq!(other, Some(a));
    }

    #[test]
    fn prunes_superseded_and_stale_data() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::open(t.path()).unwrap();
        let log = Keypair::generate().unwrap();
        let cosigner = Keypair::generate().unwrap();
        let day = 86_400_000;
        let now = 100 * day;
        let cosig = |size: u64, at: i64| {
            Signed::sign(
                Cosignature {
                    log: log.public(),
                    size,
                    root: Digest::of(&size.to_be_bytes()),
                    timestamp_ms: at,
                    cosigner: cosigner.public(),
                },
                &cosigner,
            )
            .unwrap()
        };
        s.cosig_insert(&cosig(1, now - 10 * day)).unwrap();
        s.cosig_insert(&cosig(2, now - 3 * day)).unwrap();
        s.cosig_insert(&cosig(3, now - day)).unwrap();
        s.cosig_insert(&cosig(4, now)).unwrap();
        let obs = Signed::sign(
            Observation {
                subject: log.public(),
                ip: "203.0.113.1".parse().unwrap(),
                observed_at_ms: now - 40 * day,
                observer: cosigner.public(),
            },
            &cosigner,
        )
        .unwrap();
        s.observation_upsert(&obs).unwrap();
        s.log_head_insert(&head(&log, 1, b"x", 0), now - 8 * day)
            .unwrap();

        let n = s.prune(now, &Retention::default()).unwrap();
        // Cosignatures 1 and 2 (superseded, older than two days), the
        // observation and the old checkpoint.
        assert_eq!(n, 4);
        let sizes: Vec<u64> = s
            .cosigned_sizes(&log.public())
            .unwrap()
            .into_iter()
            .map(|(size, _)| size)
            .collect();
        assert_eq!(sizes, vec![4, 3]);
        assert!(
            s.observation(&log.public(), &cosigner.public())
                .unwrap()
                .is_none()
        );
        // Nothing left to prune.
        assert_eq!(s.prune(now, &Retention::default()).unwrap(), 0);
    }
}
