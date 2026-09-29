//! The node's public HTTP API, used by peers and verifiers.
//!
//! Everything here is either a signed statement or hashes, except raw blobs,
//! which are only served for hosts on `network.serve_content_hosts`. The web
//! UI, which shows page content, is a separate router meant for localhost.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use witness_core::net::Descriptor;
use witness_core::statement::Signed;
use witness_core::{Digest, SignedAttestation, now_ms};

use crate::Node;
use crate::federation::{GossipPage, IdList, PushRequest};

pub fn router(node: Arc<Node>) -> Router {
    let limiter = Arc::new(RateLimiter::new(
        node.config.network.api_requests_per_minute,
    ));
    Router::new()
        .route("/v1/descriptor", get(descriptor))
        .route("/v1/peers", get(peers))
        .route("/v1/log/head", get(head))
        .route("/v1/log/checkpoint", get(checkpoint))
        .route("/v1/log/leaves", get(leaves))
        .route("/v1/log/consistency", get(consistency))
        .route("/v1/log/inclusion/{id}", get(inclusion))
        .route("/v1/attestation/{id}", get(attestation))
        .route(
            "/v1/attestations",
            get(attestations_by_url).post(attestations),
        )
        .route("/v1/cosignatures", post(cosignature))
        .route("/v1/bundle/{id}", get(bundle))
        .route("/v1/blob/{hash}", get(blob))
        .route("/v1/gossip", get(gossip_pull).post(gossip_push))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            (node.clone(), limiter),
            rate_limit,
        ))
        .with_state(node)
}

/// Token buckets per client address: `per_minute` tokens, refilled evenly.
pub struct RateLimiter {
    per_minute: u32,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

/// Buckets kept at most; full ones are dropped first when it fills up.
const MAX_BUCKETS: usize = 100_000;

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        RateLimiter {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take a token for `ip`; false when it has none left.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let cap = self.per_minute as f64;
        let rate = cap / 60.0;
        let key = match ip {
            IpAddr::V6(v6) => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
            v4 => v4,
        };
        let mut b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if b.len() >= MAX_BUCKETS && !b.contains_key(&key) {
            b.retain(|_, (tokens, t)| {
                *tokens + now.saturating_duration_since(*t).as_secs_f64() * rate < cap
            });
            if b.len() >= MAX_BUCKETS {
                return false;
            }
        }
        let (tokens, t) = b.entry(key).or_insert((cap, now));
        *tokens = (*tokens + now.saturating_duration_since(*t).as_secs_f64() * rate).min(cap);
        *t = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn rate_limit(
    State((node, limiter)): State<(Arc<Node>, Arc<RateLimiter>)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    // Without the real client address (a reverse proxy this node doesn't
    // trust, a LAN, proxies that didn't say), every client would share one
    // bucket.
    let known = node.proxies.client(addr.ip(), req.headers()).filter(|ip| {
        node.config.network.trust_forwarded_for || witness_capture::netpolicy::is_public(*ip)
    });
    if known.is_none_or(|ip| limiter.allow(ip, Instant::now())) {
        next.run(req).await
    } else {
        let mut r =
            ApiError(StatusCode::TOO_MANY_REQUESTS, "too many requests".into()).into_response();
        r.headers_mut()
            .insert("retry-after", axum::http::HeaderValue::from_static("10"));
        r
    }
}

struct ApiError(StatusCode, String);

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not found".into())
}

fn parse_id(s: &str) -> Result<Digest, ApiError> {
    s.parse().map_err(|_| bad("expected a 64-character hex ID"))
}

async fn descriptor(State(node): State<Arc<Node>>) -> Json<Signed<Descriptor>> {
    Json(node.descriptor())
}

async fn peers(State(node): State<Arc<Node>>) -> ApiResult<Vec<Signed<Descriptor>>> {
    let cutoff = now_ms() - 7 * 86_400_000;
    Ok(Json(
        node.store
            .peers()?
            .into_iter()
            .filter(|p| p.endpoint.is_some() && p.descriptor.body.issued_at_ms >= cutoff)
            .map(|p| p.descriptor)
            .collect(),
    ))
}

async fn head(State(node): State<Arc<Node>>) -> Result<Response, ApiError> {
    match node.store.latest_tree_head()? {
        Some(h) => Ok(Json(h).into_response()),
        None => Err(not_found()),
    }
}

/// The head auditors cosign this interval (see `Node::checkpoint`).
async fn checkpoint(State(node): State<Arc<Node>>) -> Result<Response, ApiError> {
    match node.checkpoint()? {
        Some(h) => Ok(Json(h).into_response()),
        None => Err(not_found()),
    }
}

async fn leaves(
    State(node): State<Arc<Node>>,
    Query(q): Query<HashMap<String, u64>>,
) -> ApiResult<Vec<Digest>> {
    let (Some(&start), Some(&end)) = (q.get("start"), q.get("end")) else {
        return Err(bad("start and end are required"));
    };
    if end <= start || end - start > 1000 {
        return Err(bad("0 < end - start <= 1000"));
    }
    let ids = node.store.leaf_ids_range(start, end)?;
    if ids.is_empty() {
        return Err(not_found());
    }
    Ok(Json(ids))
}

async fn consistency(
    State(node): State<Arc<Node>>,
    Query(q): Query<HashMap<String, u64>>,
) -> Result<Response, ApiError> {
    let old = *q.get("old").ok_or_else(|| bad("old is required"))? as usize;
    let new = q.get("new").map(|n| *n as usize);
    let (new, proof) = node.store.with_merkle(|m| {
        let new = new.unwrap_or(m.len());
        (new, m.consistency_proof(old, new))
    })?;
    let proof = proof.ok_or_else(|| bad("sizes out of range"))?;
    Ok(
        Json(serde_json::json!({ "old_size": old, "new_size": new, "proof": proof }))
            .into_response(),
    )
}

async fn inclusion(
    State(node): State<Arc<Node>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;
    let idx = node.store.leaf_index(&id)?.ok_or_else(not_found)?;
    let head = node.store.latest_tree_head()?.ok_or_else(not_found)?;
    let proof = node
        .store
        .with_merkle(|m| m.inclusion_proof(head.head.size as usize, idx as usize))?
        .ok_or_else(not_found)?;
    Ok(
        Json(serde_json::json!({ "leaf_index": idx, "proof": proof, "tree_head": head }))
            .into_response(),
    )
}

async fn attestation(
    State(node): State<Arc<Node>>,
    Path(id): Path<String>,
) -> ApiResult<SignedAttestation> {
    let id = parse_id(&id)?;
    Ok(Json(node.store.get(&id)?.ok_or_else(not_found)?.signed))
}

async fn attestations(
    State(node): State<Arc<Node>>,
    Json(req): Json<IdList>,
) -> ApiResult<Vec<SignedAttestation>> {
    if req.ids.len() > 500 {
        return Err(bad("at most 500 IDs per request"));
    }
    let mut out = Vec::new();
    for id in req.ids {
        // Erased attestations are simply missing.
        if let Some(r) = node.store.get(&id)? {
            out.push(r.signed);
        }
    }
    Ok(Json(out))
}

/// This node's own attestations of a URL since a time (newest 500), for
/// witnesses computing a verdict.
async fn attestations_by_url(
    State(node): State<Arc<Node>>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Vec<SignedAttestation>> {
    let url = q.get("url").ok_or_else(|| bad("url is required"))?;
    let since: i64 = match q.get("since") {
        Some(s) => s.parse().map_err(|_| bad("since must be milliseconds"))?,
        None => 0,
    };
    let url = witness_core::target::canonical_url(url).map_err(|_| bad("bad url"))?;
    let mut out: Vec<SignedAttestation> = node
        .store
        .history(url.as_str())?
        .into_iter()
        .map(|r| r.signed)
        .filter(|a| a.attestation.fetched_at_ms >= since)
        .collect();
    let skip = out.len().saturating_sub(500);
    out.drain(..skip);
    Ok(Json(out))
}

/// An auditor delivering its cosignature of this node's log.
async fn cosignature(
    State(node): State<Arc<Node>>,
    Json(c): Json<Signed<witness_core::net::Cosignature>>,
) -> ApiResult<serde_json::Value> {
    if node.receive_cosignature(&c)? {
        Ok(Json(serde_json::json!({ "accepted": true })))
    } else {
        Ok(Json(serde_json::json!({ "accepted": false })))
    }
}

fn content_allowed(node: &Node, url: &str) -> bool {
    url::Url::parse(url)
        .is_ok_and(|u| crate::host_listed(&node.config.network.serve_content_hosts, &u))
}

async fn bundle(
    State(node): State<Arc<Node>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;
    let rec = node.store.get(&id)?.ok_or_else(not_found)?;
    let with_content = content_allowed(&node, &rec.signed.attestation.url);
    Ok(Json(node.bundle(&rec, with_content)?).into_response())
}

async fn blob(
    State(node): State<Arc<Node>>,
    Path(hash): Path<String>,
) -> Result<Response, ApiError> {
    let d = parse_id(&hash)?;
    let urls = node.store.urls_referencing(&d)?;
    if !urls.iter().any(|u| content_allowed(&node, u)) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "content for this host is not served".into(),
        ));
    }
    let bytes = node.store.blobs.get(&d)?.ok_or_else(not_found)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response())
}

async fn gossip_pull(
    State(node): State<Arc<Node>>,
    Query(q): Query<HashMap<String, i64>>,
) -> ApiResult<GossipPage> {
    let after = q.get("after").copied().unwrap_or(0);
    let limit = q.get("limit").copied().unwrap_or(500).clamp(1, 500) as u32;
    Ok(Json(GossipPage {
        messages: node.store.gossip_since(after, limit)?,
    }))
}

async fn gossip_push(
    State(node): State<Arc<Node>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PushRequest>,
) -> Result<Response, ApiError> {
    if req.messages.len() > 1000 {
        return Err(bad("at most 1000 messages per push"));
    }
    // Where the peer connects from places it, so this must not be
    // forgeable (see `proxies`).
    let from = node.proxies.client(addr.ip(), &headers);
    let node2 = node.clone();
    let resp = tokio::task::spawn_blocking(move || node2.receive_push(req, from)).await??;
    Ok(Json(resp).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_limit_buckets_refill() {
        let l = RateLimiter::new(60);
        let t0 = Instant::now();
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "203.0.113.8".parse().unwrap();
        for _ in 0..60 {
            assert!(l.allow(a, t0));
        }
        assert!(!l.allow(a, t0), "burst exhausted");
        assert!(l.allow(b, t0), "other addresses have their own bucket");
        assert!(
            l.allow(a, t0 + Duration::from_secs(1)),
            "one token a second"
        );
        assert!(!l.allow(a, t0 + Duration::from_secs(1)));
        // One IPv6 /64 is one client.
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8::ffff:2".parse().unwrap();
        for _ in 0..60 {
            assert!(l.allow(v6, t0));
        }
        assert!(!l.allow(v6b, t0));
        assert!(RateLimiter::new(0).allow(a, t0), "0 = no limit");
    }
}
