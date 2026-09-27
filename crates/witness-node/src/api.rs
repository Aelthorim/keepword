//! The node's public HTTP API, used by peers and verifiers.
//!
//! Everything here is either a signed statement or hashes, except raw blobs,
//! which are only served for hosts on `network.serve_content_hosts`. The web
//! UI, which shows page content, is a separate router meant for localhost.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use witness_core::net::Descriptor;
use witness_core::statement::Signed;
use witness_core::{Digest, SignedAttestation, merkle, now_ms};

use crate::Node;
use crate::federation::{GossipPage, IdList, PushRequest};

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/v1/descriptor", get(descriptor))
        .route("/v1/peers", get(peers))
        .route("/v1/log/head", get(head))
        .route("/v1/log/leaves", get(leaves))
        .route("/v1/log/consistency", get(consistency))
        .route("/v1/log/inclusion/{id}", get(inclusion))
        .route("/v1/attestation/{id}", get(attestation))
        .route("/v1/attestations", post(attestations))
        .route("/v1/bundle/{id}", get(bundle))
        .route("/v1/blob/{hash}", get(blob))
        .route("/v1/gossip", get(gossip_pull).post(gossip_push))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(node)
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
    Json(node.descriptor.clone())
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
    let leaves = node.store.leaves()?;
    let old = *q.get("old").ok_or_else(|| bad("old is required"))? as usize;
    let new = q.get("new").map(|n| *n as usize).unwrap_or(leaves.len());
    if new > leaves.len() || old > new {
        return Err(bad("sizes out of range"));
    }
    let proof = merkle::consistency_proof(&leaves[..new], old).unwrap_or_default();
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
    let leaves = node.store.leaves()?;
    let proof = merkle::inclusion_proof(&leaves[..head.head.size as usize], idx as usize)
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

fn content_allowed(node: &Node, url: &str) -> bool {
    let Some(host) = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    else {
        return false;
    };
    node.config
        .network
        .serve_content_hosts
        .iter()
        .map(|h| h.trim_start_matches('.').to_ascii_lowercase())
        .any(|h| host == h || host.ends_with(&format!(".{h}")))
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

fn client_ip(node: &Node, addr: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if node.config.network.trust_forwarded_for {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    addr.ip()
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
    let ip = client_ip(&node, addr, &headers);
    let node2 = node.clone();
    let resp = tokio::task::spawn_blocking(move || node2.receive_push(req, ip)).await??;
    Ok(Json(resp).into_response())
}
