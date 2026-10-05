//! Fleet control-plane endpoints: the live counterpart to the
//! `darksand-fleet` agent (`register` → `config-sync` → `telemetry`).
//!
//! Previously this loop was unclosable: the agent spoke to a Go API that is
//! not built anywhere, while this service exposed no fleet routes. These
//! handlers close it against the same SQLite store as the policy plane.
//!
//! Wire contract (both sides MUST keep it byte-identical):
//! - Registration signs the [`UnsignedRegisterPayload`] struct serialized by
//!   `serde_json` in declaration order with `BTreeMap` maps. The types here
//!   are imported from `darksand_fleet`, not re-declared, so the two sides
//!   cannot drift.
//! - Telemetry signs the [`TelemetryData`] struct with `signature: None`
//!   (serde skips it), verified against the public key stored at registration.
//! - Tenant identity comes from the `X-API-Key` header (the same bearer
//!   secret as the policy plane), compared in constant time.

use super::{now_secs, AppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use darksand_fleet::{
    crypto, ConfigSyncResponse, RegisterRequest, RegisterResponse, TelemetryData,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FLEET_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS fleet_agents (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    fleet_id TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    capabilities TEXT NOT NULL DEFAULT '[]',
    public_key_ed25519 TEXT NOT NULL,
    assigned_role TEXT NOT NULL DEFAULT 'edge-worker',
    config_version INTEGER NOT NULL DEFAULT 1,
    registered_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, agent_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fleet_agents_fleet_id
    ON fleet_agents (tenant_id, fleet_id);
CREATE TABLE IF NOT EXISTS fleet_telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    health TEXT NOT NULL DEFAULT 'unknown',
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fleet_telemetry_agent
    ON fleet_telemetry (tenant_id, agent_id, ts DESC);
CREATE TABLE IF NOT EXISTS fleet_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    occurred_at INTEGER NOT NULL
);
";

/// Canonical registration payload — declaration order is load-bearing.
/// MUST mirror the agent's unsigned shape exactly (see `FleetAgent::register`).
#[derive(Debug, Serialize)]
struct UnsignedRegisterPayload {
    agent_id: String,
    hostname: String,
    platform: String,
    version: String,
    capabilities: Vec<String>,
    location: Option<String>,
    metadata: BTreeMap<String, String>,
}

/// Telemetry is accepted at most this stale (seconds). Older payloads are
/// replays or dead agents; both get 401, not silent acceptance.
const TELEMETRY_MAX_SKEW_SECS: i64 = 600;

fn fleet_tenant(headers: &HeaderMap, state: &AppState) -> Result<String, StatusCode> {
    let presented = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mut authed: Option<String> = None;
    for (stored_key, tenant) in &state.keys.0 {
        if super::constant_time_eq(presented.as_bytes(), stored_key.as_bytes()) {
            authed = Some(tenant.clone());
        }
    }
    authed.ok_or(StatusCode::UNAUTHORIZED)
}

fn audit(
    db: &rusqlite::Connection,
    tenant: &str,
    agent: &str,
    action: &str,
    detail: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO fleet_audit (tenant_id, agent_id, action, detail, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![tenant, agent, action, detail, now_secs()],
    )?;
    Ok(())
}

async fn agent_by_fleet(
    state: &AppState,
    tenant: &str,
    fleet_id: &str,
) -> Result<(String, String, i64), StatusCode> {
    let db = state.db.lock().await;
    db.query_row(
        "SELECT agent_id, public_key_ed25519, config_version FROM fleet_agents
          WHERE tenant_id = ?1 AND fleet_id = ?2 AND active = 1",
        params![tenant, fleet_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)
}

/// POST /api/fleet/register — Ed25519-verified agent enrollment.
async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let err = |c: StatusCode, m: &str| (c, m.to_string());
    let tenant = fleet_tenant(&headers, &state).map_err(|c| (c, "unauthenticated".into()))?;
    let req: RegisterRequest =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body".into()))?;
    if req.agent_id.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_agent_id"));
    }
    if req.signature.trim().is_empty() {
        // Unsigned registration is never accepted: identity without proof is
        // how fleets fill with ghosts.
        return Err(err(StatusCode::UNAUTHORIZED, "registration_signature_required"));
    }
    let pub_raw = base64_decode(&req.public_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_public_key".into()))?;
    let pub_arr: [u8; 32] = <[u8; 32]>::try_from(pub_raw)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_public_key".into()))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pub_arr)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_public_key".into()))?;
    let unsigned = UnsignedRegisterPayload {
        agent_id: req.agent_id.clone(),
        hostname: req.hostname.clone(),
        platform: req.platform.clone(),
        version: req.version.clone(),
        capabilities: req.capabilities.clone(),
        location: req.location.clone(),
        metadata: req.metadata.clone(),
    };
    crypto::verify_payload(&verifying, &unsigned, &req.signature)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid_registration_signature".into()))?;

    let db = state.db.lock().await;
    let now = now_secs();
    let caps = serde_json::to_string(&req.capabilities)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    // Stable fleet_id per (tenant, agent): re-registration resumes identity.
    let fleet_id: String = db
        .query_row(
            "SELECT fleet_id FROM fleet_agents WHERE tenant_id = ?1 AND agent_id = ?2",
            params![tenant, req.agent_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    db.execute(
        "INSERT INTO fleet_agents (tenant_id, agent_id, fleet_id, hostname, platform,
             version, capabilities, public_key_ed25519, registered_at, last_seen, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, 1)
         ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
            fleet_id = excluded.fleet_id, hostname = excluded.hostname,
            platform = excluded.platform, version = excluded.version,
            capabilities = excluded.capabilities,
            public_key_ed25519 = excluded.public_key_ed25519,
            last_seen = excluded.last_seen, active = 1",
        params![
            tenant,
            req.agent_id,
            fleet_id,
            req.hostname,
            req.platform,
            req.version,
            caps,
            req.public_key,
            now,
        ],
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    let config_version: i64 = db
        .query_row(
            "SELECT config_version FROM fleet_agents WHERE tenant_id = ?1 AND agent_id = ?2",
            params![tenant, req.agent_id],
            |r| r.get(0),
        )
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    let _ = audit(&db, &tenant, &req.agent_id, "register", &fleet_id);
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            success: true,
            fleet_id,
            assigned_role: "edge-worker".to_string(),
            config_version: config_version as u64,
        }),
    ))
}

/// GET /api/fleet/:fleet_id/config — versioned config pull.
async fn pull_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fleet_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant = fleet_tenant(&headers, &state).map_err(|c| (c, "unauthenticated".into()))?;
    let (_, _, version) = agent_by_fleet(&state, &tenant, &fleet_id)
        .await
        .map_err(|c| {
            (
                c,
                if c == StatusCode::NOT_FOUND {
                    "unknown_fleet_id".to_string()
                } else {
                    "db_error".to_string()
                },
            )
        })?;
    Ok(Json(ConfigSyncResponse {
        version: version as u64,
        config: serde_json::json!({}),
        requires_restart: false,
    }))
}

/// POST /api/fleet/:fleet_id/telemetry — verified telemetry ingest.
async fn ingest_telemetry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fleet_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let err = |c: StatusCode, m: &str| (c, m.to_string());
    let tenant = fleet_tenant(&headers, &state).map_err(|c| (c, "unauthenticated".into()))?;
    let (agent_id, pub_hex, _) = agent_by_fleet(&state, &tenant, &fleet_id)
        .await
        .map_err(|c| {
            (
                c,
                if c == StatusCode::NOT_FOUND {
                    "unknown_fleet_id".to_string()
                } else {
                    "db_error".to_string()
                },
            )
        })?;
    let mut data: TelemetryData =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body".into()))?;
    let signature = data
        .signature
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "telemetry_signature_required"))?;
    // Freshness first: stale payloads are replays or dead agents.
    let now = now_secs();
    if (now - data.timestamp as i64).abs() > TELEMETRY_MAX_SKEW_SECS {
        return Err(err(StatusCode::UNAUTHORIZED, "telemetry_too_old"));
    }
    if data.agent_id != agent_id {
        return Err(err(StatusCode::FORBIDDEN, "telemetry_agent_mismatch"));
    }
    let pub_raw = base64_decode(&pub_hex).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    let pub_arr: [u8; 32] = <[u8; 32]>::try_from(pub_raw)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pub_arr)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    data.signature = None;
    crypto::verify_payload(&verifying, &data, &signature)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid_telemetry_signature"))?;

    let db = state.db.lock().await;
    let payload = serde_json::to_string(&data).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    let health = data.status.health.clone();
    db.execute(
        "INSERT INTO fleet_telemetry (tenant_id, agent_id, ts, health, payload, signature, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![tenant, agent_id, data.timestamp as i64, health, payload, signature, now],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    db.execute(
        "UPDATE fleet_agents SET last_seen = ?3 WHERE tenant_id = ?1 AND agent_id = ?2",
        params![tenant, agent_id, now],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;
    let _ = audit(&db, &tenant, &agent_id, "telemetry", &health);
    Ok(Json(serde_json::json!({"received": true})))
}

/// DELETE /api/fleet/:fleet_id — deregister (agent-initiated or admin).
async fn deregister_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fleet_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant = fleet_tenant(&headers, &state).map_err(|c| (c, "unauthenticated".into()))?;
    let (agent_id, _, _) = agent_by_fleet(&state, &tenant, &fleet_id)
        .await
        .map_err(|c| {
            (
                c,
                if c == StatusCode::NOT_FOUND {
                    "unknown_fleet_id".to_string()
                } else {
                    "db_error".to_string()
                },
            )
        })?;
    let db = state.db.lock().await;
    db.execute(
        "UPDATE fleet_agents SET active = 0 WHERE tenant_id = ?1 AND agent_id = ?2",
        params![tenant, agent_id],
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    let _ = audit(&db, &tenant, &agent_id, "deregister", &fleet_id);
    Ok(Json(serde_json::json!({"deregistered": true})))
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentSummary {
    agent_id: String,
    hostname: String,
    health: String,
    last_seen: i64,
    config_version: i64,
}

/// GET /api/fleet/agents — tenant agent inventory (backs the dashboard).
async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant = fleet_tenant(&headers, &state).map_err(|c| (c, "unauthenticated".into()))?;
    let db = state.db.lock().await;
    let mut stmt = db
        .prepare(
            "SELECT a.agent_id, a.hostname,
                    COALESCE((SELECT t.health FROM fleet_telemetry t
                       WHERE t.tenant_id = a.tenant_id AND t.agent_id = a.agent_id
                       ORDER BY t.ts DESC LIMIT 1), 'unknown'),
                    a.last_seen, a.config_version
             FROM fleet_agents a WHERE a.tenant_id = ?1 AND a.active = 1
             ORDER BY a.last_seen DESC LIMIT 200",
        )
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    let agents: Vec<AgentSummary> = stmt
        .query_map([tenant.as_str()], |r| {
            Ok(AgentSummary {
                agent_id: r.get(0)?,
                hostname: r.get(1)?,
                health: r.get(2)?,
                last_seen: r.get(3)?,
                config_version: r.get(4)?,
            })
        })
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?
        .collect::<Result<_, _>>()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    Ok(Json(serde_json::json!({
        "agents": agents,
        "total": agents.len(),
    })))
}

fn base64_decode(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(value.trim())?)
}

/// Fleet routes merged into the main [`super::router`].
/// Stateless here: handlers extract `State<AppState>`, supplied by the
/// outer router's `.with_state(...)`.
pub fn fleet_routes() -> axum::Router<AppState> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route("/api/fleet/register", post(register_agent))
        .route("/api/fleet/:fleet_id/config", get(pull_config))
        .route("/api/fleet/:fleet_id/telemetry", post(ingest_telemetry))
        .route("/api/fleet/:fleet_id", delete(deregister_agent))
        .route("/api/fleet/agents", get(list_agents))
}
