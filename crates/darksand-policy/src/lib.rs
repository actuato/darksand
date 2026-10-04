//! Darksand robotics policy service.
//!
//! Standalone replacement for the Overture robotics-policy endpoints:
//! versioned robot-mode policies with Ed25519-signed lifecycle commands,
//! nonce replay protection, and an audit trail — backed by SQLite instead
//! of Postgres + Clerk.
//!
//! Auth model (v1, documented limitation): bearer API keys provisioned out
//! of band (`DARKSAND_POLICY_KEYS="tenant:key,..."`). Every key-holder is
//! an admin. Mutating lifecycle calls additionally require the
//! `X-Policy-*` signed-command headers verified against the tenant's
//! active signing key, using the same canonical scheme as Overture:
//! `METHOD\nPATH\nKEY_VERSION\nSIGNED_AT_MS\nNONCE\nACTION\nhex(sha256(body))`.

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ─── Models ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Policy {
    pub tenant_id: String,
    pub policy_version: String,
    pub status: String,
    pub permit: bool,
    pub runtime_permitted: bool,
    pub robot_mode: String,
    pub allowed_runtimes: Vec<String>,
    pub active: bool,
    pub expires_at: Option<i64>,
    pub activated_at: Option<i64>,
    pub expired_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_by: String,
    pub updated_by: String,
    pub revoked_by: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct PolicyRequest {
    pub policy_version: Option<String>,
    #[serde(default)]
    pub permit: bool,
    #[serde(default)]
    pub runtime_permitted: bool,
    #[serde(default)]
    pub robot_mode: String,
    #[serde(default)]
    pub allowed_runtimes: Vec<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AllowListRequest {
    #[serde(default)]
    pub allowed_runtimes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigningKey {
    pub tenant_id: String,
    pub key_version: String,
    pub signer_identity: String,
    pub public_key_ed25519: String,
    pub status: String,
    pub not_before: i64,
    pub expires_at: Option<i64>,
    pub created_by: String,
    pub revoked_by: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SigningKeyRequest {
    pub key_version: String,
    pub signer_identity: Option<String>,
    pub public_key_ed25519: String,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Map of bearer API key -> tenant id, provisioned at startup.
#[derive(Debug, Clone, Default)]
pub struct PolicyKeys(pub HashMap<String, String>);

impl PolicyKeys {
    /// Parse `DARKSAND_POLICY_KEYS="tenant:key,tenant:key"`.
    pub fn from_env() -> Result<Self> {
        let raw = std::env::var("DARKSAND_POLICY_KEYS").unwrap_or_default();
        let mut map = HashMap::new();
        for pair in raw.split(',').filter(|s| !s.trim().is_empty()) {
            let (tenant, key) = pair
                .split_once(':')
                .context("DARKSAND_POLICY_KEYS entries must be tenant:key")?;
            map.insert(key.trim().to_string(), tenant.trim().to_string());
        }
        Ok(Self(map))
    }
}

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    keys: PolicyKeys,
}

impl AppState {
    pub fn open(db_path: &str, keys: PolicyKeys) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            keys,
        })
    }

    pub fn open_memory(keys: PolicyKeys) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            keys,
        })
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS policies (
    tenant_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    status TEXT NOT NULL,
    permit INTEGER NOT NULL,
    runtime_permitted INTEGER NOT NULL,
    robot_mode TEXT NOT NULL,
    allowed_runtimes TEXT NOT NULL,
    active INTEGER NOT NULL,
    expires_at INTEGER,
    activated_at INTEGER,
    expired_at INTEGER,
    revoked_at INTEGER,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    revoked_by TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, policy_version)
);
CREATE TABLE IF NOT EXISTS signing_keys (
    tenant_id TEXT NOT NULL,
    key_version TEXT NOT NULL,
    signer_identity TEXT NOT NULL,
    public_key_ed25519 TEXT NOT NULL,
    status TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    expires_at INTEGER,
    created_by TEXT NOT NULL,
    revoked_by TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, key_version)
);
CREATE TABLE IF NOT EXISTS command_nonces (
    tenant_id TEXT NOT NULL,
    key_version TEXT NOT NULL,
    action TEXT NOT NULL,
    nonce TEXT NOT NULL,
    command_hash TEXT NOT NULL,
    command_signature TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    signer_identity TEXT NOT NULL,
    signed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, key_version, action, nonce)
);
CREATE TABLE IF NOT EXISTS policy_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    signer_identity TEXT NOT NULL,
    signer_key_version TEXT NOT NULL,
    command_nonce TEXT NOT NULL,
    command_hash TEXT NOT NULL,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS key_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    key_version TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
";

// ─── Helpers ───────────────────────────────────────────────────────────────

fn normalize_version(v: Option<String>) -> String {
    match v {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => "robotics-policy.v1".to_string(),
    }
}

fn normalize_mode(m: &str) -> &str {
    match m.trim().to_lowercase().as_str() {
        "supervised" | "active" => {
            if m.trim().to_lowercase() == "supervised" {
                "supervised"
            } else {
                "active"
            }
        }
        _ => "disabled",
    }
}

fn clean_runtimes(list: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in list {
        let r = r.trim().to_string();
        if !r.is_empty() && seen.insert(r.clone()) {
            out.push(r);
        }
    }
    out
}

fn row_policy(row: &rusqlite::Row) -> rusqlite::Result<Policy> {
    let allowed: String = row.get(6)?;
    Ok(Policy {
        tenant_id: row.get(0)?,
        policy_version: row.get(1)?,
        status: row.get(2)?,
        permit: row.get::<_, i64>(3)? != 0,
        runtime_permitted: row.get::<_, i64>(4)? != 0,
        robot_mode: row.get(5)?,
        allowed_runtimes: serde_json::from_str(&allowed).unwrap_or_default(),
        active: row.get::<_, i64>(7)? != 0,
        expires_at: row.get(8)?,
        activated_at: row.get(9)?,
        expired_at: row.get(10)?,
        revoked_at: row.get(11)?,
        created_by: row.get(12)?,
        updated_by: row.get(13)?,
        revoked_by: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

fn row_key(row: &rusqlite::Row) -> rusqlite::Result<SigningKey> {
    Ok(SigningKey {
        tenant_id: row.get(0)?,
        key_version: row.get(1)?,
        signer_identity: row.get(2)?,
        public_key_ed25519: row.get(3)?,
        status: row.get(4)?,
        not_before: row.get(5)?,
        expires_at: row.get(6)?,
        created_by: row.get(7)?,
        revoked_by: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

const POLICY_COLS: &str = "tenant_id, policy_version, status, permit, runtime_permitted,
    robot_mode, allowed_runtimes, active, expires_at, activated_at, expired_at,
    revoked_at, created_by, updated_by, revoked_by, created_at, updated_at";
const KEY_COLS: &str = "tenant_id, key_version, signer_identity, public_key_ed25519,
    status, not_before, expires_at, created_by, revoked_by, created_at, updated_at";

#[derive(Debug)]
struct Authed {
    tenant: String,
}

fn bearer_tenant(headers: &HeaderMap, keys: &PolicyKeys) -> Result<Authed, StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let key = auth.strip_prefix("Bearer ").unwrap_or("").trim();
    keys.0
        .get(key)
        .map(|t| Authed { tenant: t.clone() })
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
}

/// Verified signed-command identity for a mutating call.
struct CommandAuth {
    signer_identity: String,
    key_version: String,
    nonce: String,
    command_hash: String,
}

fn decode_signature(value: &str) -> Result<[u8; 64]> {
    if let Ok(raw) = B64.decode(value.trim()) {
        if let Ok(arr) = <[u8; 64]>::try_from(raw) {
            return Ok(arr);
        }
    }
    let raw = hex::decode(value.trim()).context("signature must be base64 or hex")?;
    <[u8; 64]>::try_from(raw).map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))
}

/// Verify the X-Policy-* headers against the tenant's active signing key and
/// consume the nonce (replay ⇒ 409). Returns the verified command identity.
async fn verify_command(
    state: &AppState,
    tenant: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    action: &str,
) -> Result<CommandAuth, (StatusCode, String)> {
    let err = |c: StatusCode, m: &str| (c, m.to_string());
    let key_version = header(headers, "x-policy-key-version");
    let signature_value = header(headers, "x-policy-signature");
    let signed_at = header(headers, "x-policy-signed-at");
    let nonce = header(headers, "x-policy-nonce");
    if key_version.is_empty() || signature_value.is_empty() || signed_at.is_empty() || nonce.is_empty() {
        return Err(err(StatusCode::UNAUTHORIZED, "policy_signature_required"));
    }
    let signed_ms: i64 = signed_at
        .parse()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid_policy_signature_timestamp"))?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if (now_ms - signed_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Err(err(StatusCode::UNAUTHORIZED, "policy_signature_expired"));
    }

    let db = state.db.lock().await;
    let now = now_secs();
    let (pub_hex, signer_identity): (String, String) = db
        .query_row(
            "SELECT public_key_ed25519, signer_identity FROM signing_keys
             WHERE tenant_id = ?1 AND key_version = ?2 AND status = 'active'
               AND not_before <= ?3 AND (expires_at IS NULL OR expires_at > ?3)",
            params![tenant, key_version, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "invalid_policy_signer_key"))?;

    let pub_raw = hex::decode(pub_hex.trim())
        .map_err(|_| err(StatusCode::FORBIDDEN, "invalid_policy_signer_key"))?;
    let pub_arr: [u8; 32] = <[u8; 32]>::try_from(pub_raw)
        .map_err(|_| err(StatusCode::FORBIDDEN, "invalid_policy_signer_key"))?;
    let verifying = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|_| err(StatusCode::FORBIDDEN, "invalid_policy_signer_key"))?;
    let sig_arr =
        decode_signature(signature_value).map_err(|_| err(StatusCode::FORBIDDEN, "invalid_policy_signature"))?;
    let signature = Signature::from_bytes(&sig_arr);

    let body_hash = hex::encode(Sha256::digest(body));
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path.trim(),
        key_version.trim(),
        signed_at.trim(),
        nonce.trim(),
        action.trim(),
        body_hash
    );
    let digest = Sha256::digest(canonical.as_bytes());
    verifying
        .verify(&digest, &signature)
        .map_err(|_| err(StatusCode::FORBIDDEN, "invalid_policy_signature"))?;

    let request_signer = header(headers, "x-policy-signer");
    if !request_signer.is_empty() && request_signer != signer_identity {
        return Err(err(StatusCode::FORBIDDEN, "policy_signer_identity_mismatch"));
    }

    let command_hash = hex::encode(digest);
    let inserted = db
        .execute(
            "INSERT INTO command_nonces (tenant_id, key_version, action, nonce,
                command_hash, command_signature, actor_id, signer_identity,
                signed_at, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT (tenant_id, key_version, action, nonce) DO NOTHING",
            params![
                tenant,
                key_version,
                action,
                nonce,
                command_hash,
                signature_value,
                tenant,
                signer_identity,
                signed_ms,
                signed_ms + MAX_CLOCK_SKEW_MS,
                now,
            ],
        )
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if inserted == 0 {
        return Err(err(StatusCode::CONFLICT, "policy_command_replay"));
    }

    Ok(CommandAuth {
        signer_identity,
        key_version: key_version.to_string(),
        nonce: nonce.to_string(),
        command_hash,
    })
}

/// Verify a signed command, with a bootstrap exception: when the tenant has
/// no active signing key yet, the call is attributed to the tenant itself
/// (audited with an empty command hash, so bootstrap rows are distinguishable).
async fn maybe_verify(
    state: &AppState,
    tenant: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    action: &str,
) -> Result<CommandAuth, (StatusCode, String)> {
    let needs_sig = {
        let db = state.db.lock().await;
        tenant_has_active_key(&db, tenant)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };
    if !needs_sig {
        return Ok(CommandAuth {
            signer_identity: tenant.to_string(),
            key_version: String::new(),
            nonce: String::new(),
            command_hash: String::new(),
        });
    }
    verify_command(state, tenant, method, path, headers, body, action).await
}

fn audit_policy(
    db: &Connection,
    tenant: &str,
    policy: &Policy,
    action: &str,
    cmd: &CommandAuth,
    previous: &str,
) -> Result<()> {
    let snapshot = serde_json::to_string(policy)?;
    db.execute(
        "INSERT INTO policy_audit (tenant_id, policy_version, action, actor_id,
            signer_identity, signer_key_version, command_nonce, command_hash,
            previous_status, new_status, snapshot, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            tenant,
            policy.policy_version,
            action,
            tenant,
            cmd.signer_identity,
            cmd.key_version,
            cmd.nonce,
            cmd.command_hash,
            previous,
            policy.status,
            snapshot,
            now_secs(),
        ],
    )?;
    Ok(())
}

fn upsert_draft(
    db: &Connection,
    tenant: &str,
    req: &PolicyRequest,
    actor: &str,
) -> Result<Policy> {
    let version = normalize_version(req.policy_version.clone());
    let mode = normalize_mode(&req.robot_mode).to_string();
    let allowed = serde_json::to_string(&clean_runtimes(req.allowed_runtimes.clone()))?;
    let now = now_secs();
    db.execute(
        "INSERT INTO policies (tenant_id, policy_version, status, permit,
            runtime_permitted, robot_mode, allowed_runtimes, active, expires_at,
            created_by, updated_by, created_at, updated_at)
         VALUES (?1, ?2, 'draft', ?3, ?4, ?5, ?6, 0, ?7, ?8, ?8, ?9, ?9)
         ON CONFLICT (tenant_id, policy_version) DO UPDATE SET
            status = 'draft', permit = excluded.permit,
            runtime_permitted = excluded.runtime_permitted,
            robot_mode = excluded.robot_mode,
            allowed_runtimes = excluded.allowed_runtimes, active = 0,
            expires_at = excluded.expires_at, updated_by = excluded.updated_by,
            updated_at = ?9",
        params![
            tenant,
            version,
            req.permit as i64,
            req.runtime_permitted as i64,
            mode,
            allowed,
            req.expires_at,
            actor,
            now,
        ],
    )?;
    get_policy(db, tenant, &version)
}

fn get_policy(db: &Connection, tenant: &str, version: &str) -> Result<Policy> {
    db.query_row(
        &format!(
            "SELECT {} FROM policies WHERE tenant_id = ?1 AND policy_version = ?2",
            POLICY_COLS
        ),
        params![tenant, version],
        row_policy,
    )
    .context("policy_not_found")
}

// ─── Routes ────────────────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth = bearer_tenant(&headers, &state.keys)?;
    let db = state.db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {} FROM policies WHERE tenant_id = ?1 ORDER BY active DESC, updated_at DESC LIMIT 100",
            POLICY_COLS
        ))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let policies: Vec<Policy> = stmt
        .query_map([auth.tenant.as_str()], row_policy)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .collect::<Result<_, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "policies": policies,
        "total": policies.len(),
    })))
}

async fn create_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth = bearer_tenant(&headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    let req: PolicyRequest =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body".into()))?;
    let cmd = maybe_verify(&state, &auth.tenant, "POST", "/v1/robotics/policies", &headers, &body, "draft").await?;
    let db = state.db.lock().await;
    let policy = upsert_draft(&db, &auth.tenant, &req, &auth.tenant)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_policy(&db, &auth.tenant, &policy, "draft", &cmd, "")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn update_draft(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth = bearer_tenant(&headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    let mut req: PolicyRequest =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body".into()))?;
    req.policy_version = Some(version.clone());
    let path = format!("/v1/robotics/policies/{}", version);
    let cmd = maybe_verify(&state, &auth.tenant, "PUT", &path, &headers, &body, "update").await?;
    let db = state.db.lock().await;
    let policy = upsert_draft(&db, &auth.tenant, &req, &auth.tenant)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_policy(&db, &auth.tenant, &policy, "update", &cmd, "draft")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(policy))
}

async fn update_allow_list(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth = bearer_tenant(&headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    let version = normalize_version(Some(version));
    let req: AllowListRequest =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body".into()))?;
    let path = format!("/v1/robotics/policies/{}/allow-list", version);
    let cmd = maybe_verify(&state, &auth.tenant, "PUT", &path, &headers, &body, "allow_list").await?;
    let db = state.db.lock().await;
    let allowed = serde_json::to_string(&clean_runtimes(req.allowed_runtimes))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let now = now_secs();
    let policy: Policy = db
        .query_row(
            &format!(
                "UPDATE policies SET allowed_runtimes = ?1, updated_by = ?2, updated_at = ?3
                 WHERE tenant_id = ?4 AND policy_version = ?5 RETURNING {}",
                POLICY_COLS
            ),
            params![allowed, auth.tenant, now, auth.tenant, version],
            row_policy,
        )
        .optional()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "policy_not_found".to_string()))?;
    let prev = policy.status.clone();
    audit_policy(&db, &auth.tenant, &policy, "allow_list", &cmd, &prev)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(policy))
}

async fn activate_policy(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth = bearer_tenant(&headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    let version = normalize_version(Some(version));
    let path = format!("/v1/robotics/policies/{}/activate", version);
    let cmd = maybe_verify(&state, &auth.tenant, "POST", &path, &headers, &body, "activate").await?;
    let db = state.db.lock().await;
    let now = now_secs();
    db.execute(
        "UPDATE policies SET active = 0,
            status = CASE WHEN status = 'active' THEN 'draft' ELSE status END,
            updated_by = ?1, updated_at = ?2
         WHERE tenant_id = ?1 AND active = 1",
        params![auth.tenant, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let policy: Policy = db
        .query_row(
            &format!(
                "UPDATE policies SET status = 'active', active = 1, activated_at = ?1,
                    expired_at = NULL, revoked_at = NULL, revoked_by = NULL,
                    updated_by = ?2, updated_at = ?1
                 WHERE tenant_id = ?2 AND policy_version = ?3 RETURNING {}",
                POLICY_COLS
            ),
            params![now, auth.tenant, version],
            row_policy,
        )
        .optional()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "policy_not_found".to_string()))?;
    audit_policy(&db, &auth.tenant, &policy, "activate", &cmd, "draft")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(policy))
}

async fn lifecycle_update(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    version: &str,
    status: &str,
    audit_action: &str,
) -> Result<Policy, (StatusCode, String)> {
    let auth = bearer_tenant(headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    let version = normalize_version(Some(version.to_string()));
    let path = format!("/v1/robotics/policies/{}/{}", version, audit_action);
    let cmd = maybe_verify(state, &auth.tenant, "POST", &path, headers, body, audit_action).await?;
    let db = state.db.lock().await;
    let now = now_secs();
    let policy: Policy = if status == "revoked" {
        db.query_row(
            &format!(
                "UPDATE policies SET status = 'revoked', active = 0, revoked_at = ?1,
                    revoked_by = ?2, updated_by = ?2, updated_at = ?1
                 WHERE tenant_id = ?2 AND policy_version = ?3 RETURNING {}",
                POLICY_COLS
            ),
            params![now, auth.tenant, version],
            row_policy,
        )
    } else {
        db.query_row(
            &format!(
                "UPDATE policies SET status = 'expired', active = 0, expired_at = ?1,
                    updated_by = ?2, updated_at = ?1
                 WHERE tenant_id = ?2 AND policy_version = ?3 RETURNING {}",
                POLICY_COLS
            ),
            params![now, auth.tenant, version],
            row_policy,
        )
    }
    .optional()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "policy_not_found".to_string()))?;
    audit_policy(&db, &auth.tenant, &policy, audit_action, &cmd, "active")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(policy)
}

async fn expire_policy(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    Ok(Json(lifecycle_update(&state, &headers, &body, &version, "expired", "expire").await?))
}

async fn revoke_policy(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    Ok(Json(lifecycle_update(&state, &headers, &body, &version, "revoked", "revoke").await?))
}

async fn list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth = bearer_tenant(&headers, &state.keys)?;
    let db = state.db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {} FROM signing_keys WHERE tenant_id = ?1 ORDER BY updated_at DESC LIMIT 100",
            KEY_COLS
        ))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let keys: Vec<SigningKey> = stmt
        .query_map([auth.tenant.as_str()], row_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .collect::<Result<_, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "signing_keys": keys, "total": keys.len() })))
}

fn tenant_has_active_key(db: &Connection, tenant: &str) -> Result<bool> {
    let now = now_secs();
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM signing_keys WHERE tenant_id = ?1
          AND status = 'active' AND not_before <= ?2
          AND (expires_at IS NULL OR expires_at > ?2))",
        params![tenant, now],
        |r| r.get(0),
    )
    .context("key lookup failed")
}

async fn create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth = bearer_tenant(&headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    // Bootstrap: the first key needs no signature. After that, rotation
    // requires a live signature from the current active key.
    maybe_verify(
        &state, &auth.tenant, "POST", "/v1/robotics/policies/signing-keys",
        &headers, &body, "signing_key_create",
    )
    .await?;
    let req: SigningKeyRequest =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body".into()))?;
    let key_version = req.key_version.trim().to_string();
    let public_key = req.public_key_ed25519.trim().to_string();
    if key_version.is_empty() || public_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "invalid_signing_key".into()));
    }
    if hex::decode(&public_key).map(|b| b.len()) != Ok(32) {
        return Err((StatusCode::BAD_REQUEST, "invalid_public_key".into()));
    }
    let signer = match req.signer_identity {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => auth.tenant.clone(),
    };
    let now = now_secs();
    let db = state.db.lock().await;
    let key: SigningKey = db
        .query_row(
            &format!(
                "INSERT INTO signing_keys (tenant_id, key_version, signer_identity,
                    public_key_ed25519, status, not_before, expires_at,
                    created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'draft', COALESCE(?5, ?6), ?7, ?8, ?6, ?6)
                 RETURNING {}",
                KEY_COLS
            ),
            params![
                auth.tenant,
                key_version,
                signer,
                public_key,
                req.not_before,
                now,
                req.expires_at,
                auth.tenant,
            ],
            row_key,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let snapshot = serde_json::to_string(&key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    db.execute(
        "INSERT INTO key_audit (tenant_id, key_version, action, actor_id,
            previous_status, new_status, snapshot, occurred_at)
         VALUES (?1, ?2, 'create', ?3, '', 'draft', ?4, ?5)",
        params![auth.tenant, key.key_version, auth.tenant, snapshot, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(key)))
}

async fn key_lifecycle(
    State(state): State<AppState>,
    Path((version, lifecycle)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (status, action) = match lifecycle.as_str() {
        "activate" => ("active", "activate"),
        "revoke" => ("revoked", "revoke"),
        "expire" => ("expired", "expire"),
        _ => return Err((StatusCode::NOT_FOUND, "unknown_lifecycle".into())),
    };
    let auth = bearer_tenant(&headers, &state.keys).map_err(|c| (c, "unauthenticated".into()))?;
    let path = format!("/v1/robotics/policies/signing-keys/{}/{}", version, lifecycle);
    maybe_verify(&state, &auth.tenant, "POST", &path, &headers, &body, &format!("signing_key_{}", action)).await?;
    let db = state.db.lock().await;
    let prev: String = db
        .query_row(
            "SELECT status FROM signing_keys WHERE tenant_id = ?1 AND key_version = ?2",
            params![auth.tenant, version],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "signing_key_not_found".to_string()))?;
    let now = now_secs();
    let key: SigningKey = if status == "revoked" {
        db.query_row(
            &format!(
                "UPDATE signing_keys SET status = 'revoked', revoked_by = ?1, updated_at = ?2
                 WHERE tenant_id = ?1 AND key_version = ?3 RETURNING {}",
                KEY_COLS
            ),
            params![auth.tenant, now, version],
            row_key,
        )
    } else {
        db.query_row(
            &format!(
                "UPDATE signing_keys SET status = ?1, updated_at = ?2
                 WHERE tenant_id = ?3 AND key_version = ?4 RETURNING {}",
                KEY_COLS
            ),
            params![status, now, auth.tenant, version],
            row_key,
        )
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let snapshot = serde_json::to_string(&key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    db.execute(
        "INSERT INTO key_audit (tenant_id, key_version, action, actor_id,
            previous_status, new_status, snapshot, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![auth.tenant, key.key_version, action, auth.tenant, prev, status, snapshot, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(key))
}

/// Build the router. Split out for tests.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/robotics/policies", get(list_policies).post(create_draft))
        .route("/v1/robotics/policies/signing-keys", get(list_keys).post(create_key))
        .route(
            "/v1/robotics/policies/signing-keys/:version/:lifecycle",
            post(key_lifecycle),
        )
        .route(
            "/v1/robotics/policies/:version",
            put(update_draft),
        )
        .route(
            "/v1/robotics/policies/:version/allow-list",
            put(update_allow_list),
        )
        .route(
            "/v1/robotics/policies/:version/activate",
            post(activate_policy),
        )
        .route("/v1/robotics/policies/:version/expire", post(expire_policy))
        .route("/v1/robotics/policies/:version/revoke", post(revoke_policy))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::Signer;
    use tower::ServiceExt;

    const TENANT: &str = "tenant-a";
    const BEARER: &str = "sekret";

    fn test_state() -> AppState {
        let mut keys = HashMap::new();
        keys.insert(BEARER.to_string(), TENANT.to_string());
        AppState::open_memory(PolicyKeys(keys)).unwrap()
    }

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
    }

    fn pub_hex(key: &ed25519_dalek::SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    /// Build a request with bearer auth and, when `key` is Some, the
    /// X-Policy-* signed-command headers for (method, path, action, body).
    fn signed_req(
        key: Option<&ed25519_dalek::SigningKey>,
        key_version: &str,
        method: &str,
        path: &str,
        action: &str,
        nonce: &str,
        body: serde_json::Value,
    ) -> Request<axum::body::Body> {
        let raw = serde_json::to_vec(&body).unwrap();
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", BEARER))
            .header("content-type", "application/json");
        if let Some(sk) = key {
            let signed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string();
            let body_hash = hex::encode(Sha256::digest(&raw));
            let canonical = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}",
                method, path, key_version, signed_at, nonce, action, body_hash
            );
            let digest = Sha256::digest(canonical.as_bytes());
            let sig = B64.encode(sk.sign(&digest).to_bytes());
            builder = builder
                .header("x-policy-key-version", key_version)
                .header("x-policy-signature", sig)
                .header("x-policy-signed-at", signed_at)
                .header("x-policy-nonce", nonce);
        }
        builder.body(axum::body::Body::from(raw)).unwrap()
    }

    async fn body_json(res: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn bootstrap_and_activate(state: &AppState) -> ed25519_dalek::SigningKey {
        let sk = signing_key();
        let app = router(state.clone());
        // Bootstrap: first key needs no signature.
        let res = app
            .clone()
            .oneshot(
                signed_req(
                    None,
                    "",
                    "POST",
                    "/v1/robotics/policies/signing-keys",
                    "",
                    "",
                    serde_json::json!({
                        "key_version": "k1",
                        "public_key_ed25519": pub_hex(&sk),
                    }),
                ),
            )
            .await
            .unwrap();
        let (status, _) = body_json(res).await;
        assert_eq!(status, StatusCode::CREATED);
        // Activate it (bootstrap key can self-activate: it is not yet active,
        // so no signature is required for this first activation either).
        let res = app
            .oneshot(
                signed_req(
                    None,
                    "",
                    "POST",
                    "/v1/robotics/policies/signing-keys/k1/activate",
                    "",
                    "",
                    serde_json::json!({}),
                ),
            )
            .await
            .unwrap();
        // Activation of a draft key requires a signature only when an active
        // key already exists; none does, so this must succeed unsigned.
        let (status, _) = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "bootstrap activation");
        sk
    }

    #[tokio::test]
    async fn full_policy_lifecycle() {
        let state = test_state();
        let sk = bootstrap_and_activate(&state).await;
        let app = router(state);

        let draft = serde_json::json!({
            "permit": true,
            "runtime_permitted": true,
            "robot_mode": "supervised",
            "allowed_runtimes": ["bot-1", "bot-1", " "],
        });
        let res = app
            .clone()
            .oneshot(signed_req(
                Some(&sk), "k1", "POST", "/v1/robotics/policies", "draft", "n1", draft,
            ))
            .await
            .unwrap();
        let (status, json) = body_json(res).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(json["status"], "draft");
        assert_eq!(json["robot_mode"], "supervised");
        assert_eq!(json["allowed_runtimes"], serde_json::json!(["bot-1"]));

        // Activate.
        let res = app
            .clone()
            .oneshot(signed_req(
                Some(&sk), "k1", "POST",
                "/v1/robotics/policies/robotics-policy.v1/activate",
                "activate", "n2", serde_json::json!({}),
            ))
            .await
            .unwrap();
        let (status, json) = body_json(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "active");
        assert!(json["active"].as_bool().unwrap());

        // Unknown robot mode normalizes to disabled on update.
        let res = app
            .clone()
            .oneshot(signed_req(
                Some(&sk), "k1", "PUT", "/v1/robotics/policies/robotics-policy.v1",
                "update", "n3",
                serde_json::json!({ "robot_mode": "autonomous", "permit": true }),
            ))
            .await
            .unwrap();
        let (status, json) = body_json(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["robot_mode"], "disabled");

        // Revoke.
        let res = app
            .oneshot(signed_req(
                Some(&sk), "k1", "POST",
                "/v1/robotics/policies/robotics-policy.v1/revoke",
                "revoke", "n4", serde_json::json!({}),
            ))
            .await
            .unwrap();
        let (status, json) = body_json(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "revoked");
    }

    #[tokio::test]
    async fn replay_and_forgery_rejected() {
        let state = test_state();
        let sk = bootstrap_and_activate(&state).await;
        let app = router(state);
        let draft = serde_json::json!({ "permit": false, "robot_mode": "disabled" });

        // First use of nonce ok.
        let res = app
            .clone()
            .oneshot(signed_req(
                Some(&sk), "k1", "POST", "/v1/robotics/policies", "draft", "dup", draft.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // Same (key, action, nonce) replays => 409.
        let res = app
            .clone()
            .oneshot(signed_req(
                Some(&sk), "k1", "POST", "/v1/robotics/policies", "draft", "dup", draft.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);

        // Wrong key signs => 403.
        let other = signing_key();
        let res = app
            .clone()
            .oneshot(signed_req(
                Some(&other), "k1", "POST", "/v1/robotics/policies", "draft", "fresh", draft.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // No bearer => 401.
        let req = Request::builder()
            .method("GET")
            .uri("/v1/robotics/policies")
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
