//! `darksand-policy` server binary.
//!
//! Env:
//! - `DARKSAND_POLICY_ADDR` (default `127.0.0.1:8085`)
//! - `DARKSAND_POLICY_DB` (default `darksand-policy.db`)
//! - `DARKSAND_POLICY_KEYS` (`tenant:key,tenant:key` — required)

use anyhow::{Context, Result};
use darksand_policy::{AppState, PolicyKeys};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "darksand_policy=info".into()),
        )
        .json()
        .init();

    let keys = PolicyKeys::from_env()?;
    if keys.0.is_empty() {
        anyhow::bail!("DARKSAND_POLICY_KEYS is empty: set tenant:key pairs first");
    }
    let db_path =
        std::env::var("DARKSAND_POLICY_DB").unwrap_or_else(|_| "darksand-policy.db".into());
    let addr =
        std::env::var("DARKSAND_POLICY_ADDR").unwrap_or_else(|_| "127.0.0.1:8085".into());

    let state = AppState::open(&db_path, keys)?;
    let app = darksand_policy::router(state);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {}", addr))?;
    tracing::info!("darksand-policy listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
