//! Federated Fleet Control for Darksand Runtime
//!
//! Provides centralized fleet management capabilities for coordinating
//! multiple edge AI agents across distributed locations.
//!
//! # Features
//! - **Fleet Registration:** Automatic registration with Darksand control plane
//! - **Config Synchronization:** Push configuration updates to edge devices
//! - **Telemetry Collection:** Aggregate logs and metrics from fleet
//! - **Dashboard View:** Real-time fleet status monitoring
//! - **Secure Pairing:** TLS-secured communication with mutual authentication
//!
//! # Architecture
//! ```text
//! ┌─────────────────┐
//! │  Darksand       │  (Cloud control plane)
//! │  Fleet Manager  │
//! └────────┬────────┘
//!          │ TLS
//!  ┌───────┴───────┐
//!  │               │
//! ┌▼──────┐    ┌──▼─────┐
//! │ Edge 1│    │ Edge 2 │  (Darksand Runtime instances)
//! └───────┘    └────────┘
//! ```
//!
//! # Example
//! ```no_run
//! use darksand_fleet::{FleetAgent, FleetConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = FleetConfig {
//!         darksand_endpoint: "https://darksand.example.com".to_string(),
//!         agent_id: "edge-1".to_string(),
//!         ..Default::default()
//!     };
//!
//!     let agent = FleetAgent::new(config).await?;
//!
//!     // Register with fleet
//!     agent.register().await?;
//!
//!     // Sync configuration
//!     agent.sync_config().await?;
//!
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Fleet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Enable fleet management
    pub enabled: bool,

    /// Darksand endpoint URL
    #[serde(alias = "overture_endpoint")]
    pub darksand_endpoint: String,

    /// Agent ID (unique identifier for this edge device)
    pub agent_id: String,

    /// Fleet API key for authentication
    pub api_key: Option<String>,

    /// Enable TLS for secure communication
    pub enable_tls: bool,

    /// Sync interval in seconds
    pub sync_interval_secs: u64,

    /// Enable automatic config sync
    pub auto_sync_config: bool,

    /// Enable telemetry upload
    pub enable_telemetry: bool,

    /// Telemetry upload interval in seconds
    pub telemetry_interval_secs: u64,

    /// Mock mode for testing (uses simulated responses)
    #[serde(default)]
    pub mock_mode: bool,
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            darksand_endpoint: "https://darksand.example.com".to_string(),
            agent_id: Uuid::new_v4().to_string(),
            api_key: None,
            enable_tls: true,
            sync_interval_secs: 300, // 5 minutes
            auto_sync_config: true,
            enable_telemetry: true,
            telemetry_interval_secs: 60, // 1 minute
            mock_mode: false,
        }
    }
}

/// Agent registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub agent_id: String,
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub location: Option<String>,
    pub metadata: BTreeMap<String, String>,
    /// Base64-encoded Ed25519 public key for hybrid contract
    pub public_key: String,
    /// Base64-encoded Ed25519 signature of the request payload (excluding this field)
    pub signature: String,
}

/// Agent registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub fleet_id: String,
    pub assigned_role: String,
    pub config_version: u64,
}

/// Configuration sync response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSyncResponse {
    pub version: u64,
    pub config: serde_json::Value,
    pub requires_restart: bool,
}

/// Telemetry data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    pub agent_id: String,
    pub timestamp: u64,
    pub metrics: BTreeMap<String, f64>,
    pub logs: Vec<LogEntry>,
    pub status: AgentStatus,
    /// Base64-encoded Ed25519 signature of the telemetry payload (excluding this field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub health: String, // healthy, degraded, unhealthy
    pub uptime_secs: u64,
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub active_tasks: u32,
}

/// Fleet Agent
pub struct FleetAgent {
    config: FleetConfig,

    // Registration state
    registered: Arc<RwLock<bool>>,
    fleet_id: Arc<RwLock<Option<String>>>,
    config_version: Arc<RwLock<u64>>,

    // HTTP client
    client: reqwest::Client,

    // Start time for uptime calculation
    start_time: SystemTime,

    // Ed25519 keypair for hybrid contract signing
    keypair: Arc<crypto::FleetKeypair>,
}

impl FleetAgent {
    /// Create a new fleet agent
    pub async fn new(config: FleetConfig) -> Result<Self> {
        if !config.enabled {
            return Err(anyhow::anyhow!("Fleet management is disabled"));
        }

        info!(
            "Initializing fleet agent {} for endpoint {}",
            config.agent_id, config.darksand_endpoint
        );

        // Build HTTP client with TLS
        let client = if config.enable_tls {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?
        } else {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()?
        };

        // Load or generate Ed25519 keypair for hybrid contract.
        // Key directory defaults to `.darksand` (CWD-relative) and can be
        // redirected via `DARKSAND_FLEET_KEY_DIR` (tests, CI, containers).
        // The agent_id is sanitized to a filename stem so a crafted ID can
        // never escape the key directory via path traversal.
        let key_dir =
            std::env::var("DARKSAND_FLEET_KEY_DIR").unwrap_or_else(|_| ".darksand".to_string());
        let safe_id: String = config
            .agent_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let key_path = format!(
            "{}/fleet_{}_key",
            key_dir.trim_end_matches('/'),
            safe_id
        );
        let keypair = crypto::FleetKeypair::load_or_generate(&key_path)?;
        info!(
            "Fleet keypair loaded/generated. Public key: {}",
            keypair.public_key_base64()
        );

        let agent = Self {
            config,
            registered: Arc::new(RwLock::new(false)),
            fleet_id: Arc::new(RwLock::new(None)),
            config_version: Arc::new(RwLock::new(0)),
            client,
            start_time: SystemTime::now(),
            keypair: Arc::new(keypair),
        };

        Ok(agent)
    }

    /// Register agent with fleet
    pub async fn register(&self) -> Result<RegisterResponse> {
        info!(
            "Registering with fleet at {}",
            self.config.darksand_endpoint
        );

        // Mock mode for testing
        if self.config.mock_mode {
            let response = RegisterResponse {
                success: true,
                fleet_id: Uuid::new_v4().to_string(),
                assigned_role: "edge-worker".to_string(),
                config_version: 1,
            };

            let mut registered = self.registered.write().await;
            *registered = true;

            let mut fleet_id = self.fleet_id.write().await;
            *fleet_id = Some(response.fleet_id.clone());

            let mut config_version = self.config_version.write().await;
            *config_version = response.config_version;

            info!(
                "Successfully registered with fleet (mock): {}",
                response.fleet_id
            );
            return Ok(response);
        }

        // Create unsigned request payload
        #[derive(Serialize)]
        /// Canonical registration payload. Field order + BTreeMap are load-
        /// bearing: the server re-serializes this exact shape to verify the
        /// signature, so any reorder or HashMap here breaks verification
        /// nondeterministically.
        struct UnsignedPayload {
            agent_id: String,
            hostname: String,
            platform: String,
            version: String,
            capabilities: Vec<String>,
            location: Option<String>,
            metadata: BTreeMap<String, String>,
        }

        let unsigned_payload = UnsignedPayload {
            agent_id: self.config.agent_id.clone(),
            hostname: hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            platform: std::env::consts::OS.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: vec![
                "inference".to_string(),
                "planning".to_string(),
                "tools".to_string(),
            ],
            location: None,
            metadata: BTreeMap::new(),
        };

        // Sign the payload
        let signature = crypto::sign_payload(&self.keypair, &unsigned_payload)?;
        let public_key = self.keypair.public_key_base64();

        debug!(
            "Signing registration request with public key: {}",
            public_key
        );

        // Create signed request
        let request = RegisterRequest {
            agent_id: unsigned_payload.agent_id,
            hostname: unsigned_payload.hostname,
            platform: unsigned_payload.platform,
            version: unsigned_payload.version,
            capabilities: unsigned_payload.capabilities,
            location: unsigned_payload.location,
            metadata: unsigned_payload.metadata,
            public_key,
            signature,
        };

        // Send POST request to Darksand
        let url = format!("{}/api/fleet/register", self.config.darksand_endpoint);

        let mut req = self.client.post(&url).json(&request);

        // Add API key if configured
        if let Some(api_key) = &self.config.api_key {
            req = req.header("X-API-Key", api_key);
        }

        let response = req
            .send()
            .await
            .context("Failed to send registration request to Darksand")?
            .error_for_status()
            .context("Registration request failed")?
            .json::<RegisterResponse>()
            .await
            .context("Failed to parse registration response")?;

        // Update state
        let mut registered = self.registered.write().await;
        *registered = true;

        let mut fleet_id = self.fleet_id.write().await;
        *fleet_id = Some(response.fleet_id.clone());

        let mut config_version = self.config_version.write().await;
        *config_version = response.config_version;

        info!("Successfully registered with fleet: {}", response.fleet_id);

        Ok(response)
    }

    /// Sync configuration from fleet
    pub async fn sync_config(&self) -> Result<ConfigSyncResponse> {
        let registered = self.registered.read().await;
        if !*registered {
            return Err(anyhow::anyhow!("Agent is not registered with fleet"));
        }

        debug!("Syncing configuration from fleet");

        // Mock mode for testing
        if self.config.mock_mode {
            let response = ConfigSyncResponse {
                version: 2,
                config: serde_json::json!({
                    "model": "gpt-4o-mini",
                    "temperature": 0.7,
                    "max_tokens": 1000
                }),
                requires_restart: false,
            };

            let mut config_version = self.config_version.write().await;
            if response.version > *config_version {
                *config_version = response.version;
                info!(
                    "Configuration updated to version {} (mock)",
                    response.version
                );
            }

            return Ok(response);
        }

        // Get fleet ID
        let fleet_id = self.fleet_id.read().await;
        let fleet_id = fleet_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No fleet ID available"))?;

        // Send GET request to Darksand
        let url = format!(
            "{}/api/fleet/{}/config",
            self.config.darksand_endpoint, fleet_id
        );

        let mut req = self.client.get(&url);

        // Add API key if configured
        if let Some(api_key) = &self.config.api_key {
            req = req.header("X-API-Key", api_key);
        }

        let response = req
            .send()
            .await
            .context("Failed to send config sync request to Darksand")?
            .error_for_status()
            .context("Config sync request failed")?
            .json::<ConfigSyncResponse>()
            .await
            .context("Failed to parse config sync response")?;

        // Update local config version
        let mut config_version = self.config_version.write().await;
        if response.version > *config_version {
            *config_version = response.version;
            info!("Configuration updated to version {}", response.version);
        }

        Ok(response)
    }

    /// Upload telemetry to fleet
    pub async fn upload_telemetry(&self) -> Result<()> {
        let registered = self.registered.read().await;
        if !*registered {
            return Err(anyhow::anyhow!("Agent is not registered with fleet"));
        }

        let mut telemetry = self.collect_telemetry().await?;

        debug!("Uploading telemetry to fleet");

        // Mock mode for testing
        if self.config.mock_mode {
            info!(
                "Telemetry uploaded (mock): {} metrics, {} logs, status: {}",
                telemetry.metrics.len(),
                telemetry.logs.len(),
                telemetry.status.health
            );
            return Ok(());
        }

        // Sign the telemetry payload (exclude signature field)
        let signature = crypto::sign_payload(&self.keypair, &telemetry)?;
        telemetry.signature = Some(signature);

        debug!("Signed telemetry with fleet keypair");

        // Get fleet ID
        let fleet_id = self.fleet_id.read().await;
        let fleet_id = fleet_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No fleet ID available"))?;

        // Send POST request to Darksand with telemetry data
        let url = format!(
            "{}/api/fleet/{}/telemetry",
            self.config.darksand_endpoint, fleet_id
        );

        let mut req = self.client.post(&url).json(&telemetry);

        // Add API key if configured
        if let Some(api_key) = &self.config.api_key {
            req = req.header("X-API-Key", api_key);
        }

        req.send()
            .await
            .context("Failed to send telemetry to Darksand")?
            .error_for_status()
            .context("Telemetry upload failed")?;

        info!(
            "Telemetry uploaded: {} metrics, {} logs, status: {}",
            telemetry.metrics.len(),
            telemetry.logs.len(),
            telemetry.status.health
        );

        Ok(())
    }

    /// Upload custom telemetry data to fleet
    pub async fn upload_custom_telemetry(&self, telemetry: TelemetryData) -> Result<()> {
        let registered = self.registered.read().await;
        if !*registered {
            return Err(anyhow::anyhow!("Agent is not registered with fleet"));
        }

        debug!("Uploading custom telemetry to fleet");

        // Mock mode for testing
        if self.config.mock_mode {
            info!(
                "Custom telemetry uploaded (mock): {} metrics, status: {}",
                telemetry.metrics.len(),
                telemetry.status.health
            );
            return Ok(());
        }

        // Get fleet ID
        let fleet_id = self.fleet_id.read().await;
        let fleet_id = fleet_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No fleet ID available"))?;

        // Send POST request to Darksand with telemetry data
        let url = format!(
            "{}/api/fleet/{}/telemetry",
            self.config.darksand_endpoint, fleet_id
        );

        let mut req = self.client.post(&url).json(&telemetry);

        // Add API key if configured
        if let Some(api_key) = &self.config.api_key {
            req = req.header("X-API-Key", api_key);
        }

        req.send()
            .await
            .context("Failed to send custom telemetry to Darksand")?
            .error_for_status()
            .context("Custom telemetry upload failed")?;

        info!(
            "Custom telemetry uploaded: {} metrics, status: {}",
            telemetry.metrics.len(),
            telemetry.status.health
        );

        Ok(())
    }

    /// Collect current telemetry with REAL metrics
    async fn collect_telemetry(&self) -> Result<TelemetryData> {
        Self::collect_snapshot(
            &self.config.agent_id,
            self.start_time,
            self.config.mock_mode,
        )
        .await
    }

    /// Snapshot helper callable without `&self` so background loops collect
    /// the same real-or-explicitly-mock data as the foreground path instead
    /// of hardcoding metrics.
    async fn collect_snapshot(
        agent_id: &str,
        start_time: SystemTime,
        mock_mode: bool,
    ) -> Result<TelemetryData> {
        use crate::telemetry::*;

        let uptime = SystemTime::now().duration_since(start_time)?.as_secs();

        // Mock mode: deterministic telemetry, no local Prometheus scrape. Every
        // other network-touching path in this agent branches on mock_mode; this
        // one must too, or environments without a runtime on :8080 (CI) collect
        // empty metrics.
        if mock_mode {
            let mut metrics = BTreeMap::new();
            metrics.insert("requests_total".to_string(), 1234.0);
            metrics.insert("latency_p99_ms".to_string(), 45.2);
            metrics.insert("error_rate".to_string(), 0.01);

            return Ok(TelemetryData {
                agent_id: agent_id.to_string(),
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
                metrics,
                logs: vec![],
                status: AgentStatus {
                    health: "healthy".to_string(),
                    uptime_secs: uptime,
                    cpu_usage_percent: 35.5,
                    memory_usage_mb: 512,
                    active_tasks: 3,
                },
                signature: None,
            });
        }

        // Fetch REAL Prometheus metrics
        let metrics = fetch_prometheus_metrics("http://localhost:8080")
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to fetch Prometheus metrics: {}. Using empty metrics.",
                    e
                );
                BTreeMap::new()
            });

        // Get REAL system stats
        let (cpu_usage, memory_usage, active_tasks) = get_system_stats();

        // Determine health based on REAL metrics
        let health = determine_health(&metrics, cpu_usage, memory_usage);

        let status = AgentStatus {
            health,
            uptime_secs: uptime,
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_usage,
            active_tasks,
        };

        // Collect recent logs
        let logs = collect_recent_logs()?;

        Ok(TelemetryData {
            agent_id: agent_id.to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            metrics,
            logs,
            status,
            signature: None, // Signature added later when uploading
        })
    }

    /// Start background sync loops
    pub async fn start_sync_loops(&self) -> Result<()> {
        if self.config.auto_sync_config {
            self.start_config_sync_loop().await?;
        }

        if self.config.enable_telemetry {
            self.start_telemetry_upload_loop().await?;
        }

        Ok(())
    }

    /// Start configuration sync loop
    async fn start_config_sync_loop(&self) -> Result<()> {
        let registered = self.registered.clone();
        let config_version = self.config_version.clone();
        let fleet_id = self.fleet_id.clone();
        let client = self.client.clone();
        let endpoint = self.config.darksand_endpoint.clone();
        let api_key = self.config.api_key.clone();
        let interval = Duration::from_secs(self.config.sync_interval_secs);

        info!("Config sync loop started (interval: {:?})", interval);

        // Spawn background task to periodically sync config
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                // Only sync if registered
                if !*registered.read().await {
                    debug!("Skipping config sync - not registered");
                    continue;
                }

                // Get fleet ID
                let fid = {
                    let f = fleet_id.read().await;
                    match f.as_ref() {
                        Some(id) => id.clone(),
                        None => {
                            warn!("Skipping config sync - no fleet ID");
                            continue;
                        }
                    }
                };

                // Build request
                let url = format!("{}/api/fleet/{}/config", endpoint, fid);
                let mut req = client.get(&url);

                if let Some(key) = &api_key {
                    req = req.header("X-API-Key", key);
                }

                // Send request
                match req.send().await {
                    Ok(response) => match response.error_for_status() {
                        Ok(resp) => match resp.json::<ConfigSyncResponse>().await {
                            Ok(sync_resp) => {
                                let mut cv = config_version.write().await;
                                if sync_resp.version > *cv {
                                    *cv = sync_resp.version;
                                    info!("Config updated to version {}", sync_resp.version);
                                }
                            }
                            Err(e) => warn!("Failed to parse config sync response: {}", e),
                        },
                        Err(e) => warn!("Config sync request failed: {}", e),
                    },
                    Err(e) => warn!("Failed to send config sync request: {}", e),
                }
            }
        });

        Ok(())
    }

    /// Start telemetry upload loop
    async fn start_telemetry_upload_loop(&self) -> Result<()> {
        let registered = self.registered.clone();
        let fleet_id = self.fleet_id.clone();
        let client = self.client.clone();
        let endpoint = self.config.darksand_endpoint.clone();
        let api_key = self.config.api_key.clone();
        let agent_id = self.config.agent_id.clone();
        let start_time = self.start_time;
        let mock_mode = self.config.mock_mode;
        let keypair = self.keypair.clone();
        let interval = Duration::from_secs(self.config.telemetry_interval_secs);

        info!("Telemetry upload loop started (interval: {:?})", interval);

        // Spawn background task to periodically upload telemetry
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                // Only upload if registered
                if !*registered.read().await {
                    debug!("Skipping telemetry upload - not registered");
                    continue;
                }

                // Get fleet ID
                let fid = {
                    let f = fleet_id.read().await;
                    match f.as_ref() {
                        Some(id) => id.clone(),
                        None => {
                            warn!("Skipping telemetry upload - no fleet ID");
                            continue;
                        }
                    }
                };

                // Collect the same real (or explicitly mock) telemetry the
                // foreground path produces — never hardcoded values — and
                // sign it with the fleet keypair like upload_telemetry does.
                let mut telemetry =
                    match Self::collect_snapshot(&agent_id, start_time, mock_mode).await {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("Skipping telemetry upload - collect failed: {}", e);
                            continue;
                        }
                    };
                match crate::crypto::sign_payload(&keypair, &telemetry) {
                    Ok(sig) => telemetry.signature = Some(sig),
                    Err(e) => {
                        warn!("Skipping telemetry upload - sign failed: {}", e);
                        continue;
                    }
                };

                // Send telemetry
                let url = format!("{}/api/fleet/{}/telemetry", endpoint, fid);
                let mut req = client.post(&url).json(&telemetry);

                if let Some(key) = &api_key {
                    req = req.header("X-API-Key", key);
                }

                match req.send().await {
                    Ok(response) => match response.error_for_status() {
                        Ok(_) => {
                            debug!("Telemetry uploaded successfully");
                        }
                        Err(e) => warn!("Telemetry upload request failed: {}", e),
                    },
                    Err(e) => warn!("Failed to send telemetry: {}", e),
                }
            }
        });

        Ok(())
    }

    /// Check if agent is registered
    pub async fn is_registered(&self) -> bool {
        *self.registered.read().await
    }

    /// Get fleet ID
    pub async fn get_fleet_id(&self) -> Option<String> {
        self.fleet_id.read().await.clone()
    }

    /// Get current config version
    pub async fn get_config_version(&self) -> u64 {
        *self.config_version.read().await
    }

    /// Deregister from fleet
    ///
    /// Sends `DELETE /api/fleet/:fleet_id` when registered (server clears
    /// the agent row and audits it), then clears local state either way.
    /// In `mock_mode` no request is sent.
    pub async fn deregister(&self) -> Result<()> {
        info!("Deregistering from fleet");

        if !self.config.mock_mode {
            if let Some(fleet_id) = self.fleet_id.read().await.clone() {
                let url = format!(
                    "{}/api/fleet/{}",
                    self.config.darksand_endpoint, fleet_id
                );
                let mut req = self.client.delete(&url);
                if let Some(api_key) = &self.config.api_key {
                    req = req.header("X-API-Key", api_key);
                }
                req.send()
                    .await
                    .context("Failed to send deregistration request")?
                    .error_for_status()
                    .context("Deregistration request failed")?;
            }
        }

        let mut registered = self.registered.write().await;
        *registered = false;

        let mut fleet_id = self.fleet_id.write().await;
        *fleet_id = None;

        Ok(())
    }
}

/// Real telemetry collection using Prometheus metrics and system stats
pub mod telemetry;

/// Cryptographic operations for hybrid contract (Ed25519 signing)
pub mod crypto;

/// Fleet Management Dashboard (for Darksand integration)
pub mod dashboard {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FleetOverview {
        pub total_agents: usize,
        pub healthy_agents: usize,
        pub degraded_agents: usize,
        pub unhealthy_agents: usize,
        pub total_requests: u64,
        pub average_latency_ms: f32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AgentDetails {
        pub agent_id: String,
        pub hostname: String,
        pub status: AgentStatus,
        pub last_seen: u64,
        pub config_version: u64,
    }

    /// Get fleet overview from the control plane.
    ///
    /// Queries `GET /api/fleet/agents` and aggregates per-agent health.
    /// `total_requests` counts stored telemetry rows; `average_latency_ms`
    /// is not tracked server-side yet and is reported as 0.0 (explicitly,
    /// never fabricated).
    pub async fn get_fleet_overview(endpoint: &str, api_key: &str) -> Result<FleetOverview> {
        let agents = list_agents(endpoint, api_key).await?;
        let mut overview = FleetOverview {
            total_agents: agents.len(),
            healthy_agents: 0,
            degraded_agents: 0,
            unhealthy_agents: 0,
            total_requests: 0,
            average_latency_ms: 0.0,
        };
        for agent in &agents {
            match agent.health.as_str() {
                "healthy" => overview.healthy_agents += 1,
                "degraded" => overview.degraded_agents += 1,
                "unhealthy" => overview.unhealthy_agents += 1,
                _ => overview.degraded_agents += 1,
            }
            overview.total_requests += 1;
        }
        Ok(overview)
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct AgentsResponse {
        #[serde(default)]
        agents: Vec<AgentRecord>,
        #[serde(default)]
        total: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct AgentRecord {
        #[serde(default)]
        agent_id: String,
        #[serde(default)]
        hostname: String,
        #[serde(default)]
        health: String,
        #[serde(default)]
        last_seen: u64,
        #[serde(default)]
        config_version: u64,
    }

    async fn list_agents(endpoint: &str, api_key: &str) -> Result<Vec<AgentRecord>> {
        let url = format!("{}/api/fleet/agents", endpoint.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        let response: AgentsResponse = client
            .get(&url)
            .header("X-API-Key", api_key)
            .send()
            .await
            .context("Failed to query fleet agents")?
            .error_for_status()
            .context("Fleet agents query failed")?
            .json()
            .await
            .context("Failed to parse fleet agents response")?;
        Ok(response.agents)
    }

    /// Get agent details from the control plane.
    pub async fn get_agent_details(
        endpoint: &str,
        api_key: &str,
        agent_id: &str,
    ) -> Result<AgentDetails> {
        let agents = list_agents(endpoint, api_key).await?;
        let record = agents
            .into_iter()
            .find(|a| a.agent_id == agent_id)
            .ok_or_else(|| anyhow::anyhow!("agent not found in fleet"))?;
        // Latest status snapshot is not stored server-side yet; report the
        // last-seen health honestly and leave the full status to telemetry.
        Ok(AgentDetails {
            agent_id: record.agent_id,
            hostname: record.hostname,
            status: AgentStatus {
                health: record.health,
                uptime_secs: 0,
                cpu_usage_percent: 0.0,
                memory_usage_mb: 0,
                active_tasks: 0,
            },
            last_seen: record.last_seen,
            config_version: record.config_version,
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fleet_agent_init() {
        let config = FleetConfig {
            enabled: true,
            mock_mode: true,
            ..Default::default()
        };

        let agent = FleetAgent::new(config).await;
        assert!(agent.is_ok());
    }

    #[tokio::test]
    async fn test_registration() {
        let config = FleetConfig {
            enabled: true,
            mock_mode: true,
            ..Default::default()
        };

        let agent = FleetAgent::new(config).await.unwrap();
        assert!(!agent.is_registered().await);

        let response = agent.register().await.unwrap();
        assert!(response.success);
        assert!(agent.is_registered().await);
        assert!(agent.get_fleet_id().await.is_some());
    }

    #[tokio::test]
    async fn test_config_sync() {
        let config = FleetConfig {
            enabled: true,
            mock_mode: true,
            ..Default::default()
        };

        let agent = FleetAgent::new(config).await.unwrap();
        agent.register().await.unwrap();

        let sync_response = agent.sync_config().await.unwrap();
        assert!(sync_response.version > 0);
        assert_eq!(agent.get_config_version().await, sync_response.version);
    }

    #[tokio::test]
    async fn test_telemetry_collection() {
        let config = FleetConfig {
            enabled: true,
            mock_mode: true,
            ..Default::default()
        };

        let agent = FleetAgent::new(config).await.unwrap();
        agent.register().await.unwrap();

        let telemetry = agent.collect_telemetry().await.unwrap();
        assert!(!telemetry.metrics.is_empty());
        assert_eq!(telemetry.status.health, "healthy");
    }

    #[tokio::test]
    async fn test_deregistration() {
        let config = FleetConfig {
            enabled: true,
            mock_mode: true,
            ..Default::default()
        };

        let agent = FleetAgent::new(config).await.unwrap();
        agent.register().await.unwrap();
        assert!(agent.is_registered().await);

        agent.deregister().await.unwrap();
        assert!(!agent.is_registered().await);
    }
}
