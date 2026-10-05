//! Typed loader for `config/robotics.example.json5`.
//!
//! The example file used to be documentation-only: nothing parsed it, and it
//! would not even have deserialized (`agent_id: null` vs `String`,
//! `"voting"` vs `Voting`, unknown `api_key_env`, `//` comments, unquoted
//! keys). This crate is the contract: strict section types with
//! `deny_unknown_fields`, snake_case enums, `agent_id: Option<String>`, and
//! a real `api_key_env` wired to process env at materialization time.
//!
//! Parsing is two stages: strip `//` line comments, then `serde_json`.
//! (Full JSON5 — trailing commas, single quotes — is rejected on purpose:
//! configs must stay machine-comparable.)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Full robotics configuration: all five sections, typed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarksandConfig {
    #[serde(default)]
    pub ros2: Ros2Section,
    #[serde(default)]
    pub sensors: SensorsSection,
    #[serde(default)]
    pub swarm: SwarmSection,
    #[serde(default)]
    pub fleet: FleetSection,
    #[serde(default)]
    pub simulation: SimulationSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ros2Section {
    pub enabled: bool,
    pub node_name: String,
    pub namespace: String,
    pub domain_id: u32,
    pub enable_nav2: bool,
    pub nav2_action_server: String,
    pub qos_reliability: u8,
    pub qos_depth: usize,
}

impl Default for Ros2Section {
    fn default() -> Self {
        Self {
            enabled: false,
            node_name: "darksand_agent".to_string(),
            namespace: "/darksand".to_string(),
            domain_id: 0,
            enable_nav2: false,
            nav2_action_server: "/navigate_to_pose".to_string(),
            qos_reliability: 1,
            qos_depth: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorsSection {
    pub enabled: bool,
    pub enable_gpio: bool,
    pub enable_camera: bool,
    pub enable_lidar: bool,
    pub camera_device: String,
    pub camera_width: u32,
    pub camera_height: u32,
    pub lidar_connection: String,
    pub lidar_address: String,
    #[serde(default)]
    pub gpio_output_whitelist: Vec<u8>,
    #[serde(default)]
    pub actuator_whitelist: Vec<String>,
    pub safety_mode: bool,
}

impl Default for SensorsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            enable_gpio: false,
            enable_camera: false,
            enable_lidar: false,
            camera_device: "/dev/video0".to_string(),
            camera_width: 640,
            camera_height: 480,
            lidar_connection: "serial".to_string(),
            lidar_address: "/dev/ttyUSB0".to_string(),
            gpio_output_whitelist: vec![],
            actuator_whitelist: vec![],
            safety_mode: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictStrategy {
    LeaderDecides,
    Voting,
    Priority,
    Consensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmSection {
    pub enabled: bool,
    pub election_timeout_secs: (u64, u64),
    pub heartbeat_interval_secs: u64,
    pub max_agents: usize,
    pub enable_conflict_resolution: bool,
    pub conflict_strategy: ConflictStrategy,
}

impl Default for SwarmSection {
    fn default() -> Self {
        Self {
            enabled: false,
            election_timeout_secs: (5, 10),
            heartbeat_interval_secs: 2,
            max_agents: 100,
            enable_conflict_resolution: true,
            conflict_strategy: ConflictStrategy::Voting,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetSection {
    pub enabled: bool,
    #[serde(alias = "overture_endpoint")]
    pub darksand_endpoint: String,
    /// Null in the file means "generate at materialization".
    pub agent_id: Option<String>,
    /// Name of the env var holding the fleet API secret (never the secret).
    #[serde(default)]
    pub api_key_env: Option<String>,
    pub enable_tls: bool,
    pub sync_interval_secs: u64,
    pub auto_sync_config: bool,
    pub enable_telemetry: bool,
    pub telemetry_interval_secs: u64,
}

impl Default for FleetSection {
    fn default() -> Self {
        Self {
            enabled: false,
            darksand_endpoint: "https://darksand.example.com".to_string(),
            agent_id: None,
            api_key_env: None,
            enable_tls: true,
            sync_interval_secs: 300,
            auto_sync_config: true,
            enable_telemetry: true,
            telemetry_interval_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvType {
    VirtualSwarm,
    Gazebo,
    IsaacSim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationSection {
    pub enabled: bool,
    pub env_type: EnvType,
    pub chaos_enabled: bool,
    pub failure_rate: f32,
}

impl Default for SimulationSection {
    fn default() -> Self {
        Self {
            enabled: false,
            env_type: EnvType::VirtualSwarm,
            chaos_enabled: false,
            failure_rate: 0.1,
        }
    }
}

impl Default for DarksandConfig {
    fn default() -> Self {
        Self {
            ros2: Ros2Section::default(),
            sensors: SensorsSection::default(),
            swarm: SwarmSection::default(),
            fleet: FleetSection::default(),
            simulation: SimulationSection::default(),
        }
    }
}

/// Fleet settings with secrets resolved: `agent_id` generated when null,
/// API key read from the process env named by `api_key_env`.
#[derive(Debug, Clone)]
pub struct ResolvedFleet {
    pub enabled: bool,
    pub darksand_endpoint: String,
    pub agent_id: String,
    pub api_key: Option<String>,
    pub enable_tls: bool,
    pub sync_interval_secs: u64,
    pub auto_sync_config: bool,
    pub enable_telemetry: bool,
    pub telemetry_interval_secs: u64,
}

impl DarksandConfig {
    /// Parse JSON5-with-`//`-comments into the typed contract.
    ///
    /// Only `//` outside string literals starts a comment (`https://…`
    /// URLs must survive stripping).
    pub fn from_json5(text: &str) -> Result<Self> {
        let stripped: String = text.lines().map(strip_line_comment).collect::<Vec<_>>().join("\n");
        serde_json::from_str(&stripped).context("robotics config is not valid (comment-stripped) JSON")
    }

    /// Load from a `.json5` file.
    pub fn from_file(path: &str) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("cannot read config {path}"))?;
        Self::from_json5(&text)
    }

    /// Resolve the fleet section: generate an agent ID when null, read the
    /// API secret from the env var named by `api_key_env` (absent var ⇒
    /// `None`, never an error — enablement is decided by `enabled`).
    pub fn resolve_fleet(&self) -> ResolvedFleet {
        let agent_id = self.fleet.agent_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let api_key = self
            .fleet
            .api_key_env
            .as_deref()
            .and_then(|name| std::env::var(name).ok());
        ResolvedFleet {
            enabled: self.fleet.enabled,
            darksand_endpoint: self.fleet.darksand_endpoint.clone(),
            agent_id,
            api_key,
            enable_tls: self.fleet.enable_tls,
            sync_interval_secs: self.fleet.sync_interval_secs,
            auto_sync_config: self.fleet.auto_sync_config,
            enable_telemetry: self.fleet.enable_telemetry,
            telemetry_interval_secs: self.fleet.telemetry_interval_secs,
        }
    }
}

/// Strip a trailing `//` comment, ignoring `//` inside string literals.
fn strip_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
        } else if c == b'"' {
            in_string = true;
            i += 1;
        } else if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            return &line[..i];
        } else {
            i += 1;
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_path() -> String {
        format!(
            "{}/../../config/robotics.example.json5",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn example_file_parses_to_typed_config() {
        let cfg = DarksandConfig::from_file(&example_path()).unwrap();
        assert!(!cfg.ros2.enabled);
        assert!(!cfg.sensors.enabled);
        assert!(!cfg.swarm.enabled);
        assert!(!cfg.fleet.enabled);
        assert!(!cfg.simulation.enabled);
        assert_eq!(cfg.swarm.conflict_strategy, ConflictStrategy::Voting);
        assert_eq!(cfg.simulation.env_type, EnvType::VirtualSwarm);
        assert_eq!(cfg.fleet.agent_id, None);
        assert_eq!(cfg.fleet.api_key_env.as_deref(), Some("FLEET_API_KEY"));
        assert_eq!(cfg.swarm.election_timeout_secs, (5, 10));
        // Round-trips back through strict JSON.
        let json = serde_json::to_string(&cfg).unwrap();
        let again: DarksandConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(again.fleet.api_key_env.as_deref(), Some("FLEET_API_KEY"));
    }

    #[test]
    fn line_comments_outside_strings_only() {
        assert_eq!(strip_line_comment(r#""https://x" // c"#), r#""https://x" "#);
        assert_eq!(strip_line_comment(r#"  "a": 1,  // c"#), r#"  "a": 1,  "#);
        assert_eq!(strip_line_comment("// full"), "");
        assert_eq!(strip_line_comment(r#""a\"//b""#), r#""a\"//b""#);
    }

    #[test]
    fn unknown_fields_fail_with_the_field_name() {
        let err = DarksandConfig::from_json5(
            r#"{"fleet": {"enabled": false, "darksand_endpoint": "x",
                "agent_id": null, "enable_tls": true, "sync_interval_secs": 1,
                "auto_sync_config": true, "enable_telemetry": true,
                "telemetry_interval_secs": 1, "api_key_typo": 1}}"#,
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("api_key_typo"));
    }

    #[test]
    fn fleet_resolution_generates_id_and_reads_env() {
        // SAFETY: single-threaded test process section — no other test in
        // this crate touches process env.
        std::env::set_var("DARKSAND_CONFIG_TEST_KEY", "s3cret");
        let cfg = DarksandConfig::from_json5(
            r#"{"fleet": {"enabled": true, "darksand_endpoint": "https://x",
                "agent_id": null, "api_key_env": "DARKSAND_CONFIG_TEST_KEY",
                "enable_tls": true, "sync_interval_secs": 1,
                "auto_sync_config": true, "enable_telemetry": true,
                "telemetry_interval_secs": 1}}"#,
        )
        .unwrap();
        let resolved = cfg.resolve_fleet();
        assert_eq!(resolved.api_key.as_deref(), Some("s3cret"));
        assert!(!resolved.agent_id.is_empty());
        std::env::remove_var("DARKSAND_CONFIG_TEST_KEY");
        // Absent env var is None, not an error.
        let resolved = cfg.resolve_fleet();
        assert_eq!(resolved.api_key, None);
    }
}
