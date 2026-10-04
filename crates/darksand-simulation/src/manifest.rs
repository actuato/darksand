//! Versioned simulator-property manifest for transfer comparability.
//!
//! The sim-to-real literature is blunt: low-level properties (contact solver,
//! integration step, actuation timing/noise, sensor models) decide transfer,
//! not the scenario name. So every evaluated run pins this manifest and every
//! proof carries its digest: two runs are comparable only under equal hashes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Pinned low-level simulator properties for one evaluated configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SimManifest {
    /// Engine identifier, e.g. `"virtual_swarm"`, `"gazebo"`, `"isaac_sim"`.
    pub engine: String,
    /// Engine version or `"unversioned"` when unknown — recorded honestly.
    #[serde(default = "default_unversioned")]
    pub engine_version: String,
    /// Physics integration step in milliseconds.
    #[serde(default = "default_step_ms")]
    pub step_ms: f64,
    /// Solver iterations per step.
    #[serde(default = "default_solver_iters")]
    pub solver_iters: u32,
    /// Contact/friction model name, e.g. `"none"`, `"coulomb"`.
    #[serde(default = "default_contact_model")]
    pub contact_model: String,
    /// Actuation timing description, e.g. `"instant"`, `"noisy-50hz"`.
    #[serde(default = "default_actuation")]
    pub actuation: String,
    /// Sensor noise description, e.g. `"none"`, `"depth-noise"`.
    #[serde(default = "default_sensor_noise")]
    pub sensor_noise: String,
    /// Render backend, e.g. `"none"`, `"ogre"`, `"rtx"`.
    #[serde(default = "default_render")]
    pub render: String,
}

fn default_unversioned() -> String {
    "unversioned".to_string()
}
fn default_step_ms() -> f64 {
    100.0
}
fn default_solver_iters() -> u32 {
    1
}
fn default_contact_model() -> String {
    "none".to_string()
}
fn default_actuation() -> String {
    "instant".to_string()
}
fn default_sensor_noise() -> String {
    "none".to_string()
}
fn default_render() -> String {
    "none".to_string()
}

impl SimManifest {
    /// Manifest for the in-process virtual swarm (no contact, instant actuation).
    pub fn virtual_swarm() -> Self {
        Self {
            engine: "virtual_swarm".to_string(),
            engine_version: default_unversioned(),
            step_ms: default_step_ms(),
            solver_iters: default_solver_iters(),
            contact_model: default_contact_model(),
            actuation: default_actuation(),
            sensor_noise: default_sensor_noise(),
            render: default_render(),
        }
    }

    /// SHA-256 hex over the canonical JSON encoding. Struct field order is
    /// declaration order, so equal manifests always hash equal.
    pub fn digest(&self) -> String {
        let json =
            serde_json::to_string(self).expect("SimManifest is always serializable");
        format!("{:x}", Sha256::digest(json.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        let a = SimManifest::virtual_swarm();
        let b = SimManifest::virtual_swarm();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest().len(), 64);
    }

    #[test]
    fn digest_distinguishes_engines() {
        let mut gazebo = SimManifest::virtual_swarm();
        gazebo.engine = "gazebo".to_string();
        gazebo.contact_model = "coulomb".to_string();
        assert_ne!(SimManifest::virtual_swarm().digest(), gazebo.digest());
    }

    #[test]
    fn unknown_fields_rejected() {
        let err = serde_json::from_str::<SimManifest>(
            r#"{"engine": "x", "teleport": true}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("teleport"));
    }
}
