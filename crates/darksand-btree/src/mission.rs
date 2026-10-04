//! JSON mission-file loader: declarative missions → deterministic BT.
//!
//! Format (`darksand-mission.v1`):
//!
//! ```json
//! {
//!     "version": "darksand-mission.v1",
//!     "name": "wharf-inspection",
//!     "root": {
//!         "type": "Sequence",
//!         "name": "mission",
//!         "children": [
//!             { "type": "SetBlackboard", "name": "init", "key": "phase", "value": "starting" },
//!             { "type": "CheckBlackboard", "name": "check", "key": "phase", "expected": "starting" }
//!         ]
//!     }
//! }
//! ```
//!
//! Supported `type` values mirror the live node inventory: `Sequence`,
//! `Selector`, `Parallel` (`policy`: `"RequireAll"` | `"RequireOne"`),
//! `Inverter`, `Repeat` (`count`, null = infinite), `Retry` (`max_retries`),
//! `Timeout` (`timeout_ms`), `CheckBlackboard` (`key`, `expected`),
//! `SetBlackboard` (`key`, `value`). ROS2 action nodes (`RosTopicPublish`,
//! `RosTopicSubscribe`, `RosServiceCall`) require the `ros2` feature and are
//! rejected with a clear error otherwise.
//!
//! Unknown node types and unknown fields are rejected (`deny_unknown_fields`)
//! so typos fail at load time, never at 2 a.m. on the pier.

use crate::core::BTreeNode;
use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level mission document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mission {
    /// Must be `"darksand-mission.v1"`.
    pub version: String,
    /// Human-readable mission name (used as documentation only).
    #[serde(default)]
    pub name: String,
    /// Root of the behavior tree.
    pub root: NodeSpec,
}

/// Declarative form of one BT node.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum NodeSpec {
    Sequence {
        #[serde(default)]
        name: String,
        #[serde(default)]
        children: Vec<NodeSpec>,
    },
    Selector {
        #[serde(default)]
        name: String,
        #[serde(default)]
        children: Vec<NodeSpec>,
    },
    Parallel {
        #[serde(default)]
        name: String,
        #[serde(default = "default_parallel_policy")]
        policy: ParallelPolicySpec,
        #[serde(default)]
        children: Vec<NodeSpec>,
    },
    Inverter {
        #[serde(default)]
        name: String,
        child: Box<NodeSpec>,
    },
    Repeat {
        #[serde(default)]
        name: String,
        child: Box<NodeSpec>,
        #[serde(default)]
        count: Option<u32>,
    },
    Retry {
        #[serde(default)]
        name: String,
        child: Box<NodeSpec>,
        #[serde(default = "default_retry_count")]
        max_retries: u32,
    },
    Timeout {
        #[serde(default)]
        name: String,
        child: Box<NodeSpec>,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    CheckBlackboard {
        #[serde(default)]
        name: String,
        key: String,
        expected: serde_json::Value,
    },
    SetBlackboard {
        #[serde(default)]
        name: String,
        key: String,
        #[serde(default)]
        value: serde_json::Value,
    },
    RosTopicPublish {
        #[serde(default)]
        name: String,
        topic: String,
        #[serde(default = "default_msg_type")]
        msg_type: String,
        #[serde(default)]
        payload: serde_json::Value,
        #[serde(default)]
        min_interval_ms: u64,
    },
    RosTopicSubscribe {
        #[serde(default)]
        name: String,
        topic: String,
        #[serde(default = "default_msg_type")]
        msg_type: String,
        #[serde(default = "default_sub_timeout_ms")]
        timeout_ms: u64,
        output_key: String,
    },
    RosServiceCall {
        #[serde(default)]
        name: String,
        service: String,
        #[serde(default)]
        request: serde_json::Value,
        #[serde(default = "default_sub_timeout_ms")]
        timeout_ms: u64,
        output_key: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
pub enum ParallelPolicySpec {
    #[default]
    RequireAll,
    RequireOne,
}

fn default_parallel_policy() -> ParallelPolicySpec {
    ParallelPolicySpec::RequireAll
}

fn default_retry_count() -> u32 {
    3
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_msg_type() -> String {
    "std_msgs/String".to_string()
}

fn default_sub_timeout_ms() -> u64 {
    2_000
}

impl Mission {
    /// Validate the envelope and build the executable tree.
    pub fn build(self) -> Result<Box<dyn BTreeNode>> {
        if self.version != "darksand-mission.v1" {
            anyhow::bail!(
                "unsupported mission version {:?} (expected \"darksand-mission.v1\")",
                self.version
            );
        }
        if self.name.is_empty() {
            tracing::debug!("mission has no name; proceeding (name is documentary)");
        }
        build_node(self.root)
    }
}

fn build_node(spec: NodeSpec) -> Result<Box<dyn BTreeNode>> {
    use crate::nodes::{
        action::SetBlackboard,
        composite::{Parallel, ParallelPolicy, Selector, Sequence},
        condition::CheckBlackboard,
        decorator::{Inverter, Repeat, Retry, Timeout},
    };

    fn display_name(given: &str, fallback: &str) -> String {
        if given.is_empty() {
            fallback.to_string()
        } else {
            given.to_string()
        }
    }

    match spec {
        NodeSpec::Sequence { name, children } => {
            let name = display_name(&name, "sequence");
            let mut node = Sequence::new(name);
            for child in children {
                node = node.add_child(build_node(child)?);
            }
            Ok(Box::new(node))
        }
        NodeSpec::Selector { name, children } => {
            let name = display_name(&name, "selector");
            let mut node = Selector::new(name);
            for child in children {
                node = node.add_child(build_node(child)?);
            }
            Ok(Box::new(node))
        }
        NodeSpec::Parallel {
            name,
            policy,
            children,
        } => {
            let name = display_name(&name, "parallel");
            let policy = match policy {
                ParallelPolicySpec::RequireAll => ParallelPolicy::RequireAll,
                ParallelPolicySpec::RequireOne => ParallelPolicy::RequireOne,
            };
            let mut node = Parallel::new(name, policy);
            for child in children {
                node = node.add_child(build_node(child)?);
            }
            Ok(Box::new(node))
        }
        NodeSpec::Inverter { name, child } => {
            let name = display_name(&name, "inverter");
            Ok(Box::new(Inverter::new(name, build_node(*child)?)))
        }
        NodeSpec::Repeat { name, child, count } => {
            let name = display_name(&name, "repeat");
            Ok(Box::new(Repeat::new(name, build_node(*child)?, count)))
        }
        NodeSpec::Retry { name, child, max_retries } => {
            let name = display_name(&name, "retry");
            Ok(Box::new(Retry::new(name, build_node(*child)?, max_retries)))
        }
        NodeSpec::Timeout {
            name,
            child,
            timeout_ms,
        } => {
            let name = display_name(&name, "timeout");
            Ok(Box::new(Timeout::new(
                name,
                build_node(*child)?,
                timeout_ms,
            )))
        }
        NodeSpec::CheckBlackboard {
            name,
            key,
            expected,
        } => {
            let name = display_name(&name, "check");
            Ok(Box::new(CheckBlackboard::new(name, key, expected)))
        }
        NodeSpec::SetBlackboard { name, key, value } => {
            let name = display_name(&name, "set");
            Ok(Box::new(SetBlackboard::new(name, key, value)))
        }
        NodeSpec::RosTopicPublish {
            name,
            topic,
            msg_type,
            payload,
            min_interval_ms,
        } => {
            #[cfg(feature = "ros2")]
            {
                use crate::nodes::action::RosTopicPublish;
                let name = display_name(&name, "ros_publish");
                Ok(Box::new(RosTopicPublish::new(
                    name,
                    topic,
                    msg_type,
                    payload,
                    min_interval_ms,
                )))
            }
            #[cfg(not(feature = "ros2"))]
            {
                let _ = (name, topic, msg_type, payload, min_interval_ms);
                anyhow::bail!(
                    "mission uses RosTopicPublish but the `ros2` feature is not enabled; \
                     rebuild with `--features ros2`"
                );
            }
        }
        NodeSpec::RosTopicSubscribe {
            name,
            topic,
            msg_type,
            timeout_ms,
            output_key,
        } => {
            #[cfg(feature = "ros2")]
            {
                use crate::nodes::action::RosTopicSubscribe;
                let name = display_name(&name, "ros_subscribe");
                Ok(Box::new(RosTopicSubscribe::new(
                    name, topic, msg_type, timeout_ms, output_key,
                )))
            }
            #[cfg(not(feature = "ros2"))]
            {
                let _ = (name, topic, msg_type, timeout_ms, output_key);
                anyhow::bail!(
                    "mission uses RosTopicSubscribe but the `ros2` feature is not enabled; \
                     rebuild with `--features ros2`"
                );
            }
        }
        NodeSpec::RosServiceCall {
            name,
            service,
            request,
            timeout_ms,
            output_key,
        } => {
            #[cfg(feature = "ros2")]
            {
                use crate::nodes::action::RosServiceCall;
                let name = display_name(&name, "ros_service");
                Ok(Box::new(RosServiceCall::new(
                    name, service, request, timeout_ms, output_key,
                )))
            }
            #[cfg(not(feature = "ros2"))]
            {
                let _ = (name, service, request, timeout_ms, output_key);
                anyhow::bail!(
                    "mission uses RosServiceCall but the `ros2` feature is not enabled; \
                     rebuild with `--features ros2`"
                );
            }
        }
    }
}

/// Parse a mission document from a JSON string.
pub fn mission_from_str(s: &str) -> Result<Box<dyn BTreeNode>> {
    let mission: Mission =
        serde_json::from_str(s).context("mission document is not valid JSON")?;
    mission.build()
}

/// Load a mission document from a `.json` file.
pub fn mission_from_file(path: &str) -> Result<Box<dyn BTreeNode>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read mission file {path}"))?;
    mission_from_str(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BTreeContext, NodeStatus};
    use crate::executor::BTreeExecutor;

    async fn run(json: &str) -> (NodeStatus, BTreeContext) {
        let mut tree = mission_from_str(json).unwrap();
        let mut ctx = BTreeContext::new();
        let status = BTreeExecutor::new()
            .tick(tree.as_mut(), &mut ctx)
            .await
            .unwrap();
        (status, ctx)
    }

    #[tokio::test]
    async fn sequence_set_then_check_succeeds() {
        let (status, ctx) = run(
            r#"{
                "version": "darksand-mission.v1",
                "name": "smoke",
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "SetBlackboard", "name": "init", "key": "phase", "value": "starting"},
                    {"type": "CheckBlackboard", "name": "check", "key": "phase", "expected": "starting"}
                ]}
            }"#,
        )
        .await;
        assert_eq!(status, NodeStatus::Success);
        assert_eq!(
            ctx.blackboard.get("phase").await,
            Some(serde_json::json!("starting"))
        );
    }

    #[tokio::test]
    async fn selector_falls_through_to_second_branch() {
        let (status, _) = run(
            r#"{
                "version": "darksand-mission.v1",
                "name": "sel",
                "root": {"type": "Selector", "name": "s", "children": [
                    {"type": "CheckBlackboard", "name": "miss", "key": "nope", "expected": 1},
                    {"type": "SetBlackboard", "name": "hit", "key": "k", "value": 2}
                ]}
            }"#,
        )
        .await;
        assert_eq!(status, NodeStatus::Success);
    }

    #[tokio::test]
    async fn decorators_retry_timeout_parallel_parse() {
        let (status, _) = run(
            r#"{
                "version": "darksand-mission.v1",
                "name": "dec",
                "root": {"type": "Parallel", "name": "p", "policy": "RequireOne", "children": [
                    {"type": "Retry", "name": "r", "max_retries": 2,
                     "child": {"type": "SetBlackboard", "name": "a", "key": "x", "value": 1}},
                    {"type": "Timeout", "name": "t", "timeout_ms": 500,
                     "child": {"type": "Inverter", "name": "i",
                      "child": {"type": "CheckBlackboard", "name": "c", "key": "zz", "expected": 0}}},
                    {"type": "Repeat", "name": "rp", "count": 2,
                     "child": {"type": "SetBlackboard", "name": "b", "key": "y", "value": true}}
                ]}
            }"#,
        )
        .await;
        assert_eq!(status, NodeStatus::Success);
    }

    fn expect_err(json: &str) -> String {
        match mission_from_str(json) {
            Ok(_) => panic!("expected mission load to fail"),
            // Debug format includes the full anyhow chain (outer context +
            // underlying serde error); Display shows the outer context only.
            Err(e) => format!("{e:?}"),
        }
    }

    #[test]
    fn unknown_node_type_rejected() {
        let err = expect_err(
            r#"{"version": "darksand-mission.v1", "name": "x",
                "root": {"type": "Teleport", "name": "t"}}"#,
        );
        assert!(err.contains("Teleport"), "got: {err}");
    }

    #[test]
    fn unknown_field_rejected() {
        let err = expect_err(
            r#"{"version": "darksand-mission.v1", "name": "x",
                "root": {"type": "Sequence", "name": "s", "children": [],
                         "teleport_speed": 9}}"#,
        );
        assert!(err.contains("teleport_speed"), "got: {err}");
    }

    #[test]
    fn wrong_version_rejected() {
        let err = expect_err(
            r#"{"version": "darksand-mission.v0", "name": "x",
                "root": {"type": "Sequence", "name": "s", "children": []}}"#,
        );
        assert!(err.contains("darksand-mission.v1"), "got: {err}");
    }

    #[test]
    #[cfg(not(feature = "ros2"))]
    fn ros_node_without_feature_errors_clearly() {
        let err = expect_err(
            r#"{"version": "darksand-mission.v1", "name": "x",
                "root": {"type": "RosTopicPublish", "name": "p", "topic": "/cmd_vel"}}"#,
        );
        assert!(err.contains("`ros2` feature"), "got: {err}");
    }
}
