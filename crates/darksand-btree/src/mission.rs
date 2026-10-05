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
    /// How the instruction was classified before compilation. Anything but
    /// `Clear` is documentation today: the loader accepts the mission and
    /// records the author's judgment for auditors.
    #[serde(default)]
    pub disposition: Disposition,
    /// Declared optimality criterion for future planners. Documentary today:
    /// the loader validates the value and exposes it for cost accounting.
    #[serde(default)]
    pub optimality: Option<Optimality>,
    /// Declarative goal in DNF: a list of conjuncts, each a list of literals.
    /// The mission succeeds (by declaration) when any conjunct holds. Used by
    /// [`Mission::goal_satisfied`] for pre/post checks, not by the executor.
    #[serde(default)]
    pub goal: Option<GoalSpec>,
    /// Estimated per-node costs keyed by node `name`. [`Mission::estimated_cost`]
    /// sums them; [`Mission::unmatched_costs`] reports names with no matching
    /// node so stale estimates surface instead of silently vanishing.
    #[serde(default)]
    pub costs: std::collections::HashMap<String, f64>,
    /// Root of the behavior tree.
    pub root: NodeSpec,
}

/// Instruction disposition, resolved before compilation (BT-ACTION pattern).
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
pub enum Disposition {
    /// Clear, executable instruction.
    #[default]
    Clear,
    /// Ambiguous: needs operator clarification; recorded, still compilable.
    Ambiguous,
    /// Infeasible for this robot: recorded so rejection has a reason.
    Infeasible,
    /// Feasible but beyond current knowledge: may need new actions.
    Modification,
}

/// Optimality criterion for planners (OBTEA/HOBTEA pattern).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum Optimality {
    MinExpectedCost,
    MinWorstCaseCost,
    RobustUnderNFailures,
}

/// Goal in disjunctive normal form: any conjunct satisfied ⇒ goal holds.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalSpec {
    pub dnf: Vec<Vec<GoalLiteral>>,
}

/// One goal literal: blackboard `key` must equal `expected`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalLiteral {
    pub key: String,
    pub expected: serde_json::Value,
}

/// Stable path-qualified node identity for audit and hot-swap lookup.
/// Paths look like `root`, `root.children[0]`, `root.child` (decorators).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePath {
    pub path: String,
    pub node_type: &'static str,
    pub name: String,
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
        // Duplicate node names make the costs table (keyed by name) ambiguous
        // and audit paths non-unique: reject at load, not at 2 a.m.
        // (Unnamed nodes are exempt: they cannot be costed or addressed.)
        let index = self.index();
        let mut seen = std::collections::HashSet::new();
        for node in &index {
            if node.name.is_empty() {
                continue;
            }
            if !seen.insert(node.name.as_str()) {
                anyhow::bail!("duplicate node name {:?} at {}", node.name, node.path);
            }
        }
        for (name, cost) in &self.costs {
            if !cost.is_finite() || *cost < 0.0 {
                anyhow::bail!("cost for node {name:?} must be finite and >= 0, got {cost}");
            }
        }
        build_node(self.root)
    }

    /// Validate the envelope without building (for linters and auditors).
    pub fn parse(s: &str) -> Result<Self> {
        let mission: Mission =
            serde_json::from_str(s).context("mission document is not valid JSON")?;
        if mission.version != "darksand-mission.v1" {
            anyhow::bail!(
                "unsupported mission version {:?} (expected \"darksand-mission.v1\")",
                mission.version
            );
        }
        Ok(mission)
    }

    /// Path-qualified index of every node in the mission (`root…`).
    pub fn index(&self) -> Vec<NodePath> {
        let mut out = Vec::new();
        index_spec(&self.root, "root".to_string(), &mut out);
        out
    }

    /// Sum of the `costs` table. Pair with [`Mission::unmatched_costs`] so
    /// stale per-node estimates cannot silently vanish after a rename.
    pub fn estimated_cost(&self) -> f64 {
        self.costs.values().sum()
    }

    /// Cost-table names with no matching node `name` in the tree.
    pub fn unmatched_costs(&self) -> Vec<String> {
        let index = self.index();
        let names: std::collections::HashSet<&str> =
            index.iter().map(|n| n.name.as_str()).collect();
        let mut missing: Vec<String> = self
            .costs
            .keys()
            .filter(|k| !names.contains(k.as_str()))
            .cloned()
            .collect();
        missing.sort();
        missing
    }

    /// True when any DNF conjunct holds against a blackboard snapshot.
    /// An empty DNF never holds (no declared goal ⇒ nothing to satisfy).
    pub fn goal_satisfied(&self, snapshot: &serde_json::Value) -> bool {
        let Some(goal) = &self.goal else {
            return false;
        };
        let obj = snapshot.as_object();
        goal.dnf.iter().any(|conjunct| {
            !conjunct.is_empty()
                && conjunct.iter().all(|lit| {
                    obj.and_then(|m| m.get(&lit.key)) == Some(&lit.expected)
                })
        })
    }

    /// True when the tree contains an unbounded `Repeat` (count `None`).
    /// Such missions never terminate on their own: pair them with an executor
    /// `max_ticks`/`deadline`, a `Timeout` ancestor, or external cancel —
    /// otherwise the default unbounded executor runs forever.
    pub fn has_unbounded_repeat(&self) -> bool {
        fn walk(spec: &NodeSpec) -> bool {
            match spec {
                NodeSpec::Repeat { count: None, .. } => true,
                _ => spec_children(spec)
                    .iter()
                    .any(|(child, _)| walk(child)),
            }
        }
        walk(&self.root)
    }
}

fn spec_type_name(spec: &NodeSpec) -> &'static str {
    match spec {
        NodeSpec::Sequence { .. } => "Sequence",
        NodeSpec::Selector { .. } => "Selector",
        NodeSpec::Parallel { .. } => "Parallel",
        NodeSpec::Inverter { .. } => "Inverter",
        NodeSpec::Repeat { .. } => "Repeat",
        NodeSpec::Retry { .. } => "Retry",
        NodeSpec::Timeout { .. } => "Timeout",
        NodeSpec::CheckBlackboard { .. } => "CheckBlackboard",
        NodeSpec::SetBlackboard { .. } => "SetBlackboard",
        NodeSpec::RosTopicPublish { .. } => "RosTopicPublish",
        NodeSpec::RosTopicSubscribe { .. } => "RosTopicSubscribe",
        NodeSpec::RosServiceCall { .. } => "RosServiceCall",
    }
}

fn spec_name(spec: &NodeSpec) -> &str {
    match spec {
        NodeSpec::Sequence { name, .. }
        | NodeSpec::Selector { name, .. }
        | NodeSpec::Parallel { name, .. }
        | NodeSpec::Inverter { name, .. }
        | NodeSpec::Repeat { name, .. }
        | NodeSpec::Retry { name, .. }
        | NodeSpec::Timeout { name, .. }
        | NodeSpec::CheckBlackboard { name, .. }
        | NodeSpec::SetBlackboard { name, .. }
        | NodeSpec::RosTopicPublish { name, .. }
        | NodeSpec::RosTopicSubscribe { name, .. }
        | NodeSpec::RosServiceCall { name, .. } => name,
    }
}

fn spec_children(spec: &NodeSpec) -> Vec<(&NodeSpec, String)> {
    match spec {
        NodeSpec::Sequence { children, .. }
        | NodeSpec::Selector { children, .. }
        | NodeSpec::Parallel { children, .. } => children
            .iter()
            .enumerate()
            .map(|(i, c)| (c, format!("children[{i}]")))
            .collect(),
        NodeSpec::Inverter { child, .. }
        | NodeSpec::Repeat { child, .. }
        | NodeSpec::Retry { child, .. }
        | NodeSpec::Timeout { child, .. } => vec![(child.as_ref(), "child".to_string())],
        _ => vec![],
    }
}

fn index_spec(spec: &NodeSpec, path: String, out: &mut Vec<NodePath>) {
    out.push(NodePath {
        path: path.clone(),
        node_type: spec_type_name(spec),
        name: spec_name(spec).to_string(),
    });
    for (child, seg) in spec_children(spec) {
        index_spec(child, format!("{path}.{seg}"), out);
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

    #[test]
    fn header_goal_disposition_optimality_costs() {
        let m = Mission::parse(
            r#"{"version": "darksand-mission.v1", "name": "h",
                "disposition": "Modification",
                "optimality": "MinExpectedCost",
                "costs": {"a": 1.5, "b": 2.5, "ghost": 9.0},
                "goal": {"dnf": [[{"key": "phase", "expected": "done"}]]},
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "SetBlackboard", "name": "a", "key": "phase", "value": "done"},
                    {"type": "SetBlackboard", "name": "b", "key": "other", "value": 1}
                ]}}"#,
        )
        .unwrap();
        assert_eq!(m.disposition, Disposition::Modification);
        assert_eq!(m.optimality, Some(Optimality::MinExpectedCost));
        assert_eq!(m.estimated_cost(), 13.0);
        assert_eq!(m.unmatched_costs(), vec!["ghost".to_string()]);
        assert!(m.goal_satisfied(&serde_json::json!({"phase": "done"})));
        assert!(!m.goal_satisfied(&serde_json::json!({"phase": "starting"})));
        assert!(!m.goal_satisfied(&serde_json::json!({})));
    }

    #[test]
    fn header_defaults_when_absent() {
        let m = Mission::parse(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Sequence", "name": "s", "children": []}}"#,
        )
        .unwrap();
        assert_eq!(m.disposition, Disposition::Clear);
        assert_eq!(m.optimality, None);
        assert_eq!(m.estimated_cost(), 0.0);
        assert!(!m.goal_satisfied(&serde_json::json!({"anything": 1})));
    }

    #[test]
    fn index_assigns_stable_paths() {        let m = Mission::parse(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "Retry", "name": "r", "max_retries": 1,
                     "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}
                ]}}"#,
        )
        .unwrap();
        let paths: Vec<(String, String)> = m
            .index()
            .into_iter()
            .map(|n| (n.path, n.node_type.to_string()))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("root".to_string(), "Sequence".to_string()),
                ("root.children[0]".to_string(), "Retry".to_string()),
                (
                    "root.children[0].child".to_string(),
                    "SetBlackboard".to_string()
                ),
            ]
        );
    }

    #[test]
    fn duplicate_names_rejected() {
        let err = expect_err(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "SetBlackboard", "name": "dup", "key": "a", "value": 1},
                    {"type": "SetBlackboard", "name": "dup", "key": "b", "value": 2}
                ]}}"#,
        );
        assert!(err.contains("duplicate node name"), "got: {err}");
    }

    #[test]
    fn negative_costs_rejected() {
        // JSON has no Infinity/NaN literals, so only negativity is reachable
        // from documents; non-finiteness is still guarded for programmatic
        // Mission construction.
        let err = expect_err(
            r#"{"version": "darksand-mission.v1",
                "costs": {"a": -1.0},
                "root": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}"#,
        );
        assert!(err.contains("must be finite"), "got: {err}");
    }

    #[test]
    fn unbounded_repeat_detected() {
        let with_inf = Mission::parse(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Repeat", "name": "r",
                    "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}}"#,
        )
        .unwrap();
        assert!(with_inf.has_unbounded_repeat());
        let bounded = Mission::parse(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Repeat", "name": "r", "count": 2,
                    "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}}"#,
        )
        .unwrap();
        assert!(!bounded.has_unbounded_repeat());
    }

    /// The shipped example mission carries a real header, executes to
    /// Success, and its declared goal holds on the final blackboard —
    /// i.e. this mission actually produces a Proof, not just a status.
    #[tokio::test]
    async fn flagship_mission_proves_its_goal() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../missions/wharf-inspection.json"
        );
        let doc = std::fs::read_to_string(path).unwrap();
        let mission = Mission::parse(&doc).unwrap();
        assert_eq!(mission.disposition, Disposition::Clear);
        assert!(mission.unmatched_costs().is_empty());
        assert!(!mission.has_unbounded_repeat());

        let mut tree = mission_from_str(&doc).unwrap();
        let mut ctx = crate::core::BTreeContext::new();
        let result = crate::BTreeExecutor::new()
            .execute(&mut *tree, &mut ctx)
            .await
            .unwrap();
        assert!(result.is_success());
        let snapshot = ctx.blackboard.snapshot().await;
        let mission = Mission::parse(&doc).unwrap();
        assert!(mission.goal_satisfied(&snapshot));
    }
}
