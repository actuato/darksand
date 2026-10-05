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
//! `Timeout` (`timeout_ms`), `Watchdog` (`timeout_ms`,
//! `max_consecutive_running`), `CheckBlackboard` (`key`, `expected`),
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

/// Proof of a mission run: terminal status plus goal verification.
///
/// A `Success` status alone is not a proof — the tree may have succeeded
/// while the declared goal never held (or no goal was declared at all).
/// `is_proof()` is true only when the run succeeded AND the goal holds on
/// the final blackboard.
#[derive(Debug, Clone)]
pub struct RunProof {
    pub status: crate::core::NodeStatus,
    pub ticks: u64,
    pub duration_ms: u64,
    pub snapshot: serde_json::Value,
    pub estimated_cost: f64,
    pub goal_satisfied: bool,
}

impl RunProof {
    pub fn is_proof(&self) -> bool {
        self.status.is_success() && self.goal_satisfied
    }
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
    Watchdog {
        #[serde(default)]
        name: String,
        child: Box<NodeSpec>,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_watchdog_running")]
        max_consecutive_running: u32,
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

fn default_watchdog_running() -> u32 {
    100
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
        self.validate()?;
        if self.name.is_empty() {
            tracing::debug!("mission has no name; proceeding (name is documentary)");
        }
        build_node(self.root)
    }

    /// Run every static check without building: version, duplicate names,
    /// cost-table sanity, and degenerate parameters that would silently
    /// no-op at runtime. Both `from_str` and `build` call this, so linters
    /// and the executor can never disagree about admissibility.
    pub fn validate(&self) -> Result<()> {
        if self.version != "darksand-mission.v1" {
            anyhow::bail!(
                "unsupported mission version {:?} (expected \"darksand-mission.v1\")",
                self.version
            );
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
        // Degenerate parameters that silently no-op: a Repeat with count 0
        // ticks nothing and reports Success; a Timeout of 0 trips before the
        // child ever runs.
        fn walk(spec: &NodeSpec) -> Result<()> {
            match spec {
                NodeSpec::Repeat {
                    count: Some(0),
                    name,
                    ..
                } => anyhow::bail!("Repeat {name:?} has count 0: never ticks its child"),
                NodeSpec::Timeout {
                    timeout_ms: 0,
                    name,
                    ..
                } => anyhow::bail!("Timeout {name:?} has timeout_ms 0: trips immediately"),
                NodeSpec::Watchdog {
                    timeout_ms: 0,
                    name,
                    ..
                } => anyhow::bail!("Watchdog {name:?} has timeout_ms 0: trips immediately"),
                _ => Ok::<(), anyhow::Error>(()),
            }?;
            for (child, _) in spec_children(spec) {
                walk(child)?;
            }
            Ok(())
        }
        walk(&self.root)
    }

    /// Validate the envelope without building (for linters and auditors).
    pub fn parse(s: &str) -> Result<Self> {
        Self::from_str(s)
    }

    /// Parse a mission document, running full validation (version, duplicate
    /// names, cost table, degenerate parameters).
    pub fn from_str(s: &str) -> Result<Self> {
        let mission: Mission =
            serde_json::from_str(s).context("mission document is not valid JSON")?;
        mission.validate()?;
        Ok(mission)
    }

    /// Load a mission document from a `.json` file, fully validated.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read mission file {path}"))?;
        Self::from_str(&content)
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

    /// Cost-table names with no matching node `name` or node path.
    /// Path-keyed entries (`root.children[0]`) take precedence in
    /// [`Mission::cost_bound`] and are therefore matched, not missing.
    pub fn unmatched_costs(&self) -> Vec<String> {
        let index = self.index();
        let mut known = std::collections::HashSet::new();
        for n in &index {
            known.insert(n.name.as_str());
            known.insert(n.path.as_str());
        }
        let mut missing: Vec<String> = self
            .costs
            .keys()
            .filter(|k| !known.contains(k.as_str()))
            .cloned()
            .collect();
        missing.sort();
        missing
    }

    /// Named nodes (non-empty `name`) with no cost entry by name or path.
    /// Cost the mission honestly: every uncovered node is an unpriced risk.
    pub fn uncovered_nodes(&self) -> Vec<String> {
        let index = self.index();
        let mut out: Vec<String> = index
            .iter()
            .filter(|n| !n.name.is_empty())
            .filter(|n| !self.costs.contains_key(&n.name) && !self.costs.contains_key(&n.path))
            .map(|n| n.name.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Structural cost bound for an optimality criterion.
    ///
    /// Walks the tree shape (not the flat table): `Sequence`/`Selector`
    /// sum, `Parallel{RequireAll}` sums, `Parallel{RequireOne}` takes the
    /// max, `Retry` prices `(max_retries+1)` attempts under
    /// `MinWorstCaseCost` but a single attempt under `MinExpectedCost`
    /// (first-try success), `Repeat{Some(n)}` prices `n` iterations, and an
    /// unbounded `Repeat` prices `INFINITY`. Node cost resolves by path
    /// first, then by name, else 0.0.
    pub fn cost_bound(&self, optimality: Optimality) -> f64 {
        fn cost_of(mission: &Mission, spec: &NodeSpec, path: &str, optimality: Optimality) -> f64 {
            if let Some(c) = mission.costs.get(path) {
                return *c;
            }
            match spec {
                NodeSpec::Sequence { children, .. }
                | NodeSpec::Selector { children, .. } => children
                    .iter()
                    .enumerate()
                    .map(|(i, c)| cost_of(mission, c, &format!("{path}.children[{i}]"), optimality))
                    .sum(),
                NodeSpec::Parallel { policy, children, .. } => {
                    let parts: Vec<f64> = children
                        .iter()
                        .enumerate()
                        .map(|(i, c)| cost_of(mission, c, &format!("{path}.children[{i}]"), optimality))
                        .collect();
                    match policy {
                        ParallelPolicySpec::RequireAll => parts.iter().sum(),
                        ParallelPolicySpec::RequireOne => {
                            parts.into_iter().fold(0.0, f64::max)
                        }
                    }
                }
                NodeSpec::Retry { child, max_retries, .. } => {
                    let one = cost_of(mission, child, &format!("{path}.child"), optimality);
                    match optimality {
                        Optimality::MinExpectedCost => one,
                        _ => one * (f64::from(*max_retries) + 1.0),
                    }
                }
                NodeSpec::Repeat { child, count, .. } => match count {
                    Some(n) => {
                        cost_of(mission, child, &format!("{path}.child"), optimality)
                            * f64::from(*n)
                    }
                    None => f64::INFINITY,
                },
                NodeSpec::Timeout { child, .. }
                | NodeSpec::Inverter { child, .. }
                | NodeSpec::Watchdog { child, .. } => {
                    cost_of(mission, child, &format!("{path}.child"), optimality)
                }
                _ => mission.costs.get(spec_name(spec)).copied().unwrap_or(0.0),
            }
        }
        cost_of(self, &self.root, "root", optimality)
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

    /// Execute this mission end-to-end and return a [`RunProof`].
    ///
    /// Builds the tree, runs it under `config`, then checks the declared
    /// goal against the final blackboard. Callers MUST check `is_proof()`,
    /// not just terminal status: without a satisfied goal there is no proof.
    pub async fn run(&self, config: crate::executor::ExecutorConfig) -> Result<RunProof> {
        let mut tree = self.clone().build()?;
        let mut context = crate::core::BTreeContext::new();
        let result = crate::executor::BTreeExecutor::with_config(config)
            .execute(&mut *tree, &mut context)
            .await?;
        let snapshot = context.blackboard.snapshot().await;
        let goal_satisfied = self.goal_satisfied(&snapshot);
        Ok(RunProof {
            status: result.status,
            ticks: result.tick_count,
            duration_ms: result.duration.as_millis() as u64,
            snapshot,
            estimated_cost: self.estimated_cost(),
            goal_satisfied,
        })
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
        NodeSpec::Watchdog { .. } => "Watchdog",
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
        | NodeSpec::Watchdog { name, .. }
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
        | NodeSpec::Timeout { child, .. }
        | NodeSpec::Watchdog { child, .. } => vec![(child.as_ref(), "child".to_string())],
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

/// One static finding from [`Mission::lint`].
#[derive(Debug, Clone, PartialEq)]
pub enum MissionLint {
    /// A key is read (check, goal, subscription) but never written.
    UnwrittenKey { key: String, read_at: Vec<String> },
    /// A `Selector` branch after an infallible first child can never run.
    UnreachableSibling { path: String },
    /// A `Retry` whose child cannot fail: the retry budget is dead weight.
    DeadRetry { path: String },
    /// An `Inverter` over an infallible child: always `Failure`.
    AlwaysFailingInverter { path: String },
    /// A cost-table entry with no matching node.
    UnmatchedCost { name: String },
    /// An unbounded `Repeat`: needs an external bound to terminate.
    UnboundedRepeat { path: String },
    /// The mission is not `Clear`: recorded for auditors.
    NonClearDisposition { disposition: Disposition },
}

impl Mission {
    /// Look up a node spec by its [`NodePath`]-style path (`root…`).
    pub fn node_at(&self, path: &str) -> Option<&NodeSpec> {
        fn go<'a>(spec: &'a NodeSpec, here: &str, want: &str) -> Option<&'a NodeSpec> {
            if here == want {
                return Some(spec);
            }
            for (child, seg) in spec_children(spec) {
                if let Some(found) = go(child, &format!("{here}.{seg}"), want) {
                    return Some(found);
                }
            }
            None
        }
        go(&self.root, "root", path)
    }

    /// Static pre-execution audit: key flow, unreachable branches, dead
    /// retries, vacuous inverters, cost coverage, unbounded loops.
    /// An empty vec means the mission is structurally sound (not that it
    /// will succeed — that is what execution plus [`Mission::run`] proves).
    pub fn lint(&self) -> Vec<MissionLint> {
        fn infallible(spec: &NodeSpec) -> bool {
            match spec {
                NodeSpec::SetBlackboard { .. } => true,
                NodeSpec::Sequence { children, .. } if children.is_empty() => true,
                NodeSpec::Sequence { children, .. } => {
                    children.iter().all(infallible)
                }
                NodeSpec::Selector { children, .. } => children
                    .first()
                    .is_some_and(infallible),
                NodeSpec::Parallel { policy, children, .. } => match policy {
                    ParallelPolicySpec::RequireAll => {
                        children.iter().all(infallible)
                    }
                    ParallelPolicySpec::RequireOne => {
                        children.iter().any(infallible)
                    }
                },
                NodeSpec::Retry { child, .. } => infallible(child),
                NodeSpec::Inverter { .. }
                | NodeSpec::Repeat { .. }
                | NodeSpec::Timeout { .. }
                | NodeSpec::Watchdog { .. }
                | NodeSpec::CheckBlackboard { .. }
                | NodeSpec::RosTopicPublish { .. }
                | NodeSpec::RosTopicSubscribe { .. }
                | NodeSpec::RosServiceCall { .. } => false,
            }
        }
        let mut out = Vec::new();
        if self.disposition != Disposition::Clear {
            out.push(MissionLint::NonClearDisposition {
                disposition: self.disposition,
            });
        }
        for name in self.unmatched_costs() {
            out.push(MissionLint::UnmatchedCost { name });
        }

        // Key flow: written vs read.
        fn writes(spec: &NodeSpec, acc: &mut Vec<String>) {
            match spec {
                NodeSpec::SetBlackboard { key, .. } => acc.push(key.clone()),
                NodeSpec::RosTopicSubscribe { output_key, .. } => acc.push(output_key.clone()),
                NodeSpec::RosServiceCall { output_key, .. } => acc.push(output_key.clone()),
                _ => {}
            }
            for (child, _) in spec_children(spec) {
                writes(child, acc);
            }
        }
        fn reads(spec: &NodeSpec, path: &str, acc: &mut Vec<(String, String)>) {
            match spec {
                NodeSpec::CheckBlackboard { key, .. } => acc.push((key.clone(), path.to_string())),
                _ => {}
            }
            for (child, seg) in spec_children(spec) {
                reads(child, &format!("{path}.{seg}"), acc);
            }
        }
        let mut written = Vec::new();
        writes(&self.root, &mut written);
        let mut read_sites = Vec::new();
        reads(&self.root, "root", &mut read_sites);
        if let Some(goal) = &self.goal {
            for conjunct in &goal.dnf {
                for lit in conjunct {
                    read_sites.push((lit.key.clone(), "goal".to_string()));
                }
            }
        }
        for (key, _) in &read_sites {
            if !written.contains(key) {
                let sites: Vec<String> = read_sites
                    .iter()
                    .filter(|(k, _)| k == key)
                    .map(|(_, p)| p.clone())
                    .collect();
                if !out.iter().any(|l| {
                    matches!(l, MissionLint::UnwrittenKey { key: k, .. } if k == key)
                }) {
                    out.push(MissionLint::UnwrittenKey {
                        key: key.clone(),
                        read_at: sites,
                    });
                }
            }
        }

        // Structural walk for unreachable/dead/vacuous/unbounded nodes.
        fn walk(spec: &NodeSpec, path: &str, out: &mut Vec<MissionLint>) {
            match spec {
                NodeSpec::Selector { children, .. } => {
                    if let Some(first) = children.first() {
                        if infallible(first) {
                            for (i, _) in children.iter().enumerate().skip(1) {
                                out.push(MissionLint::UnreachableSibling {
                                    path: format!("{path}.children[{i}]"),
                                });
                            }
                        }
                    }
                }
                NodeSpec::Retry { child, .. } => {
                    if infallible(child) {
                        out.push(MissionLint::DeadRetry {
                            path: path.to_string(),
                        });
                    }
                }
                NodeSpec::Inverter { child, .. } => {
                    if infallible(child) {
                        out.push(MissionLint::AlwaysFailingInverter {
                            path: path.to_string(),
                        });
                    }
                }
                NodeSpec::Repeat { count: None, .. } => {
                    out.push(MissionLint::UnboundedRepeat {
                        path: path.to_string(),
                    });
                }
                _ => {}
            }
            for (child, seg) in spec_children(spec) {
                walk(child, &format!("{path}.{seg}"), out);
            }
        }
        walk(&self.root, "root", &mut out);
        out
    }
}

fn build_node(spec: NodeSpec) -> Result<Box<dyn BTreeNode>> {
    use crate::nodes::{
        action::SetBlackboard,
        composite::{Parallel, ParallelPolicy, Selector, Sequence},
        condition::CheckBlackboard,
        decorator::{Inverter, Repeat, Retry, Timeout, Watchdog},
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
        NodeSpec::Watchdog {
            name,
            child,
            timeout_ms,
            max_consecutive_running,
        } => {
            let name = display_name(&name, "watchdog");
            Ok(Box::new(Watchdog::new(
                name,
                build_node(*child)?,
                timeout_ms,
                max_consecutive_running,
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
    /// Single file read: header, tree, and goal travel together.
    #[tokio::test]
    async fn flagship_mission_proves_its_goal() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../missions/wharf-inspection.json"
        );
        let mission = Mission::from_file(path).unwrap();
        assert_eq!(mission.disposition, Disposition::Clear);
        assert!(mission.unmatched_costs().is_empty());
        assert!(!mission.has_unbounded_repeat());

        let proof = mission
            .run(crate::executor::ExecutorConfig::default())
            .await
            .unwrap();
        assert!(proof.is_proof());
        assert_eq!(proof.snapshot["phase"], "done");
    }

    #[tokio::test]
    async fn success_without_goal_is_not_proof() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "goal": {"dnf": [[{"key": "phase", "expected": "done"}]]},
                "root": {"type": "SetBlackboard", "name": "a", "key": "phase", "value": "running"}}"#,
        )
        .unwrap();
        let proof = mission
            .run(crate::executor::ExecutorConfig::default())
            .await
            .unwrap();
        assert_eq!(proof.status, crate::core::NodeStatus::Success);
        assert!(!proof.goal_satisfied);
        assert!(!proof.is_proof());
    }

    #[test]
    fn degenerate_parameters_rejected() {
        let err = expect_err(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Repeat", "name": "r", "count": 0,
                    "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}}"#,
        );
        assert!(err.contains("count 0"), "got: {err}");
        let err = expect_err(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Timeout", "name": "t", "timeout_ms": 0,
                    "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}}"#,
        );
        assert!(err.contains("timeout_ms 0"), "got: {err}");
    }

    #[test]
    fn parse_rejects_duplicate_names() {
        let err = match Mission::parse(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "SetBlackboard", "name": "dup", "key": "a", "value": 1},
                    {"type": "SetBlackboard", "name": "dup", "key": "b", "value": 2}
                ]}}"#,
        ) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => format!("{e:?}"),
        };
        assert!(err.contains("duplicate node name"), "got: {err}");
    }

    #[test]
    fn flagship_lints_clean() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../missions/wharf-inspection.json"
        );
        let mission = Mission::from_file(path).unwrap();
        assert_eq!(mission.lint(), vec![]);
    }

    #[test]
    fn lint_finds_unreachable_unwritten_and_vacuous() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "goal": {"dnf": [[{"key": "never_written", "expected": 1}]]},
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "Selector", "name": "s", "children": [
                        {"type": "SetBlackboard", "name": "a", "key": "x", "value": 1},
                        {"type": "SetBlackboard", "name": "b", "key": "y", "value": 2}
                    ]},
                    {"type": "Inverter", "name": "i",
                     "child": {"type": "SetBlackboard", "name": "c", "key": "z", "value": 3}}
                ]}}"#,
        )
        .unwrap();
        let lint = mission.lint();
        assert!(
            lint.contains(&MissionLint::UnreachableSibling {
                path: "root.children[0].children[1]".to_string()
            }),
            "got: {lint:?}"
        );
        assert!(
            lint.iter().any(|l| matches!(
                l,
                MissionLint::UnwrittenKey { key, .. } if key == "never_written"
            )),
            "got: {lint:?}"
        );
        assert!(
            lint.contains(&MissionLint::AlwaysFailingInverter {
                path: "root.children[1]".to_string()
            }),
            "got: {lint:?}"
        );
    }

    #[test]
    fn cost_bound_follows_tree_shape() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "costs": {"a": 5.0, "b": 5.0, "c": 1.0},
                "root": {"type": "Parallel", "name": "p", "policy": "RequireOne", "children": [
                    {"type": "SetBlackboard", "name": "a", "key": "x", "value": 1},
                    {"type": "Retry", "name": "r", "max_retries": 2,
                     "child": {"type": "SetBlackboard", "name": "c", "key": "y", "value": 2}},
                    {"type": "SetBlackboard", "name": "b", "key": "z", "value": 3}
                ]}}"#,
        )
        .unwrap();
        // RequireOne takes the max branch: max(5, 3x1, 5) = 5 under both criteria.
        assert_eq!(mission.cost_bound(Optimality::MinExpectedCost), 5.0);
        // Retry alone: expected prices one attempt, worst prices all three.
        let retry = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "costs": {"c": 1.0},
                "root": {"type": "Retry", "name": "r", "max_retries": 2,
                    "child": {"type": "SetBlackboard", "name": "c", "key": "y", "value": 2}}}"#,
        )
        .unwrap();
        assert_eq!(retry.cost_bound(Optimality::MinExpectedCost), 1.0);
        assert_eq!(retry.cost_bound(Optimality::MinWorstCaseCost), 3.0);
        assert_eq!(retry.cost_bound(Optimality::RobustUnderNFailures), 3.0);
    }

    #[test]
    fn path_keyed_cost_takes_precedence() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "costs": {"a": 100.0, "root.children[0]": 4.0},
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "SetBlackboard", "name": "a", "key": "x", "value": 1}
                ]}}"#,
        )
        .unwrap();
        assert!(mission.unmatched_costs().is_empty());
        assert_eq!(mission.cost_bound(Optimality::MinExpectedCost), 4.0);
    }

    #[test]
    fn uncovered_nodes_lists_unpriced() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "costs": {"priced": 1.0},
                "root": {"type": "Sequence", "name": "m", "children": [
                    {"type": "SetBlackboard", "name": "priced", "key": "x", "value": 1},
                    {"type": "SetBlackboard", "name": "free", "key": "y", "value": 2}
                ]}}"#,
        )
        .unwrap();
        // "m" itself is also uncovered.
        assert_eq!(mission.uncovered_nodes(), vec!["free".to_string(), "m".to_string()]);
    }

    #[test]
    fn node_at_resolves_paths() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Retry", "name": "r", "max_retries": 1,
                    "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}}"#,
        )
        .unwrap();
        assert!(mission.node_at("root").is_some());
        assert!(mission.node_at("root.child").is_some());
        assert!(mission.node_at("root.children[0]").is_none());
    }

    #[tokio::test]
    async fn watchdog_parses_indexes_and_builds() {
        let mission = Mission::from_str(
            r#"{"version": "darksand-mission.v1",
                "root": {"type": "Watchdog", "name": "w", "timeout_ms": 500,
                    "max_consecutive_running": 5,
                    "child": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}}"#,
        )
        .unwrap();
        let paths: Vec<String> = mission
            .index()
            .into_iter()
            .map(|n| n.path)
            .collect();
        assert_eq!(paths, vec!["root".to_string(), "root.child".to_string()]);
        // Builds and ticks through to Success (child succeeds first tick).
        let mut tree = mission.build().unwrap();
        let mut ctx = BTreeContext::new();
        let status = tree.tick(&mut ctx).await.unwrap();
        assert_eq!(status, crate::core::NodeStatus::Success);
    }
}
