//! Minimal deterministic behavior-tree core for Darksand.
//!
//! Reconstructed for the standalone product (the upstream tree was missing
//! this module). Covers only what deterministic missions need: node trait,
//! shared blackboard, and execution context with an optional ROS2 handle.
//! Deferred: LLM planners, WAL checkpoints, tool registry, visualizer.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
#[cfg(feature = "ros2")]
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "ros2")]
use darksand_ros2::Ros2Node;

/// Tick outcome for a behavior-tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Success,
    Failure,
    Running,
    Skipped,
}

impl NodeStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failure)
    }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// Behavior-tree node: ticked by parents or the executor until terminal.
#[async_trait]
pub trait BTreeNode: Send + Sync {
    fn name(&self) -> &str;
    fn node_type(&self) -> &str;
    async fn tick(&mut self, context: &mut BTreeContext) -> Result<NodeStatus>;

    /// Reset internal progress (default: stateless).
    async fn reset(&mut self) {}

    /// Halt mid-execution (default: reset).
    async fn halt(&mut self) {
        self.reset().await;
    }

    fn to_json(&self) -> Result<Value>;
}

/// Shared key-value blackboard.
#[derive(Debug, Default)]
pub struct Blackboard {
    inner: RwLock<HashMap<String, Value>>,
}

impl Blackboard {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set(&self, key: &str, value: Value) {
        self.inner.write().await.insert(key.to_string(), value);
    }

    pub async fn get(&self, key: &str) -> Option<Value> {
        self.inner.read().await.get(key).cloned()
    }

    pub async fn contains(&self, key: &str) -> bool {
        self.inner.read().await.contains_key(key)
    }

    pub async fn snapshot(&self) -> Value {
        Value::Object(
            self.inner
                .read()
                .await
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }
}

/// Execution context threaded through every tick.
pub struct BTreeContext {
    pub blackboard: Blackboard,
    pub tick_count: u64,
    #[cfg(feature = "ros2")]
    ros2: Option<Arc<Ros2Node>>,
}

impl BTreeContext {
    pub fn new() -> Self {
        Self {
            blackboard: Blackboard::new(),
            tick_count: 0,
            #[cfg(feature = "ros2")]
            ros2: None,
        }
    }

    /// Attach the shared ROS2 node ROS action nodes tick against.
    #[cfg(feature = "ros2")]
    pub fn with_ros2(mut self, node: Arc<Ros2Node>) -> Self {
        self.ros2 = Some(node);
        self
    }

    /// Borrow the ROS2 node or fail the tick when none is attached.
    #[cfg(feature = "ros2")]
    pub fn require_ros2(&self) -> Result<Arc<Ros2Node>> {
        self.ros2
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no ROS2 node attached to BTreeContext"))
    }
}

impl Default for BTreeContext {
    fn default() -> Self {
        Self::new()
    }
}
