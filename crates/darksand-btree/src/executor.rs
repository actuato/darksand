//! Behavior-tree executor with lifecycle management.
//!
//! Ticks a tree until it reaches a terminal status or a bound
//! (max ticks, deadline, external cancel) trips. WAL checkpoints and the
//! tree visualizer are deferred; the per-tick JSON observer is kept for
//! live mission monitoring.

use crate::core::{BTreeContext, BTreeNode, NodeStatus};
use crate::result::ExecutionResult;
use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Executor configuration
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum number of ticks before stopping (None = unlimited)
    pub max_ticks: Option<u64>,

    /// Maximum execution duration before stopping (None = unlimited)
    pub deadline: Option<Duration>,

    /// Enable execution tracing
    pub enable_tracing: bool,

    /// Delay between ticks (for rate limiting)
    pub tick_delay: Option<Duration>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_ticks: None,
            deadline: None,
            enable_tracing: false,
            tick_delay: None,
        }
    }
}

/// High-level behavior tree executor.
pub struct BTreeExecutor {
    config: ExecutorConfig,
    /// Optional per-tick state observer. After each tick the executor sends a
    /// JSON snapshot `{"tick": N, "status": "...", "tree": {...}}` to this
    /// channel. Best-effort — a lagged receiver never stalls execution.
    tick_observer: Option<watch::Sender<serde_json::Value>>,
}

impl BTreeExecutor {
    /// Create a new executor with default configuration
    pub fn new() -> Self {
        Self {
            config: ExecutorConfig::default(),
            tick_observer: None,
        }
    }

    /// Create executor with custom configuration
    pub fn with_config(config: ExecutorConfig) -> Self {
        Self {
            config,
            tick_observer: None,
        }
    }

    /// Attach a tick observer channel for live streaming.
    pub fn with_tick_observer(mut self, tx: watch::Sender<serde_json::Value>) -> Self {
        self.tick_observer = Some(tx);
        self
    }

    /// Set maximum ticks (builder pattern)
    pub fn with_max_ticks(mut self, max_ticks: u64) -> Self {
        self.config.max_ticks = Some(max_ticks);
        self
    }

    /// Set execution deadline (builder pattern)
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.config.deadline = Some(deadline);
        self
    }

    /// Enable execution tracing (builder pattern)
    pub fn with_tracing(mut self, enabled: bool) -> Self {
        self.config.enable_tracing = enabled;
        self
    }

    /// Set tick delay for rate limiting (builder pattern)
    pub fn with_tick_delay(mut self, delay: Duration) -> Self {
        self.config.tick_delay = Some(delay);
        self
    }

    /// Execute a behavior tree until completion or limits reached.
    pub async fn execute(
        &self,
        tree: &mut dyn BTreeNode,
        context: &mut BTreeContext,
    ) -> Result<ExecutionResult> {
        let (tx, rx) = watch::channel(false);
        drop(tx); // Never cancel

        self.execute_with_cancel(tree, context, rx).await
    }

    /// Execute with cancellation support via a watch channel.
    /// When the channel receives `true`, execution stops gracefully.
    pub async fn execute_with_cancel(
        &self,
        tree: &mut dyn BTreeNode,
        context: &mut BTreeContext,
        mut cancel_rx: watch::Receiver<bool>,
    ) -> Result<ExecutionResult> {
        let start_time = Instant::now();
        let mut tick_count = 0u64;

        if self.config.enable_tracing {
            info!(
                "Starting execution of tree '{}' (type: {})",
                tree.name(),
                tree.node_type()
            );
            debug!("Config: {:?}", self.config);
        }

        loop {
            if *cancel_rx.borrow_and_update() {
                warn!("Execution cancelled at tick {}", tick_count);
                tree.halt().await;
                return Ok(ExecutionResult::new(
                    NodeStatus::Running,
                    tick_count,
                    start_time.elapsed(),
                )
                .with_cancelled());
            }

            if let Some(max_ticks) = self.config.max_ticks {
                if tick_count >= max_ticks {
                    warn!("Max ticks ({}) reached", max_ticks);
                    tree.halt().await;
                    return Ok(ExecutionResult::new(
                        NodeStatus::Running,
                        tick_count,
                        start_time.elapsed(),
                    )
                    .with_max_ticks_reached());
                }
            }

            if let Some(deadline) = self.config.deadline {
                if start_time.elapsed() >= deadline {
                    warn!("Deadline ({:?}) exceeded", deadline);
                    tree.halt().await;
                    return Ok(ExecutionResult::new(
                        NodeStatus::Running,
                        tick_count,
                        start_time.elapsed(),
                    )
                    .with_deadline_exceeded());
                }
            }

            tick_count += 1;
            context.tick_count = tick_count;

            if self.config.enable_tracing {
                debug!("Tick {} starting", tick_count);
            }

            let status = match tree.tick(context).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Tick {} failed: {}", tick_count, e);
                    return Ok(ExecutionResult::new(
                        NodeStatus::Failure,
                        tick_count,
                        start_time.elapsed(),
                    )
                    .with_error(e.to_string()));
                }
            };

            if self.config.enable_tracing {
                debug!("Tick {} completed with status: {:?}", tick_count, status);
            }

            if let Some(ref tx) = self.tick_observer {
                let tree_json = tree.to_json().unwrap_or_else(|_| serde_json::Value::Null);
                let _ = tx.send(serde_json::json!({
                    "tick": tick_count,
                    "status": format!("{:?}", status),
                    "tree": tree_json,
                }));
            }

            match status {
                NodeStatus::Success => {
                    if self.config.enable_tracing {
                        info!(
                            "Execution succeeded after {} ticks ({:?})",
                            tick_count,
                            start_time.elapsed()
                        );
                    }
                    return Ok(ExecutionResult::new(
                        NodeStatus::Success,
                        tick_count,
                        start_time.elapsed(),
                    ));
                }
                NodeStatus::Failure => {
                    if self.config.enable_tracing {
                        info!(
                            "Execution failed after {} ticks ({:?})",
                            tick_count,
                            start_time.elapsed()
                        );
                    }
                    return Ok(ExecutionResult::new(
                        NodeStatus::Failure,
                        tick_count,
                        start_time.elapsed(),
                    ));
                }
                NodeStatus::Skipped => {
                    if self.config.enable_tracing {
                        info!("Execution skipped after {} ticks", tick_count);
                    }
                    return Ok(ExecutionResult::new(
                        NodeStatus::Skipped,
                        tick_count,
                        start_time.elapsed(),
                    ));
                }
                NodeStatus::Running => {
                    if let Some(delay) = self.config.tick_delay {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    /// Execute a single tick (for manual control).
    pub async fn tick(
        &self,
        tree: &mut dyn BTreeNode,
        context: &mut BTreeContext,
    ) -> Result<NodeStatus> {
        context.tick_count += 1;

        if self.config.enable_tracing {
            debug!(
                "Manual tick {} on tree '{}'",
                context.tick_count,
                tree.name()
            );
        }

        tree.tick(context).await
    }
}

impl Default for BTreeExecutor {
    fn default() -> Self {
        Self::new()
    }
}
