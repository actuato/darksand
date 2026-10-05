//! Watchdog decorator: trip when a child stops making progress.
//!
//! `Timeout` bounds wall-clock time; `Watchdog` additionally bounds
//! *consecutive `Running` ticks*. A child that answers every tick but never
//! finishes (livelock) trips the consecutive-Running counter even when the
//! wall clock has not expired. Either trip halts the child and reports
//! `Failure` — the reference implementation only warned.

use crate::core::{BTreeContext, BTreeNode, NodeStatus};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::time::{Duration, Instant};

pub struct Watchdog {
    name: String,
    child: Box<dyn BTreeNode>,
    timeout: Duration,
    max_consecutive_running: u32,
    start_time: Option<Instant>,
    consecutive_running: u32,
}

impl Watchdog {
    /// Create a watchdog around `child`.
    ///
    /// * `timeout_ms` — wall-clock budget from the first tick.
    /// * `max_consecutive_running` — trip after this many back-to-back
    ///   `Running` ticks (0 disables the consecutive trip).
    pub fn new(
        name: impl Into<String>,
        child: Box<dyn BTreeNode>,
        timeout_ms: u64,
        max_consecutive_running: u32,
    ) -> Self {
        Self {
            name: name.into(),
            child,
            timeout: Duration::from_millis(timeout_ms),
            max_consecutive_running,
            start_time: None,
            consecutive_running: 0,
        }
    }
}

#[async_trait]
impl BTreeNode for Watchdog {
    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "Watchdog"
    }

    async fn tick(&mut self, context: &mut BTreeContext) -> Result<NodeStatus> {
        if self.start_time.is_none() {
            self.start_time = Some(Instant::now());
        }

        // Wall-clock trip first: cheapest check, no child tick spent.
        if let Some(start) = self.start_time {
            if start.elapsed() > self.timeout {
                self.child.halt().await;
                self.reset().await;
                return Ok(NodeStatus::Failure);
            }
        }

        match self.child.tick(context).await? {
            NodeStatus::Running => {
                self.consecutive_running += 1;
                if self.max_consecutive_running > 0
                    && self.consecutive_running >= self.max_consecutive_running
                {
                    self.child.halt().await;
                    self.reset().await;
                    return Ok(NodeStatus::Failure);
                }
                Ok(NodeStatus::Running)
            }
            status => {
                self.reset().await;
                Ok(status)
            }
        }
    }

    async fn reset(&mut self) {
        self.start_time = None;
        self.consecutive_running = 0;
        self.child.reset().await;
    }

    fn to_json(&self) -> Result<Value> {
        Ok(serde_json::json!({
            "name": self.name,
            "type": "Watchdog",
            "timeout_ms": self.timeout.as_millis(),
            "max_consecutive_running": self.max_consecutive_running,
            "child": self.child.to_json()?
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct AlwaysRunning {
        ticks: Arc<AtomicU32>,
        halts: Arc<AtomicU32>,
    }
    #[async_trait]
    impl BTreeNode for AlwaysRunning {
        fn name(&self) -> &str {
            "running"
        }
        fn node_type(&self) -> &str {
            "Running"
        }
        async fn tick(&mut self, _context: &mut BTreeContext) -> Result<NodeStatus> {
            self.ticks.fetch_add(1, Ordering::Relaxed);
            Ok(NodeStatus::Running)
        }
        async fn halt(&mut self) {
            self.halts.fetch_add(1, Ordering::Relaxed);
        }
        fn to_json(&self) -> Result<Value> {
            Ok(serde_json::json!({"type": "Running"}))
        }
    }

    #[tokio::test]
    async fn consecutive_running_trip_halts_child() {
        let ticks = Arc::new(AtomicU32::new(0));
        let halts = Arc::new(AtomicU32::new(0));
        let mut node = Watchdog::new(
            "w",
            Box::new(AlwaysRunning {
                ticks: Arc::clone(&ticks),
                halts: Arc::clone(&halts),
            }),
            60_000,
            3,
        );
        let mut ctx = BTreeContext::new();
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Running);
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Running);
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Failure);
        assert_eq!(ticks.load(Ordering::Relaxed), 3);
        assert_eq!(halts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn wall_clock_trip_without_child_progress() {
        let mut node = Watchdog::new(
            "w",
            Box::new(AlwaysRunning {
                ticks: Arc::new(AtomicU32::new(0)),
                halts: Arc::new(AtomicU32::new(0)),
            }),
            20,
            0,
        );
        let mut ctx = BTreeContext::new();
        tokio::time::sleep(Duration::from_millis(30)).await;
        // First tick arms the timer and passes through; the second tick
        // observes the expired budget and trips.
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Running);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Failure);
    }

    #[tokio::test]
    async fn success_passes_through_and_resets() {
        use crate::nodes::action::SetBlackboard;
        let mut node = Watchdog::new(
            "w",
            Box::new(SetBlackboard::new("s", "k", "v")),
            5_000,
            10,
        );
        let mut ctx = BTreeContext::new();
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Success);
        assert!(ctx.blackboard.contains("k").await);
    }
}
