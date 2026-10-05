//! Repeat decorator node - repeats child N times or infinitely.

use crate::core::{BTreeContext, BTreeNode, NodeStatus};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

/// Repeat: Repeat child N times or infinitely.
///
/// This decorator re-executes its child until it has succeeded N times (or
/// forever when no count is given). Only successful iterations advance the
/// counter; the tick that completes the final iteration reports `Success`
/// directly, with no extra `Running` tick.
///
/// # Behavior
///
/// - Ticks child node
/// - Child `Success`: increments counter, resets child; returns `Success`
///   when the count is reached, `Running` otherwise
/// - Child `Failure`: returns `Failure` immediately (never swallowed)
/// - Child `Running`/`Skipped`: passes through unchanged
///
/// # Use Cases
///
/// - Periodic behaviors (e.g., "scan sensors every tick")
/// - Looping animations or motions
/// - Continuous monitoring tasks
/// - Background processes
///
/// # Warning
///
/// Infinite repeats never complete on their own. Use with:
/// - Timeout decorator to limit duration
/// - Watchdog to detect stuck loops
/// - External halt signals
/// - Parent nodes that can interrupt (e.g., Parallel, Selector)
///
/// # Examples
///
/// ## Fixed Repeats
///
/// ```
/// use darksand_btree::prelude::*;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let child = Box::new(SetBlackboard::new("action", "counter", 1));
/// let mut repeat = Repeat::new("repeat_3", child, Some(3));
///
/// let mut context = BTreeContext::new();
///
/// // First 3 ticks return Running (child completes 3 times)
/// for _ in 0..3 {
///     let status = repeat.tick(&mut context).await?;
///     // Child completes immediately, but repeat returns Running
/// }
///
/// // 4th tick returns Success (count reached)
/// // Note: Due to implementation, may return Running longer
/// # Ok(())
/// # }
/// ```
///
/// ## Infinite Repeat
///
/// ```
/// use darksand_btree::prelude::*;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let child = Box::new(SetBlackboard::new("action", "tick", "active"));
/// let mut repeat = Repeat::infinite("loop_forever", child);
///
/// let mut context = BTreeContext::new();
///
/// // Will always return Running
/// for _ in 0..100 {
///     let status = repeat.tick(&mut context).await?;
///     assert_eq!(status, NodeStatus::Running);
/// }
/// # Ok(())
/// # }
/// ```
pub struct Repeat {
    name: String,
    child: Box<dyn BTreeNode>,
    count: Option<u32>,
    current: u32,
}

impl Repeat {
    /// Create a new Repeat decorator.
    ///
    /// # Arguments
    ///
    /// * `name` - Node name for debugging
    /// * `child` - Child node to repeat
    /// * `count` - Number of times to repeat (None = infinite)
    ///
    /// # Example
    ///
    /// ```
    /// use darksand_btree::prelude::*;
    ///
    /// let child = Box::new(SetBlackboard::new("action", "key", "value"));
    ///
    /// // Repeat 5 times
    /// let repeat_fixed = Repeat::new(
    ///     "repeat_5",
    ///     Box::new(SetBlackboard::new("action", "key", "value")),
    ///     Some(5),
    /// );
    ///
    /// // Repeat forever
    /// let repeat_inf = Repeat::new("repeat_forever", child, None);
    /// ```
    pub fn new(name: impl Into<String>, child: Box<dyn BTreeNode>, count: Option<u32>) -> Self {
        Self {
            name: name.into(),
            child,
            count,
            current: 0,
        }
    }

    /// Create an infinite repeat (convenience method).
    ///
    /// Equivalent to `Repeat::new(name, child, None)`.
    ///
    /// # Arguments
    ///
    /// * `name` - Node name for debugging
    /// * `child` - Child node to repeat forever
    ///
    /// # Example
    ///
    /// ```
    /// use darksand_btree::prelude::*;
    ///
    /// let child = Box::new(SetBlackboard::new("action", "key", "value"));
    /// let repeat = Repeat::infinite("loop", child);
    ///
    /// assert_eq!(repeat.name(), "loop");
    /// ```
    pub fn infinite(name: impl Into<String>, child: Box<dyn BTreeNode>) -> Self {
        Self::new(name, child, None)
    }
}

#[async_trait]
impl BTreeNode for Repeat {
    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "Repeat"
    }

    async fn tick(&mut self, context: &mut BTreeContext) -> Result<NodeStatus> {
        if let Some(max) = self.count {
            if self.current >= max {
                return Ok(NodeStatus::Success);
            }
        }

        // Only successful iterations advance the count. A child failure fails
        // the repeat immediately instead of being swallowed and retried as if
        // it had succeeded. The tick that completes the final iteration
        // reports Success directly (no extra Running tick).
        match self.child.tick(context).await? {
            NodeStatus::Success => {
                self.current += 1;
                self.child.reset().await;
                if let Some(max) = self.count {
                    if self.current >= max {
                        return Ok(NodeStatus::Success);
                    }
                }
                Ok(NodeStatus::Running)
            }
            NodeStatus::Failure => Ok(NodeStatus::Failure),
            other => Ok(other),
        }
    }

    async fn reset(&mut self) {
        self.current = 0;
        self.child.reset().await;
    }

    fn to_json(&self) -> Result<Value> {
        Ok(serde_json::json!({
            "name": self.name,
            "type": "Repeat",
            "count": self.count,
            "child": self.child.to_json()?
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::action::SetBlackboard;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct FailNode;
    #[async_trait]
    impl BTreeNode for FailNode {
        fn name(&self) -> &str {
            "fail"
        }
        fn node_type(&self) -> &str {
            "Fail"
        }
        async fn tick(&mut self, _context: &mut BTreeContext) -> Result<NodeStatus> {
            Ok(NodeStatus::Failure)
        }
        fn to_json(&self) -> Result<Value> {
            Ok(serde_json::json!({"type": "Fail"}))
        }
    }

    struct CountNode {
        ticks: Arc<AtomicU32>,
    }
    #[async_trait]
    impl BTreeNode for CountNode {
        fn name(&self) -> &str {
            "count"
        }
        fn node_type(&self) -> &str {
            "Count"
        }
        async fn tick(&mut self, _context: &mut BTreeContext) -> Result<NodeStatus> {
            self.ticks.fetch_add(1, Ordering::Relaxed);
            Ok(NodeStatus::Success)
        }
        fn to_json(&self) -> Result<Value> {
            Ok(serde_json::json!({"type": "Count"}))
        }
    }

    #[tokio::test]
    async fn child_failure_fails_repeat_immediately() {
        let mut node = Repeat::new("r", Box::new(FailNode), Some(3));
        let mut ctx = BTreeContext::new();
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Failure);
    }

    #[tokio::test]
    async fn success_reported_on_final_tick_without_extra_running() {
        let ticks = Arc::new(AtomicU32::new(0));
        let mut node = Repeat::new(
            "r",
            Box::new(CountNode {
                ticks: Arc::clone(&ticks),
            }),
            Some(3),
        );
        let mut ctx = BTreeContext::new();
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Running);
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Running);
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Success);
        assert_eq!(ticks.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn set_blackboard_repeat_accumulates() {
        let mut node = Repeat::new(
            "r",
            Box::new(SetBlackboard::new("s", "k", "v")),
            Some(2),
        );
        let mut ctx = BTreeContext::new();
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Running);
        assert_eq!(node.tick(&mut ctx).await.unwrap(), NodeStatus::Success);
        assert!(ctx.blackboard.contains("k").await);
    }
}
