//! # Darksand Behavior Tree (deterministic mission core)
//!
//! Minimal deterministic BT engine for robot missions: control-flow nodes,
//! decorators, blackboard conditions, and — behind the `ros2` feature —
//! ROS2 topic/service action nodes ticking against a shared `Ros2Node`.
//!
//! Deliberately excluded (deferred): LLM planners, JSON mission parser,
//! WAL checkpoints, tool registry, visualizer. See `reference/btree-ros`
//! for the upstream sources these were reconstructed from.

pub mod core;
pub mod executor;
pub mod nodes;
pub mod result;

/// Historical module path (`runtime::BTreeExecutor`) kept working.
pub mod runtime {
    pub use crate::executor::{BTreeExecutor, ExecutorConfig};
    pub use crate::result::ExecutionResult;
}

pub use executor::{BTreeExecutor, ExecutorConfig};
pub use result::ExecutionResult;

/// Commonly used types.
pub mod prelude {
    pub use crate::core::{BTreeContext, BTreeNode, Blackboard, NodeStatus};
    #[cfg(feature = "ros2")]
    pub use crate::nodes::action::{RosServiceCall, RosTopicPublish, RosTopicSubscribe};
    pub use crate::nodes::{
        action::SetBlackboard,
        composite::{Parallel, ParallelPolicy, Selector, Sequence},
        condition::CheckBlackboard,
        decorator::{Inverter, Repeat, Retry, Timeout},
    };
    pub use crate::{BTreeExecutor, ExecutionResult, ExecutorConfig};
    pub use async_trait::async_trait;
    pub use std::sync::Arc;
}
