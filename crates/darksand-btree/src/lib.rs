//! # Darksand Behavior Tree (deterministic mission core)
//!
//! Minimal deterministic BT engine for robot missions: control-flow nodes,
//! decorators, blackboard conditions, and — behind the `ros2` feature —
//! ROS2 topic/service action nodes ticking against a shared `Ros2Node`.
//!
//! Deliberately excluded (deferred): LLM planners,
//! WAL checkpoints, tool registry, visualizer. See `reference/btree-ros`
//! for the upstream sources these were reconstructed from.

pub mod core;
pub mod executor;
pub mod mission;
pub mod nodes;
pub mod result;
pub mod wal;

/// Historical module path (`runtime::BTreeExecutor`) kept working.
pub mod runtime {
    pub use crate::executor::{BTreeExecutor, ExecutorConfig};
    pub use crate::result::ExecutionResult;
}

pub use executor::{BTreeExecutor, ExecutorConfig};
pub use mission::{
    mission_from_file, mission_from_str, Disposition, GoalLiteral, GoalSpec, Mission, NodePath,
    NodeSpec, Optimality, RunProof,
};
pub use result::ExecutionResult;
pub use wal::{
    append_wal, mission_hash, read_wal, read_wal_tolerant, resume_mission_from_wal, verify_wal,
    WalEntry, WalReport,
};

/// Commonly used types.
pub mod prelude {
    pub use crate::core::{BTreeContext, BTreeNode, Blackboard, NodeStatus};
    #[cfg(feature = "ros2")]
    pub use crate::nodes::action::{RosServiceCall, RosTopicPublish, RosTopicSubscribe};
    pub use crate::nodes::{
        action::SetBlackboard,
        composite::{Parallel, ParallelPolicy, Selector, Sequence},
        condition::CheckBlackboard,
        decorator::{Inverter, Repeat, Retry, Timeout, Watchdog},
    };
    pub use crate::{BTreeExecutor, ExecutionResult, ExecutorConfig};
    pub use crate::{mission_from_file, mission_from_str, Mission, NodeSpec};
    pub use crate::{Disposition, GoalLiteral, GoalSpec, NodePath, Optimality, RunProof};
    pub use crate::{append_wal, read_wal, resume_mission_from_wal, WalEntry};
    pub use crate::{mission_hash, read_wal_tolerant, verify_wal, WalReport};
    pub use async_trait::async_trait;
    pub use std::sync::Arc;
}
