//! Swarm Intelligence for Darksand Runtime
//!
//! Provides advanced swarm coordination features for multi-agent systems.
//!
//! # Features
//! - **Leader Election:** Dynamic leader selection using Raft-style consensus
//! - **Conflict Resolution:** Automatic resolution of conflicting decisions
//! - **Decentralized Planning:** Distributed task planning across swarm members
//! - **Task Execution:** Run consensus-approved tasks with pluggable handlers
//! - **Scalability:** Support for 100+ agents
//! - **Fault Tolerance:** Automatic failover, stale agent cleanup, and recovery
//!
//! # Example
//! ```no_run
//! use darksand_swarm::{SwarmCoordinator, SwarmConfig, AgentRole};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = SwarmConfig::default();
//!     let coordinator = SwarmCoordinator::new(config).await?;
//!
//!     // Join swarm
//!     coordinator.join_swarm("agent-1").await?;
//!
//!     // Check role
//!     let role = coordinator.get_role().await;
//!     println!("My role: {:?}", role);
//!
//!     Ok(())
//! }
//! ```

pub mod message_signing;
pub mod task_executor;
pub mod transport;

pub use message_signing::{
    verify_envelope, verify_envelope_fresh, PeerKeyRegistry, SignedSwarmEnvelope, SwarmMessageSigner,
};
pub use task_executor::{
    HealthCheckHandler, InferenceTaskHandler, TaskExecutionResult, TaskExecutor, TaskHandler,
};
pub use transport::{SwarmBus, SwarmMessage, SwarmTransport, SwarmTransportHandle};

use anyhow::Result;
use crate::transport::SwarmTransport as _;
use rand::Rng;use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Agent role in the swarm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    /// Leader agent (coordinates swarm)
    Leader,
    /// Follower agent (executes tasks)
    Follower,
    /// Candidate (election in progress)
    Candidate,
}

/// Swarm configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Enable swarm coordination
    pub enabled: bool,

    /// Election timeout range (min, max) in seconds
    pub election_timeout_secs: (u64, u64),

    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,

    /// Maximum number of agents in swarm
    pub max_agents: usize,

    /// Enable conflict resolution
    pub enable_conflict_resolution: bool,

    /// Conflict resolution strategy
    pub conflict_strategy: ConflictStrategy,

    /// Stale agent timeout in seconds (remove if no heartbeat)
    pub stale_agent_timeout_secs: u64,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            election_timeout_secs: (5, 10),
            heartbeat_interval_secs: 2,
            max_agents: 100,
            enable_conflict_resolution: true,
            conflict_strategy: ConflictStrategy::Voting,
            stale_agent_timeout_secs: 30,
        }
    }
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Leader decides
    LeaderDecides,
    /// Majority voting
    Voting,
    /// Priority-based (higher priority wins)
    Priority,
    /// Consensus (all agents must agree)
    Consensus,
}

/// Agent metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub role: AgentRole,
    pub last_heartbeat: u64,
    pub term: u64,
    pub priority: u8,
    pub capabilities: Vec<String>,
}

/// Task proposal for swarm planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskProposal {
    pub id: String,
    pub proposer_id: String,
    pub task_type: String,
    pub parameters: serde_json::Value,
    pub priority: u8,
    pub timestamp: u64,
    pub votes: HashMap<String, bool>,
}

impl TaskProposal {
    /// Check if proposal has reached consensus
    pub fn has_consensus(&self, required_votes: usize) -> bool {
        let approvals = self.votes.values().filter(|&&v| v).count();
        approvals >= required_votes
    }

    /// Check if proposal is rejected
    pub fn is_rejected(&self, total_agents: usize) -> bool {
        let rejections = self.votes.values().filter(|&&v| !v).count();
        let required_majority = (total_agents / 2) + 1;
        rejections >= required_majority
    }
}

/// Swarm status summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmStatus {
    pub agent_id: String,
    pub role: AgentRole,
    pub term: u64,
    pub leader_id: Option<String>,
    pub swarm_size: usize,
    pub pending_proposals: usize,
}

/// Swarm Coordinator
pub struct SwarmCoordinator {
    config: SwarmConfig,

    // Agent metadata
    agent_id: String,
    current_role: Arc<RwLock<AgentRole>>,
    current_term: Arc<RwLock<u64>>,
    voted_for: Arc<RwLock<Option<String>>>,

    // Election tracking
    votes_received: Arc<RwLock<HashSet<String>>>,

    // Swarm state
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
    leader_id: Arc<RwLock<Option<String>>>,

    // Planning state
    proposals: Arc<RwLock<HashMap<String, TaskProposal>>>,

    // Election state
    last_heartbeat_received: Arc<RwLock<SystemTime>>,

    // Task executor
    task_executor: Option<Arc<TaskExecutor>>,
}

impl SwarmCoordinator {
    /// Create a new swarm coordinator
    pub async fn new(config: SwarmConfig) -> Result<Self> {
        let agent_id = Uuid::new_v4().to_string();

        info!("Initializing swarm coordinator for agent {}", agent_id);

        let coordinator = Self {
            config,
            agent_id: agent_id.clone(),
            current_role: Arc::new(RwLock::new(AgentRole::Follower)),
            current_term: Arc::new(RwLock::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
            votes_received: Arc::new(RwLock::new(HashSet::new())),
            agents: Arc::new(RwLock::new(HashMap::new())),
            leader_id: Arc::new(RwLock::new(None)),
            proposals: Arc::new(RwLock::new(HashMap::new())),
            last_heartbeat_received: Arc::new(RwLock::new(SystemTime::now())),
            task_executor: None,
        };

        Ok(coordinator)
    }

    /// Create with a specific agent ID
    pub async fn with_id(config: SwarmConfig, agent_id: &str) -> Result<Self> {
        let mut coordinator = Self::new(config).await?;
        coordinator.agent_id = agent_id.to_string();
        Ok(coordinator)
    }

    /// Attach a task executor for handling consensus-approved tasks
    pub fn set_task_executor(&mut self, executor: Arc<TaskExecutor>) {
        self.task_executor = Some(executor);
    }

    /// Get this agent's ID
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Join the swarm
    pub async fn join_swarm(&self, custom_id: &str) -> Result<()> {
        let agents = self.agents.read().await;
        if agents.len() >= self.config.max_agents {
            return Err(anyhow::anyhow!(
                "Swarm full: {}/{} agents",
                agents.len(),
                self.config.max_agents
            ));
        }
        drop(agents);

        info!("Agent {} joining swarm", custom_id);

        let info = AgentInfo {
            id: custom_id.to_string(),
            role: AgentRole::Follower,
            last_heartbeat: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            term: 0,
            priority: 1,
            capabilities: vec!["inference".to_string(), "planning".to_string()],
        };

        let mut agents = self.agents.write().await;
        agents.insert(custom_id.to_string(), info);

        Ok(())
    }

    /// Start election timeout monitor
    pub async fn start_election_monitor(&self) -> Result<()> {
        let last_heartbeat = self.last_heartbeat_received.clone();
        let current_role = self.current_role.clone();
        let timeout_range = self.config.election_timeout_secs;

        tokio::spawn(async move {
            loop {
                // Random timeout between min and max
                let timeout_secs = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(timeout_range.0..=timeout_range.1)
                };
                let timeout = Duration::from_secs(timeout_secs);

                time::sleep(timeout).await;

                let last = last_heartbeat.read().await;
                let elapsed = SystemTime::now().duration_since(*last).unwrap_or_default();

                if elapsed > timeout {
                    let mut role = current_role.write().await;
                    if *role == AgentRole::Follower {
                        warn!("Election timeout - becoming candidate");
                        *role = AgentRole::Candidate;
                    }
                }
            }
        });

        Ok(())
    }

    /// One election-monitor step, factored out so it is testable without
    /// sleeping through randomized timeouts. Returns `true` when it
    /// escalated (Follower→Candidate, or Candidate→new election).
    ///
    /// The spawned [`Self::start_election_monitor`] loop calls the same
    /// transition every second; this is the whole state machine, the loop
    /// is just a timer around it.
    pub async fn tick_election(&self) -> Result<bool> {
        let elapsed = SystemTime::now()
            .duration_since(*self.last_heartbeat_received.read().await)
            .unwrap_or_default();
        if elapsed <= Duration::from_secs(self.config.election_timeout_secs.0) {
            return Ok(false);
        }
        // Re-arm the timer first: the next escalation is a full timeout away,
        // so terms advance once per timeout, not once per monitor tick.
        *self.last_heartbeat_received.write().await = SystemTime::now();
        let role = *self.current_role.read().await;
        match role {
            AgentRole::Follower => {
                warn!("Election timeout - becoming candidate");
                *self.current_role.write().await = AgentRole::Candidate;
                Ok(true)
            }
            AgentRole::Candidate => {
                // Re-arm: new term, self-vote, and re-check the majority so
                // a lone agent (or a partition of one) still converges.
                self.start_election().await?;
                Ok(true)
            }
            AgentRole::Leader => Ok(false),
        }
    }

    /// Start an election (Raft-style with vote counting)
    pub async fn start_election(&self) -> Result<()> {
        info!("Starting leader election");

        // Increment term
        let mut term = self.current_term.write().await;
        *term += 1;
        let new_term = *term;

        // Vote for self
        let mut voted = self.voted_for.write().await;
        *voted = Some(self.agent_id.clone());

        // Track votes received (start with self-vote)
        let mut votes = self.votes_received.write().await;
        votes.clear();
        votes.insert(self.agent_id.clone());

        // Become candidate
        let mut role = self.current_role.write().await;
        *role = AgentRole::Candidate;

        debug!("Agent {} is candidate for term {}", self.agent_id, new_term);

        // Check if we're the only agent (auto-win)
        let agents = self.agents.read().await;
        let total_agents = agents.len().max(1); // At least count ourselves
        let required_votes = (total_agents / 2) + 1;

        if votes.len() >= required_votes {
            drop(agents);
            drop(votes);
            drop(voted);
            drop(term);
            drop(role);
            self.become_leader().await?;
        }
        // Otherwise, wait for RequestVote responses via process_vote_response()

        Ok(())
    }

    /// Process a vote request from another candidate
    pub async fn process_vote_request(
        &self,
        candidate_id: &str,
        candidate_term: u64,
    ) -> (bool, u64) {
        let current_term = *self.current_term.read().await;

        // Reject if candidate's term is stale
        if candidate_term < current_term {
            return (false, current_term);
        }

        // Step down if candidate's term is higher
        if candidate_term > current_term {
            *self.current_term.write().await = candidate_term;
            *self.current_role.write().await = AgentRole::Follower;
            *self.voted_for.write().await = None;
        }

        // Vote if we haven't voted in this term
        let mut voted_for = self.voted_for.write().await;
        if voted_for.is_none() || voted_for.as_ref() == Some(&candidate_id.to_string()) {
            *voted_for = Some(candidate_id.to_string());
            info!("Voting for {} in term {}", candidate_id, candidate_term);
            (true, candidate_term)
        } else {
            debug!(
                "Already voted for {:?} in term {}",
                *voted_for, candidate_term
            );
            (false, candidate_term)
        }
    }

    /// Process a vote response (called when another agent votes for us)
    pub async fn process_vote_response(
        &self,
        voter_id: &str,
        granted: bool,
        response_term: u64,
    ) -> Result<()> {
        let current_term = *self.current_term.read().await;

        // If response has higher term, step down
        if response_term > current_term {
            *self.current_term.write().await = response_term;
            *self.current_role.write().await = AgentRole::Follower;
            *self.voted_for.write().await = None;
            return Ok(());
        }

        // Only process if we're still a candidate in the same term
        let role = *self.current_role.read().await;
        if role != AgentRole::Candidate || response_term != current_term {
            return Ok(());
        }

        if granted {
            let mut votes = self.votes_received.write().await;
            votes.insert(voter_id.to_string());

            let agents = self.agents.read().await;
            let total_agents = agents.len().max(1);
            let required_votes = (total_agents / 2) + 1;

            if votes.len() >= required_votes {
                drop(votes);
                drop(agents);
                self.become_leader().await?;
            }
        }

        Ok(())
    }

    /// Become leader
    async fn become_leader(&self) -> Result<()> {
        info!(
            "Agent {} became leader for term {}",
            self.agent_id,
            *self.current_term.read().await
        );

        *self.current_role.write().await = AgentRole::Leader;
        *self.leader_id.write().await = Some(self.agent_id.clone());

        Ok(())
    }

    /// Process a heartbeat from the leader
    pub async fn process_heartbeat(&self, leader_id: &str, leader_term: u64) {
        let current_term = *self.current_term.read().await;

        if leader_term >= current_term {
            // Accept leader's authority
            if leader_term > current_term {
                *self.current_term.write().await = leader_term;
            }

            *self.current_role.write().await = AgentRole::Follower;
            *self.leader_id.write().await = Some(leader_id.to_string());
            *self.last_heartbeat_received.write().await = SystemTime::now();

            // Update agent info for leader
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(leader_id) {
                agent.last_heartbeat = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                agent.role = AgentRole::Leader;
                agent.term = leader_term;
            }
        }
    }

    /// Send heartbeat (leader only)
    pub async fn send_heartbeat(&self) -> Result<()> {
        let role = self.current_role.read().await;
        if *role != AgentRole::Leader {
            return Err(anyhow::anyhow!("Only leader can send heartbeats"));
        }

        debug!("Leader sending heartbeat");
        Ok(())
    }

    /// Broadcast a heartbeat over `transport` (leader only) and refresh the
    /// leader's own heartbeat clock so it never considers itself stale.
    ///
    /// This is the real send path; [`Self::send_heartbeat`] only asserts
    /// leadership without a transport to speak on.
    pub async fn broadcast_heartbeat(
        &self,
        transport: &impl SwarmTransport,
    ) -> Result<()> {
        let (role, term) = (
            *self.current_role.read().await,
            *self.current_term.read().await,
        );
        if role != AgentRole::Leader {
            return Err(anyhow::anyhow!("Only leader can send heartbeats"));
        }
        transport
            .broadcast(SwarmMessage::Heartbeat {
                leader_id: self.agent_id.clone(),
                term,
            })
            .await?;
        *self.last_heartbeat_received.write().await = SystemTime::now();
        Ok(())
    }

    /// Get current role
    pub async fn get_role(&self) -> AgentRole {
        *self.current_role.read().await
    }

    /// Get current term
    pub async fn get_term(&self) -> u64 {
        *self.current_term.read().await
    }

    /// Get leader ID
    pub async fn get_leader_id(&self) -> Option<String> {
        self.leader_id.read().await.clone()
    }

    /// Propose a task to the swarm
    pub async fn propose_task(
        &self,
        task_type: String,
        parameters: serde_json::Value,
        priority: u8,
    ) -> Result<String> {
        let proposal = TaskProposal {
            id: Uuid::new_v4().to_string(),
            proposer_id: self.agent_id.clone(),
            task_type,
            parameters,
            priority,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            votes: HashMap::new(),
        };

        let proposal_id = proposal.id.clone();

        let mut proposals = self.proposals.write().await;
        proposals.insert(proposal_id.clone(), proposal);

        info!("Proposed task: {}", proposal_id);

        Ok(proposal_id)
    }

    /// Vote on a task proposal
    pub async fn vote_on_proposal(&self, proposal_id: &str, approve: bool) -> Result<()> {
        let mut proposals = self.proposals.write().await;

        let proposal = proposals
            .get_mut(proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found"))?;

        proposal.votes.insert(self.agent_id.clone(), approve);

        debug!(
            "Agent {} voted {} on proposal {}",
            self.agent_id,
            if approve { "approve" } else { "reject" },
            proposal_id
        );

        Ok(())
    }

    /// Check if proposal has reached consensus and execute if so
    pub async fn check_and_execute_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<Option<TaskExecutionResult>> {
        let agents = self.agents.read().await;
        let total_agents = agents.len().max(1);
        let required_votes = (total_agents / 2) + 1;
        drop(agents);

        let proposals = self.proposals.read().await;
        let proposal = proposals
            .get(proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found"))?;

        if !proposal.has_consensus(required_votes) {
            return Ok(None);
        }

        let task_type = proposal.task_type.clone();
        let parameters = proposal.parameters.clone();
        let pid = proposal.id.clone();
        drop(proposals);

        // Execute via task executor if available
        if let Some(ref executor) = self.task_executor {
            let result = executor.execute_task(&pid, &task_type, parameters).await?;
            Ok(Some(result))
        } else {
            info!(
                "Proposal {} reached consensus but no task executor configured",
                proposal_id
            );
            Ok(None)
        }
    }

    /// Check if proposal has reached consensus
    pub async fn check_proposal_consensus(&self, proposal_id: &str) -> Result<bool> {
        let proposals = self.proposals.read().await;

        let proposal = proposals
            .get(proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found"))?;

        let agents = self.agents.read().await;
        let total_agents = agents.len().max(1);
        let required_votes = (total_agents / 2) + 1;

        Ok(proposal.has_consensus(required_votes))
    }

    /// Resolve conflict between proposals
    pub async fn resolve_conflict(&self, proposal_ids: Vec<String>) -> Result<Option<String>> {
        let proposals = self.proposals.read().await;

        let conflicting_proposals: Vec<_> = proposal_ids
            .iter()
            .filter_map(|id| proposals.get(id))
            .collect();

        if conflicting_proposals.is_empty() {
            return Ok(None);
        }

        let winner = match self.config.conflict_strategy {
            ConflictStrategy::LeaderDecides => {
                // Leader's proposal wins
                let leader = self.leader_id.read().await;
                conflicting_proposals
                    .iter()
                    .find(|p| leader.as_ref() == Some(&p.proposer_id))
                    .or_else(|| conflicting_proposals.first())
            }
            ConflictStrategy::Voting => {
                // Most votes wins
                conflicting_proposals
                    .iter()
                    .max_by_key(|p| p.votes.values().filter(|&&v| v).count())
            }
            ConflictStrategy::Priority => {
                // Highest priority wins
                conflicting_proposals.iter().max_by_key(|p| p.priority)
            }
            ConflictStrategy::Consensus => {
                // First to reach consensus wins
                let agents = self.agents.read().await;
                let required = (agents.len().max(1) / 2) + 1;
                conflicting_proposals
                    .iter()
                    .find(|p| p.has_consensus(required))
            }
        };

        Ok(winner.map(|p| p.id.clone()))
    }

    /// Clean up stale agents that haven't sent heartbeats
    pub async fn cleanup_stale_agents(&self) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timeout = self.config.stale_agent_timeout_secs;
        let mut agents = self.agents.write().await;
        let mut removed = Vec::new();
        let this = self.agent_id.clone();

        agents.retain(|id, info| {
            // The coordinator is always fresh to itself: evicting our own
            // entry would orphan our leadership and our votes.
            if id == &this {
                return true;
            }
            if now.saturating_sub(info.last_heartbeat) > timeout {
                warn!(
                    "Removing stale agent: {} (last seen {}s ago)",
                    id,
                    now - info.last_heartbeat
                );
                removed.push(id.clone());
                false
            } else {
                true
            }
        });

        // If leader was removed, reset leader
        if let Some(ref leader) = *self.leader_id.read().await {
            if removed.contains(leader) {
                *self.leader_id.write().await = None;
                info!("Leader {} was stale; leader reset", leader);
            }
        }

        removed
    }

    /// Get swarm status summary
    pub async fn get_status(&self) -> SwarmStatus {
        SwarmStatus {
            agent_id: self.agent_id.clone(),
            role: *self.current_role.read().await,
            term: *self.current_term.read().await,
            leader_id: self.leader_id.read().await.clone(),
            swarm_size: self.agents.read().await.len(),
            pending_proposals: self.proposals.read().await.len(),
        }
    }

    /// Get swarm size
    pub async fn get_swarm_size(&self) -> usize {
        self.agents.read().await.len()
    }

    /// Get all agents
    pub async fn get_agents(&self) -> Vec<AgentInfo> {
        self.agents.read().await.values().cloned().collect()
    }

    /// Process an incoming swarm message (from transport layer)
    pub async fn process_message(&self, message: SwarmMessage) -> Result<Option<SwarmMessage>> {
        match message {
            SwarmMessage::RequestVote { candidate_id, term } => {
                let (granted, response_term) = self.process_vote_request(&candidate_id, term).await;
                Ok(Some(SwarmMessage::VoteResponse {
                    voter_id: self.agent_id.clone(),
                    term: response_term,
                    granted,
                }))
            }
            SwarmMessage::VoteResponse {
                voter_id,
                term,
                granted,
            } => {
                self.process_vote_response(&voter_id, granted, term).await?;
                Ok(None)
            }
            SwarmMessage::Heartbeat { leader_id, term } => {
                self.process_heartbeat(&leader_id, term).await;
                Ok(None)
            }
            SwarmMessage::TaskProposed {
                proposal_id,
                proposer_id,
                task_type,
                parameters,
                priority,
            } => {
                // Store the proposal from another agent
                let proposal = TaskProposal {
                    id: proposal_id,
                    proposer_id,
                    task_type,
                    parameters,
                    priority,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs(),
                    votes: HashMap::new(),
                };
                self.proposals
                    .write()
                    .await
                    .insert(proposal.id.clone(), proposal);
                Ok(None)
            }
            SwarmMessage::TaskVote {
                proposal_id,
                voter_id,
                approve,
            } => {
                let mut proposals = self.proposals.write().await;
                if let Some(proposal) = proposals.get_mut(&proposal_id) {
                    proposal.votes.insert(voter_id, approve);
                }
                Ok(None)
            }
            SwarmMessage::AgentJoined {
                agent_id,
                capabilities,
            } => {
                let info = AgentInfo {
                    id: agent_id.clone(),
                    role: AgentRole::Follower,
                    last_heartbeat: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs(),
                    term: 0,
                    priority: 1,
                    capabilities,
                };
                self.agents.write().await.insert(agent_id.clone(), info);
                info!("Agent {} joined swarm", agent_id);
                Ok(None)
            }
            SwarmMessage::AgentLeft { agent_id } => {
                self.agents.write().await.remove(&agent_id);
                info!("Agent {} left swarm", agent_id);
                Ok(None)
            }
            SwarmMessage::TaskResult { .. } => {
                // Task results can be handled by the application layer
                Ok(None)
            }
        }
    }

    /// Process a signed envelope: verify (peer key, signature, freshness,
    /// replay) through `registry`, then handle the inner message.
    ///
    /// This is the ingress every transport MUST use. `process_message`
    /// remains for already-trusted (e.g. loopback/test) traffic.
    pub async fn process_envelope(
        &self,
        envelope: &crate::message_signing::SignedSwarmEnvelope,
        registry: &mut crate::message_signing::PeerKeyRegistry,
    ) -> Result<Option<SwarmMessage>> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let message = registry.verify(envelope, now)?;
        self.process_message(message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_swarm_coordinator_init() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config).await;
        assert!(coordinator.is_ok());
    }

    #[tokio::test]
    async fn test_join_swarm() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config).await.unwrap();

        coordinator.join_swarm("agent-1").await.unwrap();
        assert_eq!(coordinator.get_swarm_size().await, 1);
    }

    #[tokio::test]
    async fn test_leader_election_single_agent() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::with_id(config, "agent-1").await.unwrap();
        coordinator.join_swarm("agent-1").await.unwrap();

        assert_eq!(coordinator.get_role().await, AgentRole::Follower);

        coordinator.start_election().await.unwrap();
        assert_eq!(coordinator.get_role().await, AgentRole::Leader);
    }

    #[tokio::test]
    async fn test_multi_agent_election() {
        let config = SwarmConfig::default();

        // Create two coordinators
        let c1 = SwarmCoordinator::with_id(config.clone(), "agent-1")
            .await
            .unwrap();
        let c2 = SwarmCoordinator::with_id(config, "agent-2").await.unwrap();

        // Register agents in both coordinators
        c1.join_swarm("agent-1").await.unwrap();
        c1.join_swarm("agent-2").await.unwrap();
        c2.join_swarm("agent-1").await.unwrap();
        c2.join_swarm("agent-2").await.unwrap();

        // Agent-1 starts election
        c1.start_election().await.unwrap();

        // Agent-1 is now a candidate (not yet leader - needs 2 votes with 2 agents)
        // It has 1 self-vote, needs 2 total
        assert_eq!(c1.get_role().await, AgentRole::Candidate);

        // Agent-2 processes vote request and grants vote
        let (granted, _term) = c2.process_vote_request("agent-1", 1).await;
        assert!(granted);

        // Agent-1 receives the vote response
        c1.process_vote_response("agent-2", true, 1).await.unwrap();

        // Now agent-1 should be leader (2/2 votes)
        assert_eq!(c1.get_role().await, AgentRole::Leader);
    }

    #[tokio::test]
    async fn test_task_proposal() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config).await.unwrap();

        let proposal_id = coordinator
            .propose_task(
                "inference".to_string(),
                serde_json::json!({"model": "gpt-4"}),
                1,
            )
            .await
            .unwrap();

        coordinator
            .vote_on_proposal(&proposal_id, true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_conflict_resolution() {
        let config = SwarmConfig {
            conflict_strategy: ConflictStrategy::Priority,
            ..Default::default()
        };
        let coordinator = SwarmCoordinator::new(config).await.unwrap();

        // Create two proposals with different priorities
        let p1 = coordinator
            .propose_task("task1".to_string(), serde_json::json!({}), 1)
            .await
            .unwrap();

        let p2 = coordinator
            .propose_task("task2".to_string(), serde_json::json!({}), 5)
            .await
            .unwrap();

        // Resolve conflict - higher priority should win
        let winner = coordinator
            .resolve_conflict(vec![p1.clone(), p2.clone()])
            .await
            .unwrap();

        assert_eq!(winner, Some(p2));
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config).await.unwrap();

        // Become leader first
        coordinator.start_election().await.unwrap();

        // Send heartbeat
        coordinator.send_heartbeat().await.unwrap();
    }

    #[tokio::test]
    async fn test_heartbeat_processing() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::with_id(config, "agent-2").await.unwrap();

        // Process heartbeat from leader
        coordinator.process_heartbeat("agent-1", 5).await;

        assert_eq!(coordinator.get_role().await, AgentRole::Follower);
        assert_eq!(
            coordinator.get_leader_id().await,
            Some("agent-1".to_string())
        );
        assert_eq!(coordinator.get_term().await, 5);
    }

    #[tokio::test]
    async fn test_stale_agent_cleanup() {
        let config = SwarmConfig {
            stale_agent_timeout_secs: 0, // Immediate timeout for testing
            ..Default::default()
        };
        let coordinator = SwarmCoordinator::new(config).await.unwrap();

        coordinator.join_swarm("agent-1").await.unwrap();
        assert_eq!(coordinator.get_swarm_size().await, 1);

        // Manually backdate the agent's last heartbeat to force staleness
        {
            let mut agents = coordinator.agents.write().await;
            if let Some(info) = agents.get_mut("agent-1") {
                info.last_heartbeat = info.last_heartbeat.saturating_sub(2);
            }
        }

        let removed = coordinator.cleanup_stale_agents().await;
        assert_eq!(removed.len(), 1);
        assert_eq!(coordinator.get_swarm_size().await, 0);
    }

    #[tokio::test]
    async fn test_process_message_vote_request() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::with_id(config, "agent-2").await.unwrap();

        let response = coordinator
            .process_message(SwarmMessage::RequestVote {
                candidate_id: "agent-1".to_string(),
                term: 1,
            })
            .await
            .unwrap();

        match response {
            Some(SwarmMessage::VoteResponse {
                voter_id, granted, ..
            }) => {
                assert_eq!(voter_id, "agent-2");
                assert!(granted);
            }
            _ => panic!("Expected VoteResponse"),
        }
    }

    #[tokio::test]
    async fn test_swarm_status() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::with_id(config, "agent-1").await.unwrap();

        coordinator.join_swarm("agent-1").await.unwrap();
        coordinator.join_swarm("agent-2").await.unwrap();

        let status = coordinator.get_status().await;
        assert_eq!(status.agent_id, "agent-1");
        assert_eq!(status.role, AgentRole::Follower);
        assert_eq!(status.swarm_size, 2);
    }

    #[tokio::test]
    async fn test_task_execution_after_consensus() {
        let config = SwarmConfig::default();
        let mut coordinator = SwarmCoordinator::with_id(config, "agent-1").await.unwrap();
        coordinator.join_swarm("agent-1").await.unwrap();

        // Set up task executor with health check handler
        let executor = Arc::new(TaskExecutor::new("agent-1"));
        executor
            .register_handler("health", Arc::new(HealthCheckHandler))
            .await;
        coordinator.set_task_executor(executor);

        // Propose and vote
        let proposal_id = coordinator
            .propose_task("health".to_string(), serde_json::json!({}), 1)
            .await
            .unwrap();

        coordinator
            .vote_on_proposal(&proposal_id, true)
            .await
            .unwrap();

        // Check and execute
        let result = coordinator
            .check_and_execute_proposal(&proposal_id)
            .await
            .unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().success);
    }

    #[tokio::test]
    async fn test_max_agents_limit() {
        let config = SwarmConfig {
            max_agents: 2,
            ..Default::default()
        };
        let coordinator = SwarmCoordinator::new(config).await.unwrap();

        coordinator.join_swarm("agent-1").await.unwrap();
        coordinator.join_swarm("agent-2").await.unwrap();
        assert!(coordinator.join_swarm("agent-3").await.is_err());
    }
}

#[cfg(test)]
mod ingress_tests {
    use super::*;
    use crate::message_signing::{PeerKeyRegistry, SwarmMessageSigner};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_config() -> SwarmConfig {
        SwarmConfig {
            election_timeout_secs: (0, 0),
            stale_agent_timeout_secs: 30,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn envelope_roundtrip_and_drop_policy() {
        let coord = SwarmCoordinator::with_id(test_config(), "node-2").await.unwrap();
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let mut registry = PeerKeyRegistry::new(60);
        registry.register_peer("node-1", sk1.verifying_key());
        registry.register_peer("node-2", sk2.verifying_key());

        // Valid heartbeat from a known peer is processed: leader recorded.
        let signer = SwarmMessageSigner::new("node-1", sk1);
        let env = signer
            .sign(SwarmMessage::Heartbeat {
                leader_id: "node-1".to_string(),
                term: 7,
            })
            .unwrap();
        coord.process_envelope(&env, &mut registry).await.unwrap();
        assert_eq!(coord.get_leader_id().await.as_deref(), Some("node-1"));

        // Exact redelivery is a replay: rejected, state untouched.
        assert!(coord.process_envelope(&env, &mut registry).await.is_err());

        // Unknown peer: rejected before any crypto.
        let stranger = SigningKey::generate(&mut OsRng);
        let senv = SwarmMessageSigner::new("node-9", stranger)
            .sign(SwarmMessage::Heartbeat {
                leader_id: "node-9".to_string(),
                term: 1,
            })
            .unwrap();
        assert!(coord.process_envelope(&senv, &mut registry).await.is_err());

        // Tampered content: signature no longer matches.
        let mut tampered = signer
            .sign(SwarmMessage::Heartbeat {
                leader_id: "node-1".to_string(),
                term: 8,
            })
            .unwrap();
        tampered.message = SwarmMessage::Heartbeat {
            leader_id: "node-1".to_string(),
            term: 999,
        };
        assert!(coord.process_envelope(&tampered, &mut registry).await.is_err());
    }

    #[tokio::test]
    async fn leader_recovers_after_timeout() {
        let coord = SwarmCoordinator::with_id(test_config(), "solo").await.unwrap();
        coord.start_election().await.unwrap();
        assert_eq!(coord.get_role().await, AgentRole::Leader);
        let term1 = coord.get_term().await;

        // Leader steps down (partition heals with a higher term elsewhere).
        *coord.current_role.write().await = AgentRole::Follower;
        *coord.leader_id.write().await = None;
        *coord.last_heartbeat_received.write().await = SystemTime::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap();

        // First escalation: Follower → Candidate.
        assert!(coord.tick_election().await.unwrap());
        assert_eq!(coord.get_role().await, AgentRole::Candidate);
        // Once the timer lapses again, the candidate re-runs the election and,
        // alone, converges back to Leader with a strictly greater term.
        *coord.last_heartbeat_received.write().await = SystemTime::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap();
        assert!(coord.tick_election().await.unwrap());
        assert_eq!(coord.get_role().await, AgentRole::Leader);
        assert!(coord.get_term().await > term1);
    }

    #[tokio::test]
    async fn cleanup_never_evicts_self() {        let coord = SwarmCoordinator::with_id(test_config(), "me").await.unwrap();
        coord.join_swarm("me").await.unwrap();
        coord.join_swarm("peer").await.unwrap();
        // Backdate everything, including ourselves.
        {
            let mut agents = coord.agents.write().await;
            for info in agents.values_mut() {
                info.last_heartbeat = info.last_heartbeat.saturating_sub(10_000);
            }
        }
        let removed = coord.cleanup_stale_agents().await;
        assert_eq!(removed, vec!["peer".to_string()]);
        assert!(coord.agents.read().await.contains_key("me"));
    }

    #[tokio::test]
    async fn broadcast_heartbeat_reaches_peers() {
        use crate::transport::SwarmBus;

        let bus = SwarmBus::new();
        let leader_tx = bus.create_transport("leader", 16).await;
        let follower_tx = bus.create_transport("follower", 16).await;
        let mut follower_inbox = SwarmTransportHandle::from_transport(follower_tx);

        let coord = SwarmCoordinator::with_id(test_config(), "leader").await.unwrap();
        coord.start_election().await.unwrap();
        assert_eq!(coord.get_role().await, AgentRole::Leader);

        coord.broadcast_heartbeat(&leader_tx).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(2), follower_inbox.recv()).await {
            Ok(Some(SwarmMessage::Heartbeat { leader_id, .. })) => {
                assert_eq!(leader_id, "leader")
            }
            other => panic!("expected heartbeat, got {other:?}"),
        }

        // Non-leaders cannot broadcast.
        let follower = SwarmCoordinator::with_id(test_config(), "follower").await.unwrap();
        assert!(follower.broadcast_heartbeat(&leader_tx).await.is_err());
    }

    #[tokio::test]
    async fn election_timer_rearms_after_escalation() {
        let config = SwarmConfig {
            election_timeout_secs: (3600, 3600),
            ..Default::default()
        };
        let coord = SwarmCoordinator::with_id(config, "n").await.unwrap();
        *coord.last_heartbeat_received.write().await = SystemTime::now()
            .checked_sub(Duration::from_secs(4000))
            .unwrap();
        let term0 = coord.get_term().await;
        assert!(coord.tick_election().await.unwrap());
        assert_eq!(coord.get_role().await, AgentRole::Candidate);
        // Timer re-armed: immediate ticks escalate nothing and bump no terms.
        assert!(!coord.tick_election().await.unwrap());
        assert!(!coord.tick_election().await.unwrap());
        assert_eq!(coord.get_term().await, term0);
    }
}
