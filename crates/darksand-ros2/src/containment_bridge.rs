//! Deterministic containment → ROS2 actuator safety bridge.
//!
//! [`ContainmentBridge`] subscribes to [`ViolationEventBus`] and, on every
//! containment violation, executes a **hard deterministic halt sequence**:
//!
//! 1. Capture current robotics state (active goal ID, pose, velocity).
//! 2. Cancel the active Nav2 goal within a 20 ms deadline.
//! 3. Spawn a high-priority zero-velocity loop (publishes every 100 ms for 3 s).
//! 4. Assert the BT safe-idle signal (planning / tools / LLM disabled).
//! 5. Write a supplementary signed [`ViolationRecord`] with full robotics context,
//!    chained from the original supervisor record.
//!
//! # Timing budget
//!
//! Steps 1–4 complete synchronously in the bridge task. Step 3 spawns a
//! detached tokio task and returns immediately. The entire critical path
//! (steps 1–4) targets **≤ 50 ms** on Jetson-class hardware.
//!
//! Step 5 (I/O) runs in the same task after the actuator path is safe.
//!
//! # Safety guarantees
//!
//! - The halt sequence executes even if the Behavior Tree state is corrupted.
//! - Zero-velocity publishing continues even if Nav2 cancel fails.
//! - The signed violation log is always written, independently of actuator results.
//! - No LLM calls occur anywhere in this module.
//! - No non-deterministic recovery logic is present.

use crate::Ros2Node;
use ed25519_dalek::SigningKey;
use darksand_safety::{ContainmentEvent, RoboticsContext, ViolationEventBus, ViolationRecord};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{broadcast, watch, RwLock};
use tracing::{debug, error, info, warn};

/// Receiver half of the BT safe-idle signal.
///
/// Yields `true` once a violation has been handled. Poll with [`is_safe_idle`]
/// in the BT executor loop and HTTP handlers to gate new work:
///
/// ```rust,ignore
/// # use darksand_ros2::containment_bridge::{SafeIdleReceiver, is_safe_idle};
/// # let idle_rx: SafeIdleReceiver = unimplemented!();
/// if is_safe_idle(&idle_rx) {
///     return Err(anyhow::anyhow!("System in safe-idle — no new work accepted"));
/// }
/// ```
pub type SafeIdleReceiver = watch::Receiver<bool>;

/// Returns `true` if the system is currently in the BT safe-idle state.
pub fn is_safe_idle(rx: &SafeIdleReceiver) -> bool {
    *rx.borrow()
}

/// Outcome of one deterministic halt sequence.
///
/// `zero_vel_ok` / `zero_vel_errors` count `/cmd_vel` publishes for the most
/// recent halt only. Use [`ContainmentBridge::zero_vel_stats`] for lifetime
/// totals across all halts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaltOutcome {
    /// Nav2 cancel confirmed (or no active goal).
    pub cancel_ok: bool,
    /// Number of zero-velocity publishes attempted for this halt (30).
    pub zero_vel_attempted: u32,
    /// Zero-velocity publishes that returned `Ok` for this halt.
    pub zero_vel_ok: u32,
    /// Zero-velocity publishes that returned `Err` for this halt.
    pub zero_vel_errors: u32,
    /// Safe-idle flag was asserted (always `true`; the watch value is set
    /// even when no receivers are registered).
    pub idle_asserted: bool,
    /// Critical path (steps 1–4) exceeded the 50 ms budget.
    pub budget_exceeded: bool,
    /// Supplementary robotics violation record was persisted.
    pub log_ok: bool,
}

/// Halt critical-path latency histogram (steps 1–4, milliseconds).
///
/// Bounded ring (1024 samples): steady-state memory on long-lived robots.
/// Percentiles are computed over a sorted copy; empty input yields 0s so
/// dashboards never see `NaN`.
#[derive(Debug, Clone, Default)]
pub struct HaltMetrics {
    samples_ms: Vec<u64>,
}

impl HaltMetrics {
    const CAP: usize = 1024;

    /// Record one halt critical-path sample.
    pub fn record(&mut self, elapsed_ms: u64) {
        if self.samples_ms.len() >= Self::CAP {
            self.samples_ms.remove(0);
        }
        self.samples_ms.push(elapsed_ms);
    }

    /// `(count, p50_ms, p99_ms, max_ms)`.
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        if self.samples_ms.is_empty() {
            return (0, 0, 0, 0);
        }
        let mut sorted = self.samples_ms.clone();
        sorted.sort_unstable();
        let n = sorted.len();
        let pct = |p: f64| sorted[((p * n as f64).ceil() as usize).saturating_sub(1).min(n - 1)];
        (n as u64, pct(0.50), pct(0.99), sorted[n - 1])
    }

    /// JSON snapshot for dashboards and audit bundles.
    pub fn to_json(&self) -> serde_json::Value {
        let (count, p50, p99, max) = self.stats();
        serde_json::json!({
            "halt_count": count,
            "critical_path_ms_p50": p50,
            "critical_path_ms_p99": p99,
            "critical_path_ms_max": max,
            "budget_ms": 50,
            "over_budget": self.samples_ms.iter().filter(|&&ms| ms > 50).count(),
        })
    }
}

/// Bridge between the containment supervisor and ROS2 actuator subsystems.
///
/// Created at startup via [`ContainmentBridge::new`]. Run as a long-lived
/// tokio task via [`ContainmentBridge::run`].
pub struct ContainmentBridge {
    receiver: broadcast::Receiver<ContainmentEvent>,
    node: Arc<Ros2Node>,
    signing_key: SigningKey,
    log_path: String,
    /// Hash of the last record written by this bridge (for chaining).
    last_hash: String,
    idle_tx: watch::Sender<bool>,
    /// Local subscription so the bridge itself can answer `is_halted()`
    /// without needing a caller-held receiver.
    idle_rx: watch::Receiver<bool>,
    /// Lifetime counters across all halts handled by this bridge.
    halts_handled: Arc<AtomicU32>,
    zero_vel_ok_total: Arc<AtomicU32>,
    zero_vel_err_total: Arc<AtomicU32>,
    /// Outcome of the most recent halt (critical-path fields set
    /// synchronously; zero-vel counts filled when the 3 s loop completes).
    last_outcome: Arc<RwLock<Option<HaltOutcome>>>,
    /// Critical-path latency samples across all halts (bounded ring).
    halt_metrics: Arc<tokio::sync::Mutex<HaltMetrics>>,
}

impl ContainmentBridge {
    /// Create a new containment bridge.
    ///
    /// # Parameters
    ///
    /// - `bus`: [`ViolationEventBus`] that the containment supervisor publishes to.
    /// - `node`: Shared [`Ros2Node`] for Nav2 cancel and `/cmd_vel` commands.
    /// - `signing_key`: Ed25519 key for the supplementary robotics violation record.
    ///   Use the same key as the supervisor for a unified audit trail.
    /// - `log_path`: JSONL violation log path (same file as the supervisor).
    /// - `initial_hash`: Hash of the most recent supervisor record for chaining.
    ///   Pass `""` on first startup.
    ///
    /// # Returns
    ///
    /// `(bridge, idle_rx)` — spawn `bridge.run()` in a dedicated tokio task and
    /// wire `idle_rx` into the BT executor and HTTP handlers. The BT executor
    /// already supports this via `BTreeExecutor::execute_with_cancel`: pass a
    /// `watch::Receiver<bool>` cloned from `idle_rx` so in-flight missions halt
    /// when safe-idle is asserted — polling `is_safe_idle()` alone is advisory.
    pub fn new(
        bus: &ViolationEventBus,
        node: Arc<Ros2Node>,
        signing_key: SigningKey,
        log_path: String,
        initial_hash: String,
    ) -> (Self, SafeIdleReceiver) {
        let receiver = bus.subscribe();
        let (idle_tx, idle_rx) = watch::channel(false);
        let bridge = Self {
            receiver,
            node,
            signing_key,
            log_path,
            last_hash: initial_hash,
            idle_tx,
            idle_rx: idle_rx.clone(),
            halts_handled: Arc::new(AtomicU32::new(0)),
            zero_vel_ok_total: Arc::new(AtomicU32::new(0)),
            zero_vel_err_total: Arc::new(AtomicU32::new(0)),
            last_outcome: Arc::new(RwLock::new(None)),
            halt_metrics: Arc::new(tokio::sync::Mutex::new(HaltMetrics::default())),
        };
        (bridge, idle_rx)
    }

    /// Returns `true` once this bridge has asserted safe-idle.
    pub fn is_halted(&self) -> bool {
        *self.idle_rx.borrow()
    }

    /// Refuse new work when halted. Call at the top of BT/HTTP handlers:
    /// `bridge.ensure_not_halted()?`.
    pub fn ensure_not_halted(&self) -> anyhow::Result<()> {
        if self.is_halted() {
            anyhow::bail!("System in safe-idle after containment violation — no new work accepted")
        } else {
            Ok(())
        }
    }

    /// Outcome of the most recent halt, if any.
    pub async fn last_halt_outcome(&self) -> Option<HaltOutcome> {
        *self.last_outcome.read().await
    }

    /// Lifetime `(halts_handled, zero_vel_ok, zero_vel_errors)` totals.
    pub fn zero_vel_stats(&self) -> (u32, u32, u32) {
        (
            self.halts_handled.load(Ordering::Relaxed),
            self.zero_vel_ok_total.load(Ordering::Relaxed),
            self.zero_vel_err_total.load(Ordering::Relaxed),
        )
    }

    /// `(halt_count, p50_ms, p99_ms, max_ms)` over the bounded latency ring.
    pub async fn halt_latency_stats(&self) -> (u64, u64, u64, u64) {
        self.halt_metrics.lock().await.stats()
    }

    /// JSON snapshot of halt latency vs the 50 ms budget (dashboards).
    pub async fn halt_metrics_json(&self) -> serde_json::Value {
        self.halt_metrics.lock().await.to_json()
    }

    /// Export a signed audit bundle: all log records plus chain verification.
    ///
    /// Writes `{exported_at_ms, record_count, chain_verified, records}` to
    /// `out_path` and returns `record_count`. Verification uses this bridge's
    /// signing key, so a bundle exported with a foreign key fails closed.
    /// Operators ship this file — not raw JSONL — to auditors.
    pub async fn export_receipt_bundle(&self, out_path: &str) -> anyhow::Result<usize> {
        use darksand_safety::verify_log_chain;

        let content = tokio::fs::read_to_string(&self.log_path).await?;
        let records: Vec<serde_json::Value> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<_, _>>()?;
        let verifying = self.signing_key.verifying_key();
        let verified = verify_log_chain(&self.log_path, &verifying).is_ok();
        let bundle = serde_json::json!({
            "exported_at_ms": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            "record_count": records.len(),
            "chain_verified": verified,
            "halt_metrics": self.halt_metrics_json().await,
            "records": records,
        });
        tokio::fs::write(out_path, serde_json::to_string_pretty(&bundle)?).await?;
        if !verified {
            anyhow::bail!("receipt bundle written but chain verification FAILED");
        }
        Ok(records.len())
    }

    /// Run the bridge event loop.
    ///
    /// Blocks until the [`ViolationEventBus`] is closed. Spawn in a dedicated
    /// tokio task at startup:
    ///
    /// ```rust,ignore
    /// # async fn example() {
    /// # let (bridge, _rx): (darksand_ros2::containment_bridge::ContainmentBridge, _) = unimplemented!();
    /// tokio::spawn(bridge.run());
    /// # }
    /// ```
    pub async fn run(mut self) {
        info!("ContainmentBridge started — monitoring violation event bus");
        loop {
            match self.receiver.recv().await {
                Ok(ContainmentEvent::Violation(record)) => {
                    info!(
                        violation_id = %record.id,
                        kind = ?record.violation_kind,
                        "ContainmentBridge received violation — executing deterministic halt"
                    );
                    self.handle_violation(&record).await;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("ViolationEventBus closed — ContainmentBridge shutting down");
                    break;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Missed ≥1 violation. Apply fail-safe immediately, then continue.
                    error!(
                        missed = n,
                        "ContainmentBridge lagged {} violation events — \
                         applying unconditional emergency halt",
                        n
                    );
                    self.apply_emergency_halt_unconditional().await;
                }
            }
        }
    }

    // ── Core halt sequence ───────────────────────────────────────────────────

    /// Execute the deterministic halt sequence for a known violation.
    ///
    /// Total critical-path budget (steps 1–4): ≤ 50 ms.
    async fn handle_violation(&mut self, record: &ViolationRecord) {
        let start = std::time::Instant::now();
        self.halts_handled.fetch_add(1, Ordering::Relaxed);

        // Step 1 — Capture robotics state BEFORE any action changes it.
        let (goal_id, pose, pre_halt_velocity) = self.capture_robotics_state().await;

        // Step 2 — Cancel active Nav2 goal (hard timeout: 20 ms).
        let cancel_ok = self.cancel_active_goal_timed(20).await;
        if !cancel_ok {
            warn!(
                "Nav2 goal cancel did not complete within 20 ms — \
                 continuing halt sequence (zero-vel loop will stop robot)"
            );
        }

        // Step 3 — Spawn zero-velocity loop (non-blocking, returns immediately).
        // Publishes zero Twist to /cmd_vel every 100 ms for 3 s (30 iterations).
        // Runs independently of Nav2 cancel result. Per-publish results are
        // counted (not just warned) so a dead `/cmd_vel` path is observable.
        const ZERO_VEL_ITERS: u32 = 30;
        {
            let node_clone = Arc::clone(&self.node);
            let ok_total = Arc::clone(&self.zero_vel_ok_total);
            let err_total = Arc::clone(&self.zero_vel_err_total);
            let outcome_slot = Arc::clone(&self.last_outcome);
            // Snapshot counters so this halt's counts are isolated from any
            // concurrent halt loop.
            let ok_base = ok_total.load(Ordering::Relaxed);
            let err_base = err_total.load(Ordering::Relaxed);
            tokio::spawn(async move {
                info!("Zero-velocity loop started (30 × 100 ms = 3 s)");
                for _ in 0..ZERO_VEL_ITERS {
                    if node_clone.publish_zero_velocity().await.is_ok() {
                        ok_total.fetch_add(1, Ordering::Relaxed);
                    } else {
                        err_total.fetch_add(1, Ordering::Relaxed);
                        warn!("Zero-velocity publish error (counted, continuing loop)");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                info!("Zero-velocity loop complete");
                // Fill in this halt's zero-vel counts on the stored outcome.
                let ok = ok_total.load(Ordering::Relaxed).saturating_sub(ok_base);
                let errs = err_total.load(Ordering::Relaxed).saturating_sub(err_base);
                let mut guard = outcome_slot.write().await;
                if let Some(o) = guard.as_mut() {
                    o.zero_vel_ok = ok;
                    o.zero_vel_errors = errs;
                }
            });
        }

        // Step 4 — Assert BT safe-idle. `send` updates the watch value even
        // when no receivers are registered (returns Err in that case), so the
        // halted state is always recorded locally; receivers observe it.
        let receivers = self.idle_tx.receiver_count();
        if self.idle_tx.send(true).is_err() {
            debug!(
                receivers,
                "Safe-idle asserted with no BT idle-signal consumers registered"
            );
        }

        let critical_path_ms = start.elapsed().as_millis();
        let budget_exceeded = critical_path_ms > 50;
        info!(
            elapsed_ms = critical_path_ms,
            cancel_ok, "Halt critical path complete in {} ms (budget: 50 ms)", critical_path_ms
        );
        if budget_exceeded {
            error!(
                "SAFETY BUDGET EXCEEDED: halt critical path took {} ms — \
                 investigate scheduling latency on this platform",
                critical_path_ms
            );
        }
        self.halt_metrics
            .lock()
            .await
            .record(u64::try_from(critical_path_ms).unwrap_or(u64::MAX));

        // Step 5 — Write supplementary signed robotics violation record.
        // Done AFTER actuators are safe (non-blocking I/O does not affect halt timing).
        let robotics_ctx = RoboticsContext::emergency_halt(goal_id, pose, pre_halt_velocity);
        let log_ok = self.append_robotics_violation(record, robotics_ctx).await;

        *self.last_outcome.write().await = Some(HaltOutcome {
            cancel_ok,
            zero_vel_attempted: ZERO_VEL_ITERS,
            // Filled by the background loop on completion; start at 0.
            zero_vel_ok: 0,
            zero_vel_errors: 0,
            idle_asserted: true,
            budget_exceeded,
            log_ok,
        });
    }

    /// Apply emergency halt with no associated violation record (lag recovery path).
    async fn apply_emergency_halt_unconditional(&mut self) {
        let start = std::time::Instant::now();
        warn!("Unconditional emergency halt triggered (lag recovery)");
        self.halts_handled.fetch_add(1, Ordering::Relaxed);
        let cancel_ok = self.cancel_active_goal_timed(20).await;
        let node_clone = Arc::clone(&self.node);
        let ok_total = Arc::clone(&self.zero_vel_ok_total);
        let err_total = Arc::clone(&self.zero_vel_err_total);
        let outcome_slot = Arc::clone(&self.last_outcome);
        let ok_base = ok_total.load(Ordering::Relaxed);
        let err_base = err_total.load(Ordering::Relaxed);
        tokio::spawn(async move {
            for _ in 0..30u32 {
                if node_clone.publish_zero_velocity().await.is_ok() {
                    ok_total.fetch_add(1, Ordering::Relaxed);
                } else {
                    err_total.fetch_add(1, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let ok = ok_total.load(Ordering::Relaxed).saturating_sub(ok_base);
            let errs = err_total.load(Ordering::Relaxed).saturating_sub(err_base);
            let mut guard = outcome_slot.write().await;
            if let Some(o) = guard.as_mut() {
                o.zero_vel_ok = ok;
                o.zero_vel_errors = errs;
            }
        });
        let _ = self.idle_tx.send(true);
        self.halt_metrics
            .lock()
            .await
            .record(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
        // No robotics record exists for the lag path (no original violation);
        // still publish an outcome so operators can see cancel/idle state.
        // log_ok=false distinguishes this from a fully recorded halt.
        *self.last_outcome.write().await = Some(HaltOutcome {
            cancel_ok,
            zero_vel_attempted: 30,
            zero_vel_ok: 0,
            zero_vel_errors: 0,
            idle_asserted: true,
            budget_exceeded: false,
            log_ok: false,
        });
    }

    // ── Nav2 cancel ─────────────────────────────────────────────────────────

    /// Cancel the active Nav2 goal within `max_ms` milliseconds.
    ///
    /// Returns `true` when the goal is confirmed cancelled (or there was no
    /// active goal). Returns `false` only on hard timeout — the zero-velocity
    /// loop in step 3 will stop the robot regardless.
    async fn cancel_active_goal_timed(&self, max_ms: u64) -> bool {
        let handle = match self.node.get_active_handle().await {
            Some(h) => h,
            None => {
                tracing::debug!("No active navigation goal to cancel — skipping");
                return true;
            }
        };

        match tokio::time::timeout(
            Duration::from_millis(max_ms),
            handle.cancel_with_timeout(max_ms),
        )
        .await
        {
            Ok(Ok(goal_id)) => {
                info!("Nav2 goal {} cancelled deterministically", goal_id);
                true
            }
            Ok(Err(e)) => {
                // Already in terminal state — robot is already stopped.
                tracing::debug!("Goal already terminal during cancel: {}", e);
                true
            }
            Err(_elapsed) => {
                error!(
                    "Nav2 cancel timed out after {} ms — \
                     zero-velocity loop will arrest motion",
                    max_ms
                );
                false
            }
        }
    }

    // ── Robotics state capture ───────────────────────────────────────────────

    /// Capture current robotics state for the violation record.
    ///
    /// Returns `(goal_id, pose_xyz, velocity_linear_angular)`.
    /// Fields are `None` when unavailable (e.g., no active goal, robot at rest).
    async fn capture_robotics_state(&self) -> (Option<String>, Option<[f64; 3]>, Option<[f64; 2]>) {
        // Velocity BEFORE zero-command (odometry / last known state).
        let velocity = {
            let v = self.node.last_velocity().await;
            if v[0].abs() > 1e-9 || v[1].abs() > 1e-9 {
                Some(v)
            } else {
                None
            }
        };

        // Goal ID and pose from the active navigation handle.
        match self.node.get_active_handle().await {
            Some(handle) => {
                let gid = handle.goal_id().await;
                let fb = handle.feedback().await;
                let (x, y, z) = fb.current_pose;
                // In stub: z is unused; in production this comes from /amcl_pose yaw.
                (Some(gid), Some([x, y, z]), velocity)
            }
            None => (None, None, velocity),
        }
    }

    // ── Signed robotics violation record ─────────────────────────────────────

    /// Write a supplementary violation record that includes robotics context.
    ///
    /// Chains from `original` (previous_hash = original.hash), so the full
    /// audit trail is: [supervisor record] → [robotics context record].
    /// Returns `true` when the record was persisted.
    async fn append_robotics_violation(
        &mut self,
        original: &ViolationRecord,
        robotics: RoboticsContext,
    ) -> bool {
        let context = serde_json::json!({
            "source": "containment_bridge",
            "phase": "robotics_halt",
            "original_violation_id": original.id.to_string(),
        });

        let record = ViolationRecord::new_with_robotics(
            original.violation_kind,
            context,
            original.hash.clone(), // chain from the supervisor's record
            &self.signing_key,
            robotics,
        );

        let ok = match record.append_to_log(&self.log_path) {
            Ok(()) => {
                info!(
                    record_id = %record.id,
                    hash = %record.hash,
                    "Robotics violation record written (hash chain intact)"
                );
                true
            }
            Err(e) => {
                error!(
                    "Failed to write robotics violation record to {}: {}",
                    self.log_path, e
                );
                false
            }
        };

        // Advance our chain pointer only on success, so a later record never
        // chains from an unpersisted hash.
        if ok {
            self.last_hash = record.hash.clone();
        }
        ok
    }
}

// ============================================================================
// Integration tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NavigationGoal, NavigationState, Ros2Config};
    use ed25519_dalek::SigningKey;
    use darksand_safety::{ViolationEventBus, ViolationKind, ViolationRecord};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_log() -> String {
        std::env::temp_dir()
            .join(format!("darksand_bridge_test_{}.jsonl", uuid::Uuid::now_v7()))
            .to_string_lossy()
            .into_owned()
    }

    async fn make_node() -> Arc<Ros2Node> {
        Arc::new(
            Ros2Node::new(Ros2Config {
                enabled: true,
                enable_nav2: true,
                ..Default::default()
            })
            .await
            .unwrap(),
        )
    }

    fn make_violation(previous_hash: &str) -> ViolationRecord {
        ViolationRecord::new(
            ViolationKind::Time,
            serde_json::json!({"tick_ms": 500, "budget_ms": 100}),
            previous_hash.to_string(),
            &test_key(),
        )
    }

    /// Spin up a bridge with a fresh bus, give it time to subscribe.
    async fn setup_bridge(
        bus: &ViolationEventBus,
        node: Arc<Ros2Node>,
        log: &str,
    ) -> SafeIdleReceiver {
        let (bridge, rx) =
            ContainmentBridge::new(bus, node, test_key(), log.to_string(), String::new());
        tokio::spawn(bridge.run());
        // Small delay so the bridge task starts polling recv().
        tokio::time::sleep(Duration::from_millis(15)).await;
        rx
    }

    // ── Step 2: Nav2 cancel ──────────────────────────────────────────────────

    /// Active Nav2 goal is cancelled deterministically on violation.
    #[tokio::test]
    async fn violation_cancels_active_nav2_goal() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let _idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;

        // Issue goal and wait until robot is Executing.
        let handle = node
            .navigate_to_pose(NavigationGoal {
                x: 10.0,
                y: 10.0,
                z: 0.0,
                orientation_w: 1.0,
                frame_id: "map".to_string(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !handle.status().await.is_terminal(),
            "goal must be active before test"
        );

        // Fire violation.
        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(60)).await;

        assert_eq!(
            handle.status().await,
            NavigationState::Canceled,
            "goal must be Canceled"
        );
        let _ = std::fs::remove_file(&log);
    }

    /// Cancel is safe when no goal is active.
    #[tokio::test]
    async fn violation_safe_with_no_active_goal() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;

        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(60)).await;

        assert!(
            is_safe_idle(&idle_rx),
            "idle must be asserted even with no active goal"
        );
        let _ = std::fs::remove_file(&log);
    }

    /// Goal cancel also works if the goal is already terminal (idempotent).
    #[tokio::test]
    async fn violation_cancel_idempotent_on_terminal_goal() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;

        let handle = node
            .navigate_to_pose(NavigationGoal {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                orientation_w: 1.0,
                frame_id: "map".to_string(),
            })
            .await
            .unwrap();
        // Wait for natural completion.
        handle.wait().await.unwrap();
        assert_eq!(handle.status().await, NavigationState::Succeeded);

        // Violation after goal already succeeded — must not panic.
        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(is_safe_idle(&idle_rx));
        let _ = std::fs::remove_file(&log);
    }

    // ── Step 3: Zero-velocity loop ───────────────────────────────────────────

    /// After a violation, ≥3 zero-velocity commands are published within 350 ms.
    #[tokio::test]
    async fn violation_publishes_zero_velocity_commands() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        setup_bridge(&bus, Arc::clone(&node), &log).await;

        assert_eq!(node.cmd_vel_command_count().await, 0);
        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(350)).await;

        let count = node.cmd_vel_command_count().await;
        assert!(count >= 3, "expected ≥3 zero-vel commands, got {}", count);
        let _ = std::fs::remove_file(&log);
    }

    /// Zero-velocity loop runs even when Nav2 cancel is skipped (no active goal).
    #[tokio::test]
    async fn zero_velocity_independent_of_nav2_cancel() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        setup_bridge(&bus, Arc::clone(&node), &log).await;

        // No nav goal issued.
        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(
            node.cmd_vel_command_count().await >= 2,
            "zero-vel loop must run independently"
        );
        let _ = std::fs::remove_file(&log);
    }

    // ── Step 4: BT safe-idle signal ──────────────────────────────────────────

    /// The safe-idle watch channel becomes true within 50 ms of a violation.
    #[tokio::test]
    async fn violation_asserts_bt_idle_signal() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;

        assert!(!is_safe_idle(&idle_rx), "idle must start false");
        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(is_safe_idle(&idle_rx), "idle must be true after violation");
        let _ = std::fs::remove_file(&log);
    }

    /// A cloned SafeIdleReceiver also sees the true value.
    #[tokio::test]
    async fn idle_signal_observable_from_clone() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;
        let idle_rx2 = idle_rx.clone();

        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(is_safe_idle(&idle_rx));
        assert!(is_safe_idle(&idle_rx2));
        let _ = std::fs::remove_file(&log);
    }

    // ── Step 5: Signed robotics violation record ─────────────────────────────

    /// A supplementary robotics violation record is written after a violation.
    #[tokio::test]
    async fn violation_writes_signed_robotics_record() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let _ = std::fs::remove_file(&log);
        setup_bridge(&bus, Arc::clone(&node), &log).await;

        // Navigate so bridge can capture goal_id and pose.
        let _handle = node
            .navigate_to_pose(NavigationGoal {
                x: 3.0,
                y: 4.0,
                z: 0.0,
                orientation_w: 1.0,
                frame_id: "map".to_string(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(120)).await;

        let content = std::fs::read_to_string(&log).expect("log must be written");
        let records: Vec<ViolationRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("valid JSONL"))
            .collect();

        let robotics_rec = records
            .iter()
            .find(|r| r.robotics.is_some())
            .expect("a robotics context record must be present");

        assert!(!robotics_rec.hash.is_empty(), "hash must be non-empty");
        assert!(
            !robotics_rec.signature.is_empty(),
            "signature must be non-empty"
        );
        assert_eq!(
            robotics_rec.robotics.as_ref().unwrap().fallback_action,
            "emergency_halt"
        );

        let _ = std::fs::remove_file(&log);
    }

    /// The robotics record's previous_hash equals the original violation's hash.
    #[tokio::test]
    async fn hash_chain_links_robotics_to_supervisor_record() {
        let key = test_key();
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let _ = std::fs::remove_file(&log);

        let (bridge, _idle_rx) = ContainmentBridge::new(
            &bus,
            Arc::clone(&node),
            key.clone(),
            log.clone(),
            String::new(),
        );
        tokio::spawn(bridge.run());
        tokio::time::sleep(Duration::from_millis(15)).await;

        // Write the supervisor's record to the same log manually.
        let supervisor_record = ViolationRecord::new(
            ViolationKind::Time,
            serde_json::json!({"tick_ms": 200}),
            String::new(),
            &key,
        );
        supervisor_record.append_to_log(&log).unwrap();
        let supervisor_hash = supervisor_record.hash.clone();

        // Emit the same record on the bus so the bridge processes it.
        bus.emit_violation(supervisor_record);
        tokio::time::sleep(Duration::from_millis(120)).await;

        let content = std::fs::read_to_string(&log).unwrap();
        let records: Vec<ViolationRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        let robotics_rec = records
            .iter()
            .find(|r| r.robotics.is_some())
            .expect("robotics record must exist");

        assert_eq!(
            robotics_rec.previous_hash, supervisor_hash,
            "robotics record must chain from supervisor record"
        );

        let _ = std::fs::remove_file(&log);
    }

    /// Robotics record includes nav2_goal_id and current_pose when a goal was active.
    #[tokio::test]
    async fn robotics_record_includes_nav2_context_when_navigating() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let _ = std::fs::remove_file(&log);
        setup_bridge(&bus, Arc::clone(&node), &log).await;

        let handle = node
            .navigate_to_pose(NavigationGoal {
                x: 5.0,
                y: 0.0,
                z: 0.0,
                orientation_w: 1.0,
                frame_id: "map".to_string(),
            })
            .await
            .unwrap();
        let expected_goal_id = handle.goal_id().await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(120)).await;

        let content = std::fs::read_to_string(&log).unwrap();
        let records: Vec<ViolationRecord> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        let robotics_rec = records.iter().find(|r| r.robotics.is_some()).unwrap();
        let ctx = robotics_rec.robotics.as_ref().unwrap();
        assert_eq!(
            ctx.nav2_goal_id.as_deref(),
            Some(expected_goal_id.as_str()),
            "nav2_goal_id must match the active goal"
        );
        assert!(ctx.current_pose.is_some(), "current_pose must be captured");

        let _ = std::fs::remove_file(&log);
    }

    // ── Timing budget ────────────────────────────────────────────────────────

    /// Steps 1–4 complete within the 50 ms budget (idle signal asserted ≤ 50 ms).
    #[tokio::test]
    async fn halt_critical_path_within_50ms_budget() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();

        let _handle = node
            .navigate_to_pose(NavigationGoal {
                x: 50.0,
                y: 50.0,
                z: 0.0,
                orientation_w: 1.0,
                frame_id: "map".to_string(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;

        let t0 = std::time::Instant::now();
        bus.emit_violation(make_violation(""));

        // Poll for idle assertion in tight loop (budget: 50 ms from emit).
        let mut observed = false;
        let poll_end = std::time::Instant::now() + Duration::from_millis(80);
        while std::time::Instant::now() < poll_end {
            if is_safe_idle(&idle_rx) {
                observed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let elapsed_ms = t0.elapsed().as_millis();

        assert!(observed, "idle signal must be asserted within poll window");
        assert!(
            elapsed_ms <= 50,
            "critical path took {} ms — exceeds 50 ms budget",
            elapsed_ms
        );

        let _ = std::fs::remove_file(&log);
    }

    // ── Concurrent scenario ──────────────────────────────────────────────────

    /// Two violations fired concurrently: both handled, no panic, no deadlock.
    #[tokio::test]
    async fn concurrent_violations_no_race_condition() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let idle_rx = setup_bridge(&bus, Arc::clone(&node), &log).await;

        node.navigate_to_pose(NavigationGoal {
            x: 20.0,
            y: 20.0,
            z: 0.0,
            orientation_w: 1.0,
            frame_id: "map".to_string(),
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Fire two violations in rapid succession.
        bus.emit_violation(make_violation(""));
        bus.emit_violation(make_violation(""));

        tokio::time::sleep(Duration::from_millis(250)).await;

        // Node alive, idle asserted, zero-vel commands present.
        assert!(
            node.is_active().await,
            "node must remain active (idle, not crashed)"
        );
        assert!(is_safe_idle(&idle_rx), "safe-idle must be asserted");
        assert!(
            node.cmd_vel_command_count().await >= 2,
            "zero-vel commands must have been published"
        );

        let _ = std::fs::remove_file(&log);
    }

    // ── Halt outcome + gate enforcement ───────────────────────────────────

    /// Fresh bridge is not halted; `ensure_not_halted` passes, then fails
    /// once safe-idle is asserted. Exercises the enforcement helper BT/HTTP
    /// handlers must call (polling `is_safe_idle` alone is advisory).
    #[tokio::test]
    async fn halt_gate_blocks_new_work_once_halted() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let (bridge, _rx) = ContainmentBridge::new(
            &bus,
            Arc::clone(&node),
            test_key(),
            log.clone(),
            String::new(),
        );
        assert!(!bridge.is_halted());
        assert!(bridge.ensure_not_halted().is_ok());
        // Same-module access: assert the gate directly.
        bridge.idle_tx.send(true).unwrap();
        assert!(bridge.is_halted());
        assert!(bridge.ensure_not_halted().is_err());
        let _ = std::fs::remove_file(&log);
    }

    /// A handled violation records a critical-path outcome and accumulates
    /// zero-vel counts (stub publishes `Ok`, so errors stay 0).
    #[tokio::test]
    async fn halt_outcome_recorded_with_zero_vel_counts() {        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let _ = std::fs::remove_file(&log);

        let (bridge, idle_rx) = ContainmentBridge::new(
            &bus,
            Arc::clone(&node),
            test_key(),
            log.clone(),
            String::new(),
        );
        // Clone shared state before `run()` consumes the bridge.
        let outcome_slot = Arc::clone(&bridge.last_outcome);
        let halts = Arc::clone(&bridge.halts_handled);
        let ok_total = Arc::clone(&bridge.zero_vel_ok_total);
        let err_total = Arc::clone(&bridge.zero_vel_err_total);
        tokio::spawn(bridge.run());
        tokio::time::sleep(Duration::from_millis(15)).await;

        bus.emit_violation(make_violation(""));
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(is_safe_idle(&idle_rx), "idle must be asserted");
        assert_eq!(halts.load(Ordering::Relaxed), 1);
        {
            let outcome = outcome_slot.read().await;
            let o = outcome.as_ref().expect("outcome must be recorded");
            assert!(o.cancel_ok, "no active goal → cancel trivially ok");
            assert_eq!(o.zero_vel_attempted, 30);
            assert!(o.idle_asserted);
            assert!(o.log_ok, "robotics record must persist");
        }
        // Zero-vel loop runs in background: ≥2 publishes within 350 ms total.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            ok_total.load(Ordering::Relaxed) >= 2,
            "zero-vel successes must accumulate"
        );
        assert_eq!(err_total.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_file(&log);
    }

    /// When `/cmd_vel` publishes fail, the bridge counts errors instead of
    /// hiding them behind a warn: nothing is logged as sent, error counters
    /// rise, and the outcome records the failure split once the loop ends.
    #[tokio::test]
    async fn zero_vel_errors_counted_when_cmd_vel_fails() {
        let node = make_node().await;
        // Fail every publish of the 3 s loop (30 iterations).
        node.fail_next_zero_vel_publishes(30);
        let bus = ViolationEventBus::new();
        let log = test_log();
        let _ = std::fs::remove_file(&log);

        let (bridge, _idle_rx) = ContainmentBridge::new(
            &bus,
            Arc::clone(&node),
            test_key(),
            log.clone(),
            String::new(),
        );
        let outcome_slot = Arc::clone(&bridge.last_outcome);
        let err_total = Arc::clone(&bridge.zero_vel_err_total);
        let ok_total = Arc::clone(&bridge.zero_vel_ok_total);
        tokio::spawn(bridge.run());
        tokio::time::sleep(Duration::from_millis(15)).await;

        bus.emit_violation(make_violation(""));
        // A few loop iterations (100 ms each) must already show errors.
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(
            node.cmd_vel_command_count().await,
            0,
            "failed publishes must not be logged as sent"
        );
        assert!(
            err_total.load(Ordering::Relaxed) >= 2,
            "zero-vel errors must accumulate"
        );
        assert_eq!(ok_total.load(Ordering::Relaxed), 0);

        // Full loop (30 × 100 ms) fills the outcome split.
        tokio::time::sleep(Duration::from_millis(2900)).await;
        {
            let outcome = outcome_slot.read().await;
            let o = outcome.as_ref().expect("outcome must be recorded");
            assert_eq!(o.zero_vel_attempted, 30);
            assert_eq!(o.zero_vel_ok, 0);
            assert_eq!(o.zero_vel_errors, 30);
        }

        let _ = std::fs::remove_file(&log);
    }

    // ── Halt metrics + receipt export ────────────────────────────────────

    #[test]
    fn halt_metrics_empty_is_zero() {
        let m = HaltMetrics::default();
        assert_eq!(m.stats(), (0, 0, 0, 0));
        assert_eq!(m.to_json()["halt_count"], 0);
    }

    #[test]
    fn halt_metrics_percentiles_and_budget_count() {
        let mut m = HaltMetrics::default();
        for ms in 1u64..=100 {
            m.record(ms);
        }
        let (count, p50, p99, max) = m.stats();
        assert_eq!((count, p50, p99, max), (100, 50, 99, 100));
        let j = m.to_json();
        assert_eq!(j["over_budget"], 50);
        assert_eq!(j["budget_ms"], 50);
    }

    /// Each handled halt appends one latency sample; the receipt bundle
    /// verifies the chain and ships metrics + records to auditors.
    /// Calls `handle_violation` directly (no bus timing involved).
    #[tokio::test]
    async fn halt_latency_and_receipt_bundle_export() {
        let node = make_node().await;
        let bus = ViolationEventBus::new();
        let log = test_log();
        let out = format!("{log}.bundle.json");
        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(&out);

        let (mut bridge, _idle_rx) = ContainmentBridge::new(
            &bus,
            Arc::clone(&node),
            test_key(),
            log.clone(),
            String::new(),
        );
        assert_eq!(bridge.halt_latency_stats().await, (0, 0, 0, 0));

        // Supervisor record first so the bridge's robotics record chains.
        let sup = make_violation("");
        sup.append_to_log(&log).unwrap();
        bridge.handle_violation(&sup).await;

        let (count, _, _, _) = bridge.halt_latency_stats().await;
        assert_eq!(count, 1);
        let metrics_json = bridge.halt_metrics_json().await;
        assert_eq!(metrics_json["halt_count"], 1);

        let exported = bridge.export_receipt_bundle(&out).await.unwrap();
        assert_eq!(exported, 2, "supervisor + robotics records");
        let bundle: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(bundle["chain_verified"], true);
        assert_eq!(bundle["record_count"], 2);
        assert_eq!(bundle["halt_metrics"]["halt_count"], 1);

        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(&out);
    }
}
