use crate::{
    bounds::Bounds,
    event_bus::ViolationEventBus,
    violation::{ViolationKind, ViolationRecord},
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::{timeout, Duration},
};
use tracing::{error, warn};

struct WorkerHandle {
    child: Child,
    pid: u32,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

struct SupervisorConfig {
    bounds: Bounds,
    signing_key: SigningKey,
    log_path: String,
    last_hash: String,
    worker_bin: Option<String>,
    /// Optional broadcast bus; events are emitted after the violation record is
    /// written and hash-chained. Safety recording is NOT gated on delivery.
    event_bus: Option<ViolationEventBus>,
}

/// Supervisor manages a persistent worker process for true process-level containment.
///
/// All user code execution occurs inside the worker process. The supervisor:
/// - Spawns the worker (same binary, `--worker` flag)
/// - Attaches it to a dedicated cgroup (Linux)
/// - Forwards JSON jobs over stdin
/// - Reads JSON results from stdout
/// - Enforces a hard timeout via `tokio::time::timeout`
/// - SIGKILLs the worker on timeout, writes a signed violation record, and respawns
///
/// Optionally, a [`ViolationEventBus`] can be injected via [`Supervisor::new_with_bus`]
/// so that downstream subsystems (e.g., the ROS2 containment bridge) receive
/// violation events immediately after the record is committed to the log.
pub struct Supervisor {
    config: SupervisorConfig,
    worker: Option<WorkerHandle>,
}

impl Supervisor {
    /// Create a supervisor without a violation event bus.
    pub fn new(bounds: Bounds, signing_key: SigningKey, log_path: String) -> Self {
        if !Self::containment_enforced() {
            warn!(
                "Supervisor created on non-Linux platform: cgroup containment is a \
                 dev-only stub (timeout + SIGKILL where supported). Do not run \
                 untrusted workloads here."
            );
        }
        Self {
            config: SupervisorConfig {
                bounds,
                signing_key,
                log_path,
                last_hash: String::new(),
                worker_bin: None,
                event_bus: None,
            },
            worker: None,
        }
    }

    /// Create a supervisor that broadcasts violation events to `bus`.
    ///
    /// The event is emitted *after* the record is written and hash-chained,
    /// so subscribers always see a record that is already persisted.
    pub fn new_with_bus(
        bounds: Bounds,
        signing_key: SigningKey,
        log_path: String,
        event_bus: ViolationEventBus,
    ) -> Self {
        if !Self::containment_enforced() {
            warn!(
                "Supervisor created on non-Linux platform: cgroup containment is a \
                 dev-only stub (timeout + SIGKILL where supported). Do not run \
                 untrusted workloads here."
            );
        }
        Self {
            config: SupervisorConfig {
                bounds,
                signing_key,
                log_path,
                last_hash: String::new(),
                worker_bin: None,
                event_bus: Some(event_bus),
            },
            worker: None,
        }
    }

    pub fn with_worker_binary(mut self, worker_bin: String) -> Self {
        self.config.worker_bin = Some(worker_bin);
        self
    }

    /// Join the hash chain to an existing log instead of starting a fork.
    ///
    /// Call after construction when the supervisor restarts against a
    /// persisted log: the next record chains from the log's last hash, so
    /// `verify_log_chain` keeps passing across restarts. Missing/empty log
    /// keeps the fresh (empty) chain; a corrupt log fails here, loudly.
    pub fn recover_chain(&mut self) -> Result<(), String> {
        let hash = ViolationRecord::last_hash_from_log(&self.config.log_path)
            .map_err(|e| e.to_string())?;
        self.config.last_hash = hash;
        Ok(())
    }

    /// Spawn a fresh worker process and attach it to a cgroup.
    fn spawn_worker(&mut self) -> Result<(), String> {
        let worker_bin = self
            .config
            .worker_bin
            .clone()
            .or_else(|| std::env::var("DARKSAND_WORKER_BIN").ok());
        let exe = match worker_bin {
            Some(path) => std::path::PathBuf::from(path),
            None => std::env::current_exe().map_err(|e| e.to_string())?,
        };
        let mut command = Command::new(exe);
        command
            .arg("--worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        #[cfg(unix)]
        {
            use nix::libc;

            let memory_limit_bytes = self
                .config
                .bounds
                .max_memory_mb
                .map(|mb| u64::from(mb) * 1024 * 1024);
            unsafe {
                command.pre_exec(move || {
                    if let Some(limit_bytes) = memory_limit_bytes {
                        let limit = libc::rlimit {
                            rlim_cur: limit_bytes as libc::rlim_t,
                            rlim_max: limit_bytes as libc::rlim_t,
                        };
                        if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }

        let mut child = command.spawn().map_err(|e| e.to_string())?;

        let pid = child
            .id()
            .ok_or_else(|| "worker exited immediately".to_string())?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "could not get worker stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "could not get worker stdout".to_string())?;
        let stdout = BufReader::new(stdout);

        // Attach to cgroup before taking ownership. On failure kill the child
        // so a runaway worker is never left outside containment.
        if let Err(e) = self.attach_cgroup(pid) {
            let _ = child.start_kill();
            return Err(e);
        }

        self.worker = Some(WorkerHandle {
            child,
            pid,
            stdin,
            stdout,
        });
        Ok(())
    }

    /// Add the worker PID to a CPU-quota cgroup (Linux only; no-op on other platforms).
    #[cfg(target_os = "linux")]
    fn attach_cgroup(&self, pid: u32) -> Result<(), String> {
        use cgroups_rs::fs::{cgroup_builder::CgroupBuilder, hierarchies};
        use cgroups_rs::CgroupPid;
        let hier = hierarchies::auto();
        let period: u64 = 100_000; // 100 ms in µs
        let quota = (self.config.bounds.max_cpu_percent as i64 * period as i64) / 100;
        let cg = CgroupBuilder::new("darksand_worker")
            .cpu()
            .quota(quota)
            .period(period)
            .done()
            .build(hier)
            .map_err(|e| e.to_string())?;
        cg.add_task(CgroupPid::from(pid as u64))
            .map_err(|e| e.to_string())
    }

    #[cfg(not(target_os = "linux"))]
    fn attach_cgroup(&self, _pid: u32) -> Result<(), String> {
        Ok(())
    }

    /// Send SIGKILL to the current worker. Does nothing if no worker is running.
    fn kill_worker(&self) {
        if let Some(w) = &self.worker {
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(w.pid as i32), Signal::SIGKILL);
            }
        }
    }

    /// Wait for the worker to exit and clear the handle.
    async fn reap_worker(&mut self) {
        if let Some(mut w) = self.worker.take() {
            let _ = w.child.wait().await;
        }
    }

    /// Write a signed violation record, update the hash chain, and optionally
    /// emit an event on the violation bus.
    ///
    /// The record is always written to the JSONL log before any event is emitted.
    /// Returns `true` when the record was persisted. On I/O failure the hash
    /// chain is NOT advanced and no event is emitted, so a later successful
    /// record still chains from the last persisted hash.
    fn record_violation(&mut self, kind: ViolationKind, context: Value) -> bool {
        let record = ViolationRecord::new(
            kind,
            context,
            self.config.last_hash.clone(),
            &self.config.signing_key,
        );
        if record.append_to_log(&self.config.log_path).is_err() {
            return false;
        }
        self.config.last_hash = record.hash.clone();

        // Emit after the record is committed. Non-blocking; safety does not depend
        // on whether any subscriber receives the event.
        if let Some(bus) = &self.config.event_bus {
            bus.emit_violation(record);
        }
        true
    }

    /// Returns `true` on Linux where cgroup + rlimit containment is enforced.
    ///
    /// On non-Linux targets process isolation is a dev-only stub (no cgroup,
    /// timeout + SIGKILL only where supported). Do not run untrusted workloads
    /// there and expect containment.
    pub fn containment_enforced() -> bool {
        cfg!(target_os = "linux")
    }

    /// Classify a finished worker IPC exchange into its exact violation kind.
    ///
    /// Pure function so the audit taxonomy is unit-testable without spawning
    /// a worker: only an elapsed deadline is `Time`; broken pipes, EOF, and
    /// empty answers are `Infra`; successfully-read but unparsable output is
    /// `Malformed` (parse itself happens in `execute`).
    fn classify_ipc(
        timed_out: bool,
        outcome: &std::io::Result<String>,
    ) -> Option<ViolationKind> {
        if timed_out {
            return Some(ViolationKind::Time);
        }
        match outcome {
            Err(_) => Some(ViolationKind::Infra),
            Ok(line) if line.trim().is_empty() => Some(ViolationKind::Infra),
            Ok(_) => None,
        }
    }

    /// Execute a job in the worker process.
    ///
    /// Sends `job` as a single JSON line to the worker's stdin and reads one JSON line
    /// from stdout. A hard timeout of `bounds.max_tick_ms` is applied.
    ///
    /// Violation kinds are exact, not bucketed: `Time` on timeout (worker
    /// SIGKILLed, signed record written, fresh worker respawned),
    /// `Infra` when the worker cannot even be spawned, `Malformed` when the
    /// worker answers with unparsable output.
    pub async fn execute(&mut self, job: Value) -> Result<Value, ViolationKind> {
        if self.worker.is_none() {
            self.spawn_worker().map_err(|_| ViolationKind::Infra)?;
        }

        let job_bytes = {
            let mut s = serde_json::to_string(&job).expect("job is serializable");
            s.push('\n');
            s
        };

        let duration = Duration::from_millis(self.config.bounds.max_tick_ms);

        // Borrow stdin/stdout from the worker for the IPC future.
        // `timed_out` distinguishes a deadline overrun (Time) from a dead
        // worker pipe (Infra); the happy path parses below (Malformed).
        let mut timed_out = false;
        let ipc_result = {
            let w = self.worker.as_mut().unwrap();
            let stdin = &mut w.stdin;
            let stdout = &mut w.stdout;
            let inner = timeout(duration, async {
                stdin.write_all(job_bytes.as_bytes()).await?;
                stdin.flush().await?;
                let mut line = String::new();
                stdout.read_line(&mut line).await?;
                std::io::Result::Ok(line)
            })
            .await;
            match inner {
                Err(_) => {
                    timed_out = true;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "worker tick deadline exceeded",
                    ))
                }
                Ok(r) => r,
            }
        };

        match ipc_result {
            Ok(line) if !line.trim().is_empty() => {
                // Happy path: parse and return the result JSON. Unparsable
                // worker output is a distinct violation kind, not a timeout.
                serde_json::from_str::<Value>(line.trim())
                    .map_err(|_| ViolationKind::Malformed)
            }
            other => {
                // Timeout, dead pipe, or empty answer — kill, reap, record
                // the exact kind, respawn.
                let probe: std::io::Result<String> = match &other {
                    Ok(line) => Ok(line.clone()),
                    Err(e) => Err(std::io::Error::new(e.kind(), "worker IPC failed")),
                };
                let kind =
                    Self::classify_ipc(timed_out, &probe).unwrap_or(ViolationKind::Infra);
                self.kill_worker();
                self.reap_worker().await;
                if !self.record_violation(kind, job) {
                    error!(
                        log_path = %self.config.log_path,
                        "Violation occurred but the signed record could not be persisted"
                    );
                }
                // Best-effort respawn; ignore failure (caller gets Err).
                let _ = self.spawn_worker();
                Err(kind)
            }
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if let Some(w) = self.worker.as_mut() {
            let _ = w.child.start_kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_new() {
        let bounds = Bounds::new(50, 100);
        let secret: [u8; 32] = [0u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let sup = Supervisor::new(bounds, signing_key, "/tmp/test.jsonl".to_string());
        assert!(
            sup.worker.is_none(),
            "worker must not be spawned at construction"
        );
    }

    #[test]
    fn test_supervisor_new_with_bus() {
        let bounds = Bounds::new(50, 100);
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let bus = ViolationEventBus::new();
        let sup = Supervisor::new_with_bus(bounds, signing_key, "/tmp/test.jsonl".to_string(), bus);
        assert!(sup.worker.is_none());
        assert!(sup.config.event_bus.is_some());
    }

    #[test]
    fn test_record_violation_emits_event() {
        // Use a synchronous test; the emit is non-blocking so we can check it
        // immediately via try_recv.
        let bounds = Bounds::new(50, 100);
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let bus = ViolationEventBus::new();
        let mut rx = bus.subscribe();
        let log = std::env::temp_dir()
            .join("darksand_sup_emit_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&log);

        let mut sup = Supervisor::new_with_bus(bounds, signing_key, log.clone(), bus);
        assert!(sup.record_violation(ViolationKind::Time, serde_json::json!({"test": true})));

        let event = rx.try_recv().expect("event must be immediately available");
        let crate::event_bus::ContainmentEvent::Violation(r) = event;
        assert!(matches!(r.violation_kind, ViolationKind::Time));
        assert!(!r.hash.is_empty());

        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn test_record_violation_log_failure_keeps_chain() {
        // Point the log at a directory so append fails. Chain must not advance
        // and no event may be emitted for the unpersisted record.
        let bounds = Bounds::new(50, 100);
        let signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let bus = ViolationEventBus::new();
        let mut rx = bus.subscribe();
        let dir = std::env::temp_dir()
            .join("darksand_sup_fail_dir")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::create_dir_all(&dir);

        let mut sup = Supervisor::new_with_bus(bounds, signing_key, dir.clone(), bus);
        assert!(!sup.record_violation(ViolationKind::Time, serde_json::json!({"t": 1})));
        assert!(rx.try_recv().is_err(), "failed log must not emit");
        assert!(
            sup.config.last_hash.is_empty(),
            "chain must not advance on I/O failure"
        );

        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_containment_enforced_matches_platform() {        assert_eq!(
            Supervisor::containment_enforced(),
            cfg!(target_os = "linux")
        );
        assert_eq!(crate::cgroup::CGroup::is_enforced(), cfg!(target_os = "linux"));
    }

    #[test]
    fn test_recover_chain_joins_existing_log() {
        use crate::violation::ViolationRecord;
        let log = std::env::temp_dir()
            .join("darksand_sup_recover_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&log);
        // Fresh log: empty chain.
        assert_eq!(ViolationRecord::last_hash_from_log(&log).unwrap(), "");
        assert_eq!(
            ViolationRecord::last_hash_from_log("/tmp/definitely-not-here-darksand.jsonl")
                .unwrap(),
            ""
        );

        // Write a record, then recover: next record chains from it.
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let bounds = Bounds::new(50, 100);
        let mut first = Supervisor::new(bounds.clone(), key, log.clone());
        assert!(first.record_violation(ViolationKind::Time, serde_json::json!({})));
        let head = ViolationRecord::last_hash_from_log(&log).unwrap();
        assert!(!head.is_empty());

        let key2 = SigningKey::from_bytes(&[8u8; 32]);
        let mut second = Supervisor::new(bounds, key2, log.clone());
        second.recover_chain().unwrap();
        assert!(second.record_violation(ViolationKind::Cpu, serde_json::json!({})));
        assert_eq!(ViolationRecord::last_hash_from_log(&log).unwrap(), second.config.last_hash);

        // Full chain verifies across the restart.
        let same = SigningKey::from_bytes(&[8u8; 32]);
        assert!(crate::violation::verify_log_chain(&log, &same.verifying_key()).is_ok());
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        // Different key must NOT verify (proves the check is real).
        assert!(crate::violation::verify_log_chain(&log, &wrong.verifying_key()).is_err());
        let _ = std::fs::remove_file(&log);
    }

    /// Full supervisor round-trip test.
    ///
    /// Requires the test binary to handle `--worker`. Skip in unit-test context with
    /// `#[ignore]`; run via an integration test harness that embeds the worker entry point.
    #[tokio::test]
    #[ignore]
    async fn test_execute_success() {
        let bounds = Bounds::new(80, 500);
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let mut sup = Supervisor::new(bounds, signing_key, "/tmp/darksand_sup_test.jsonl".to_string());
        let result = sup.execute(serde_json::json!({"ping": 1})).await;
        assert!(
            result.is_ok(),
            "expected Ok result from worker, got {:?}",
            result
        );
    }

    /// Timeout violation test — also requires a real worker binary; skipped in unit tests.
    #[tokio::test]
    #[ignore]
    async fn test_execute_timeout_violation() {
        let bounds = Bounds::new(80, 50); // 50 ms — worker must exceed this
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let log = "/tmp/darksand_sup_timeout_test.jsonl".to_string();
        let _ = std::fs::remove_file(&log);
        let mut sup = Supervisor::new(bounds, signing_key, log.clone());
        let result = sup.execute(serde_json::json!({"slow": true})).await;
        assert!(
            matches!(result, Err(ViolationKind::Time)),
            "expected Time violation"
        );
        assert!(std::fs::metadata(&log).is_ok(), "violation log must exist");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn test_classify_ipc_exact_kinds() {
        use std::io::{Error, ErrorKind};
        // Elapsed deadline is always Time, whatever the pipe says.
        assert_eq!(
            Supervisor::classify_ipc(true, &Ok("anything".to_string())),
            Some(ViolationKind::Time)
        );
        assert_eq!(
            Supervisor::classify_ipc(
                true,
                &Err(Error::new(ErrorKind::BrokenPipe, "x"))
            ),
            Some(ViolationKind::Time)
        );
        // Dead pipe / EOF / empty answer without a timeout is Infra.
        assert_eq!(
            Supervisor::classify_ipc(
                false,
                &Err(Error::new(ErrorKind::BrokenPipe, "x"))
            ),
            Some(ViolationKind::Infra)
        );
        assert_eq!(
            Supervisor::classify_ipc(false, &Ok(String::new())),
            Some(ViolationKind::Infra)
        );
        assert_eq!(
            Supervisor::classify_ipc(false, &Ok("   \n".to_string())),
            Some(ViolationKind::Infra)
        );
        // Readable output is the caller's to parse: no violation yet.
        assert_eq!(
            Supervisor::classify_ipc(false, &Ok("{\"a\":1}".to_string())),
            None
        );
    }
}
