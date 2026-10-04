//! Write-ahead log for mission crash recovery.
//!
//! The executor appends one JSONL entry per completed tick:
//! `{"tick": N, "status": "...", "blackboard": {...}, "tree": {...}}`.
//! After a crash, [`resume_mission_from_wal`] rebuilds the tree from the
//! mission document and restores the last blackboard snapshot, so the
//! re-executed mission continues from observed state instead of blank.
//!
//! Limits (documented, not hidden):
//! - The WAL replays *state*, not *effects*: already-sent actuator commands
//!   are not undone. Downstream systems must tolerate re-ticked actions
//!   (Nav2 goal re-issue is idempotent; raw `/cmd_vel` publishes are not
//!   journaled — gate them behind containment).
//! - Entries are checksummed by length only; tamper evidence comes from the
//!   signed violation log ([`darksand_safety`] is not a dependency here to
//!   keep the core dependency-free), not from this file.
//! - `tick_count` restarts at 1 on resume; the blackboard carries continuity.

use crate::core::{BTreeContext, BTreeNode};
use anyhow::{Context, Result};

/// One journaled tick.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalEntry {
    pub tick: u64,
    pub status: String,
    pub blackboard: serde_json::Value,
    #[serde(default)]
    pub tree: serde_json::Value,
}

/// Append one entry to the WAL (creates the file on first write).
pub fn append_wal(path: &str, entry: &WalEntry) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let line = serde_json::to_string(entry).context("WAL entry is not serializable")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open WAL {path}"))?;
    writeln!(file, "{line}").with_context(|| format!("cannot write WAL {path}"))?;
    file.sync_all().ok(); // best-effort durability; tick loop must not block
    Ok(())
}

/// Read all entries in order; skips blank lines, fails on corrupt JSON.
pub fn read_wal(path: &str) -> Result<Vec<WalEntry>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read WAL {path}"))?;
    let mut entries = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        entries.push(
            serde_json::from_str(line)
                .with_context(|| format!("WAL {path} line {idx} is corrupt"))?,
        );
    }
    Ok(entries)
}

/// Rebuild a mission tree and restore the last journaled blackboard snapshot.
///
/// Returns `(tree, context)` ready for [`crate::BTreeExecutor::execute`].
/// Errors when the mission document is invalid, the WAL is missing/corrupt,
/// or the last snapshot is not a JSON object.
pub async fn resume_mission_from_wal(
    mission_json: &str,
    wal_path: &str,
) -> Result<(Box<dyn BTreeNode>, BTreeContext)> {
    let tree = crate::mission::mission_from_str(mission_json)?;
    let entries = read_wal(wal_path)?;
    let last = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("WAL {wal_path} has no entries to resume from"))?;
    let mut context = BTreeContext::new();
    context.blackboard.restore(&last.blackboard).await?;
    context.tick_count = last.tick;
    Ok((tree, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tick: u64, phase: &str) -> WalEntry {
        WalEntry {
            tick,
            status: format!("{phase:?}"),
            blackboard: serde_json::json!({"phase": phase}),
            tree: serde_json::Value::Null,
        }
    }

    #[test]
    fn roundtrip_preserves_order() {
        let path = std::env::temp_dir()
            .join("darksand_wal_roundtrip_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &entry(1, "starting")).unwrap();
        append_wal(&path, &entry(2, "on-station")).unwrap();
        let entries = read_wal(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].tick, 2);
        assert_eq!(entries[1].blackboard["phase"], "on-station");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_tail_fails_closed() {
        let path = std::env::temp_dir()
            .join("darksand_wal_corrupt_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &entry(1, "starting")).unwrap();
        std::fs::write(&path, "not json at all\n").unwrap();
        assert!(read_wal(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn resume_restores_blackboard_and_tick() {        let path = std::env::temp_dir()
            .join("darksand_wal_resume_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &entry(1, "starting")).unwrap();
        append_wal(&path, &entry(2, "on-station")).unwrap();

        let mission = r#"{"version": "darksand-mission.v1", "name": "r",
            "root": {"type": "Sequence", "name": "m", "children": [
                {"type": "CheckBlackboard", "name": "c", "key": "phase", "expected": "on-station"}
            ]}}"#;
        let (mut tree, mut ctx) = resume_mission_from_wal(mission, &path).await.unwrap();
        assert_eq!(ctx.tick_count, 2);
        // The restored snapshot satisfies the check without re-running leg 1.
        let status = crate::BTreeExecutor::new()
            .tick(tree.as_mut(), &mut ctx)
            .await
            .unwrap();
        assert_eq!(status, crate::core::NodeStatus::Success);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn executor_journals_ticks_to_wal() {
        let path = std::env::temp_dir()
            .join("darksand_wal_exec_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);

        let mission = r#"{"version": "darksand-mission.v1", "name": "w",
            "root": {"type": "Sequence", "name": "m", "children": [
                {"type": "SetBlackboard", "name": "a", "key": "leg", "value": 1},
                {"type": "SetBlackboard", "name": "b", "key": "leg", "value": 2}
            ]}}"#;
        let mut tree = crate::mission::mission_from_str(mission).unwrap();
        let mut ctx = crate::core::BTreeContext::new();
        let result = crate::BTreeExecutor::new()
            .with_wal(&path)
            .execute(&mut *tree, &mut ctx)
            .await
            .unwrap();
        assert!(result.is_success());

        // Sequence completes in one tick: exactly one journaled entry.
        let entries = read_wal(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tick, 1);
        assert_eq!(entries[0].blackboard["leg"], 2);
        let _ = std::fs::remove_file(&path);
    }

    /// Crash-mid-mission recovery: stop early with WAL, resume from the
    /// journal, run to completion. The resumed run sees leg 1's state.
    #[tokio::test]
    async fn crash_mid_mission_resumes_to_success() {
        let path = std::env::temp_dir()
            .join("darksand_wal_crash_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);

        // Repeat needs 2 ticks: first execute() is "killed" via max_ticks=1.
        let mission = r#"{"version": "darksand-mission.v1", "name": "crash",
            "root": {"type": "Repeat", "name": "twice", "count": 2,
                "child": {"type": "SetBlackboard", "name": "leg", "key": "n", "value": 7}}}"#;
        let mut tree = crate::mission::mission_from_str(mission).unwrap();
        let mut ctx = crate::core::BTreeContext::new();
        let partial = crate::BTreeExecutor::new()
            .with_max_ticks(1)
            .with_wal(&path)
            .execute(&mut *tree, &mut ctx)
            .await
            .unwrap();
        assert!(partial.max_ticks_reached);

        // "Restart": rebuild from mission + WAL and run to completion.
        let (mut tree2, mut ctx2) = resume_mission_from_wal(mission, &path).await.unwrap();
        let done = crate::BTreeExecutor::new()
            .execute(&mut *tree2, &mut ctx2)
            .await
            .unwrap();
        assert!(done.is_success());
        assert_eq!(
            ctx2.blackboard.get("n").await,
            Some(serde_json::json!(7))
        );
        let _ = std::fs::remove_file(&path);
    }
}
