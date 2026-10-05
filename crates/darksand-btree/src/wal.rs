//! Write-ahead log for mission crash recovery.
//!
//! The executor appends one JSONL entry per completed tick:
//! `{"tick": N, "status": "...", "blackboard": {...}, "tree": {...}}`.
//! After a crash, [`resume_mission_from_wal`] rebuilds the tree from the
//! mission document and restores the last blackboard snapshot, so the
//! re-executed mission continues from observed state instead of blank.
//!
//! Limits (documented, not hidden):
//! - The WAL replays *blackboard state*, not *node cursors*: `Sequence`
//!   progress, retry counts, and decorator timers restart. Design missions so
//!   re-ticked actions are idempotent (Nav2 goal re-issue is; raw `/cmd_vel`
//!   publishes are not journaled — gate them behind containment).
//! - Entries carry the mission document's identity when the executor was
//!   given one (`with_mission_identity`); resume refuses a foreign journal.
//! - A torn tail (crash mid-write) is dropped with a warning; a corrupt
//!   non-final line fails closed.
//! - Tamper evidence comes from the signed violation log, not this file.

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
    /// Mission name this tick belongs to (absent in pre-identity journals).
    #[serde(default)]
    pub mission: Option<String>,
    /// SHA-256 of the mission document (absent in pre-identity journals).
    #[serde(default)]
    pub mission_hash: Option<String>,
}

/// SHA-256 hex of a mission document. Pair with
/// [`resume_mission_from_wal`]: the resume rejects a WAL whose identity does
/// not match the document being resumed.
pub fn mission_hash(mission_json: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(mission_json.as_bytes()))
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
    let (entries, _) = read_wal_tolerant(path)?;
    Ok(entries)
}

/// Read all entries, tolerating a torn tail.
///
/// A crash mid-`writeln` leaves a partial final line — the expected artifact,
/// not evidence of tampering. A corrupt *non-final* line still fails closed.
/// Returns `(entries, torn)` where `torn` reports a dropped partial tail.
pub fn read_wal_tolerant(path: &str) -> Result<(Vec<WalEntry>, bool)> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read WAL {path}"))?;
    let lines: Vec<&str> = content.lines().collect();
    let mut entries = Vec::new();
    let mut torn = false;
    for (idx, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(entry) => entries.push(entry),
            Err(_) if idx == lines.len() - 1 => {
                torn = true; // partial final write from a crash; drop it
            }
            Err(e) => {
                anyhow::bail!("WAL {path} line {idx} is corrupt: {e}");
            }
        }
    }
    Ok((entries, torn))
}

/// Integrity report for a WAL file.
#[derive(Debug, Clone, PartialEq)]
pub struct WalReport {
    pub entries: usize,
    pub torn: bool,
    pub monotonic: bool,
}

/// Verify a WAL file: every entry parses, ticks are strictly increasing, and
/// all carried mission identities agree.
///
/// A journal must be a legal execution prefix — out-of-order ticks or mixed
/// missions mean the file is not one run's history and resume must refuse it.
/// Pre-identity entries (no mission fields) are skipped by the identity check.
pub fn verify_wal(path: &str) -> Result<WalReport> {
    let (entries, torn) = read_wal_tolerant(path)?;
    check_entries(&entries, path)?;
    Ok(WalReport {
        entries: entries.len(),
        torn,
        monotonic: true,
    })
}

fn check_entries(entries: &[WalEntry], path: &str) -> Result<()> {
    for pair in entries.windows(2) {
        if pair[1].tick <= pair[0].tick {
            anyhow::bail!("WAL {path} ticks are not strictly increasing");
        }
    }
    let mut identity: Option<(&str, &str)> = None;
    for entry in entries {
        if let (Some(name), Some(hash)) = (entry.mission.as_deref(), entry.mission_hash.as_deref())
        {
            match identity {
                None => identity = Some((name, hash)),
                Some((n, h)) if n == name && h == hash => {}
                _ => anyhow::bail!("WAL {path} mixes entries from different missions"),
            }
        }
    }
    Ok(())
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
    // Tolerant read: a torn tail is the expected crash artifact, not tampering.
    // Then verify: the journal must be one run's legal prefix, and every
    // identity-carrying entry must belong to THIS document — not just the last.
    let (entries, torn) = read_wal_tolerant(wal_path)?;
    if torn {
        tracing::warn!("WAL {wal_path} had a torn tail; resumed from the intact prefix");
    }
    check_entries(&entries, wal_path)?;
    let last = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("WAL {wal_path} has no entries to resume from"))?;
    // Fail closed on mission mismatch: never inject one mission's state into
    // another. Journals written before identity existed carry no identity and
    // are accepted (with the WAL path in the log for audit). The agreed
    // identity anchors on the FIRST carrying entry, so a foreign head cannot
    // hide behind a matching tail.
    if let Some(first) = entries.iter().find_map(|e| {
        e.mission
            .as_deref()
            .zip(e.mission_hash.as_deref())
    }) {
        let (wal_name, wal_hash) = first;
        let doc: serde_json::Value =
            serde_json::from_str(mission_json).context("mission document is not valid JSON")?;
        let doc_name = doc
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        if wal_name != doc_name || wal_hash != mission_hash(mission_json) {
            anyhow::bail!(
                "WAL {wal_path} belongs to mission {wal_name:?}, not {doc_name:?}: refusing resume"
            );
        }
    }
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
            mission: None,
            mission_hash: None,
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
    fn corrupt_middle_fails_closed() {
        let path = std::env::temp_dir()
            .join("darksand_wal_corrupt_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &entry(1, "starting")).unwrap();
        // Corrupt NON-final line: fail closed, history is suspect.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "not json at all").unwrap();
        append_wal(&path, &entry(2, "on-station")).unwrap();
        assert!(read_wal(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn torn_tail_is_dropped_not_fatal() {
        let path = std::env::temp_dir()
            .join("darksand_wal_torn_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &entry(1, "starting")).unwrap();
        // Simulate a crash mid-write: partial final line, no trailing newline.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, "{{\"tick\": 2, \"stat").unwrap();
        let (entries, torn) = read_wal_tolerant(&path).unwrap();
        assert!(torn);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tick, 1);
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
    /// journal, run to completion. The resumed run sees leg 1's state, ticks
    /// stay monotonic, and a foreign journal is refused.
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
        let hash = mission_hash(mission);
        let mut tree = crate::mission::mission_from_str(mission).unwrap();
        let mut ctx = crate::core::BTreeContext::new();
        let partial = crate::BTreeExecutor::new()
            .with_max_ticks(1)
            .with_wal(&path)
            .with_mission_identity("crash", hash.clone())
            .execute(&mut *tree, &mut ctx)
            .await
            .unwrap();
        assert!(partial.max_ticks_reached);

        // "Restart": rebuild from mission + WAL and run to completion.
        let (mut tree2, mut ctx2) = resume_mission_from_wal(mission, &path).await.unwrap();
        let done = crate::BTreeExecutor::new()
            .with_start_tick(ctx2.tick_count)
            .with_wal(&path)
            .with_mission_identity("crash", hash)
            .execute(&mut *tree2, &mut ctx2)
            .await
            .unwrap();
        assert!(done.is_success());
        assert_eq!(
            ctx2.blackboard.get("n").await,
            Some(serde_json::json!(7))
        );

        // Journal ticks are monotonic across the restart: first run ticked
        // once (1/2 iterations), the resumed run ticks twice more.
        let ticks: Vec<u64> = read_wal(&path)
            .unwrap()
            .into_iter()
            .map(|e| e.tick)
            .collect();
        assert_eq!(ticks, vec![1, 2, 3]);

        // A different mission document is refused the journal.
        let foreign = r#"{"version": "darksand-mission.v1", "name": "other",
            "root": {"type": "SetBlackboard", "name": "x", "key": "q", "value": 0}}"#;
        assert!(resume_mission_from_wal(foreign, &path).await.is_err());

        let _ = std::fs::remove_file(&path);
    }

    fn identified(tick: u64, name: &str, hash: &str) -> WalEntry {
        WalEntry {
            tick,
            status: "Success".to_string(),
            blackboard: serde_json::json!({}),
            tree: serde_json::Value::Null,
            mission: Some(name.to_string()),
            mission_hash: Some(hash.to_string()),
        }
    }

    #[test]
    fn verify_wal_rejects_non_monotonic_ticks() {
        let path = std::env::temp_dir()
            .join("darksand_wal_nonmono_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &entry(1, "a")).unwrap();
        append_wal(&path, &entry(5, "b")).unwrap();
        append_wal(&path, &entry(3, "c")).unwrap();
        let err = verify_wal(&path).unwrap_err();
        assert!(err.to_string().contains("non-monotonic") || err.to_string().contains("strictly increasing"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_wal_rejects_mixed_missions() {
        let path = std::env::temp_dir()
            .join("darksand_wal_mixed_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        append_wal(&path, &identified(1, "one", "h1")).unwrap();
        append_wal(&path, &identified(2, "one", "h1")).unwrap();
        let report = verify_wal(&path).unwrap();
        assert_eq!(
            report,
            WalReport {
                entries: 2,
                torn: false,
                monotonic: true
            }
        );
        append_wal(&path, &identified(3, "other", "h2")).unwrap();
        assert!(verify_wal(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn resume_refuses_foreign_head_behind_matching_tail() {
        let path = std::env::temp_dir()
            .join("darksand_wal_foreign_head_test.jsonl")
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        let mission = r#"{"version": "darksand-mission.v1", "name": "mine",
            "root": {"type": "SetBlackboard", "name": "a", "key": "k", "value": 1}}"#;
        let hash = mission_hash(mission);
        append_wal(&path, &identified(1, "other", "deadbeef")).unwrap();
        append_wal(
            &path,
            &WalEntry {
                tick: 2,
                status: "Success".to_string(),
                blackboard: serde_json::json!({"k": 1}),
                tree: serde_json::Value::Null,
                mission: Some("mine".to_string()),
                mission_hash: Some(hash),
            },
        )
        .unwrap();
        // Tail matches, head does not: refuse (last-entry-only checks pass this).
        assert!(resume_mission_from_wal(mission, &path).await.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
