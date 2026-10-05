//! Swarm message signing and verification (Phase 5).
//!
//! Every inter-node `SwarmMessage` is wrapped in a `SignedSwarmEnvelope` before
//! transmission over HTTP.  The envelope carries:
//!
//! * `peer_id` — the sending node's logical identity.
//! * `timestamp` — ISO-8601 UTC, included in the signed payload to prevent
//!   replay attacks.
//! * `signature` — Base64 Ed25519 over `SHA-256(peer_id:timestamp:body_json)`.
//!
//! Peers MUST call `verify_envelope` before processing any inbound message.
//! Invalid or missing signatures MUST result in the message being dropped.
//!
//! # HTTP header convention
//!
//! When the envelope is serialised for HTTP transport the signature is also
//! available as the `X-Darksand-Swarm-Sig` request header (Base64 Ed25519).

use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::transport::SwarmMessage;

// ─────────────────────────────────────────────────────────────────────────────
// SignedSwarmEnvelope
// ─────────────────────────────────────────────────────────────────────────────

/// A signed wrapper around a `SwarmMessage`.
///
/// All fields participate in the signature computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSwarmEnvelope {
    /// Sending peer's agent identifier.
    pub peer_id: String,
    /// ISO-8601 UTC timestamp at signing time.
    pub timestamp: String,
    /// The inner swarm message.
    pub message: SwarmMessage,
    /// Base64-encoded Ed25519 signature over
    /// `SHA-256("{peer_id}:{timestamp}:{message_json}")`.
    pub signature: String,
}

impl SignedSwarmEnvelope {
    /// Build and sign a new envelope.
    pub fn new(peer_id: &str, message: SwarmMessage, signing_key: &SigningKey) -> Result<Self> {
        let timestamp = swarm_iso8601_now();
        let message_json = serde_json::to_string(&message)?;
        let payload = format!("{}:{}:{}", peer_id, timestamp, message_json);
        let digest = Sha256::digest(payload.as_bytes());
        let sig = signing_key.sign(&digest);
        let signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        Ok(Self {
            peer_id: peer_id.to_string(),
            timestamp,
            message,
            signature,
        })
    }

    /// Return the value suitable for the `X-Darksand-Swarm-Sig` HTTP header.
    pub fn header_value(&self) -> &str {
        &self.signature
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmMessageSigner
// ─────────────────────────────────────────────────────────────────────────────

/// Signs outbound swarm messages on behalf of a local node.
pub struct SwarmMessageSigner {
    peer_id: String,
    signing_key: SigningKey,
}

impl SwarmMessageSigner {
    /// Create a new signer with the given Ed25519 key.
    pub fn new(peer_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            peer_id: peer_id.into(),
            signing_key,
        }
    }

    /// Sign `message` and return a `SignedSwarmEnvelope`.
    pub fn sign(&self, message: SwarmMessage) -> Result<SignedSwarmEnvelope> {
        SignedSwarmEnvelope::new(&self.peer_id, message, &self.signing_key)
    }

    /// Return the hex-encoded public verifying key (for peer exchange).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verify that `envelope.signature` was produced by `verifying_key`.
///
/// Returns `Ok(())` on success, `Err(...)` if the signature is absent, malformed,
/// or does not match the envelope contents.  Callers MUST drop the message on
/// `Err`. Authenticity only — for freshness and replay see
/// [`verify_envelope_fresh`] and [`PeerKeyRegistry`].
pub fn verify_envelope(envelope: &SignedSwarmEnvelope, verifying_key: &VerifyingKey) -> Result<()> {
    use ed25519_dalek::Signature;

    if envelope.signature.is_empty() {
        anyhow::bail!("swarm envelope has no signature");
    }

    let message_json = serde_json::to_string(&envelope.message)?;
    let payload = format!(
        "{}:{}:{}",
        envelope.peer_id, envelope.timestamp, message_json
    );
    let digest = Sha256::digest(payload.as_bytes());

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature)
        .map_err(|e| anyhow::anyhow!("bad base64 signature: {}", e))?;

    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid signature bytes: {}", e))?;

    verifying_key
        .verify(&digest, &sig)
        .map_err(|e| anyhow::anyhow!("swarm signature verification failed: {}", e))
}

/// Parse an envelope timestamp (`%Y-%m-%dT%H:%M:%SZ`, UTC) back to epoch
/// seconds. Strict: anything else is a drop, not a guess.
fn parse_envelope_time(s: &str) -> Result<u64> {
    let err = || anyhow::anyhow!("bad envelope timestamp {s:?}");
    if s.len() != 20
        || !s.ends_with('Z')
        || s.as_bytes()[4] != b'-'
        || s.as_bytes()[7] != b'-'
        || s.as_bytes()[10] != b'T'
        || s.as_bytes()[13] != b':'
        || s.as_bytes()[16] != b':'
    {
        return Err(err());
    }
    let num = |lo: usize, hi: usize| {
        s[lo..hi]
            .parse::<u64>()
            .map_err(|_| err())
    };
    let (year, mon, day, hour, min, sec) = (
        num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?,
    );
    if !(1..=12).contains(&mon) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return Err(err());
    }
    // Howard Hinnant's days_from_civil.
    let y = if mon <= 2 { year as i64 - 1 } else { year as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = ((mon as i64 + 9) % 12) as u64;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as u64 * 146097 + doe - 719468;
    Ok(days * 86_400 + hour * 3_600 + min * 60 + sec)
}

/// Verify signature AND freshness: the envelope must verify under `key` and
/// its timestamp must be within `max_skew_secs` of `now_secs` (past or
/// future). Stale or far-future envelopes are dropped even when genuinely
/// signed — freshness is a property of delivery, not of the key.
pub fn verify_envelope_fresh(
    envelope: &SignedSwarmEnvelope,
    verifying_key: &VerifyingKey,
    now_secs: u64,
    max_skew_secs: u64,
) -> Result<()> {
    verify_envelope(envelope, verifying_key)?;
    let ts = parse_envelope_time(&envelope.timestamp)?;
    let skew = now_secs.abs_diff(ts);
    if skew > max_skew_secs {
        anyhow::bail!("stale envelope: skew {skew}s exceeds {max_skew_secs}s");
    }
    Ok(())
}

/// Verifying keys plus replay memory for a set of peers.
///
/// `verify` enforces, in order: known peer → valid signature → fresh
/// timestamp → unseen digest. Digests are SHA-256 over the exact signed
/// bytes, so any redelivery — bit-identical or replayed — is rejected.
/// Memory is bounded (4096 digests, then cleared with a fresh start);
/// monotonic timestamps are NOT required, so two legitimate same-second
/// messages with different content both pass.
pub struct PeerKeyRegistry {
    keys: std::collections::HashMap<String, VerifyingKey>,
    seen: std::collections::HashSet<String>,
    max_skew_secs: u64,
}

impl PeerKeyRegistry {
    pub fn new(max_skew_secs: u64) -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            seen: std::collections::HashSet::new(),
            max_skew_secs,
        }
    }

    /// Register (or rotate) a peer's verifying key. Clears that peer's
    /// replay memory: rotation starts a new epoch by definition.
    pub fn register_peer(&mut self, peer_id: &str, key: VerifyingKey) {
        self.keys.insert(peer_id.to_string(), key);
        self.seen.retain(|d| !d.starts_with(peer_id));
    }

    /// Verify an envelope now (seconds since epoch). Returns the inner
    /// message on success; drops (Err) unknown peers, bad signatures,
    /// stale timestamps, and exact redeliveries.
    pub fn verify(
        &mut self,
        envelope: &SignedSwarmEnvelope,
        now_secs: u64,
    ) -> Result<SwarmMessage> {
        let key = self
            .keys
            .get(&envelope.peer_id)
            .ok_or_else(|| anyhow::anyhow!("unknown swarm peer {}", envelope.peer_id))?;
        verify_envelope_fresh(envelope, key, now_secs, self.max_skew_secs)?;
        let message_json = serde_json::to_string(&envelope.message)?;
        let digest_input = format!(
            "{}:{}:{}",
            envelope.peer_id, envelope.timestamp, message_json
        );
        let digest = format!("{:x}", Sha256::digest(digest_input.as_bytes()));
        let tag = format!("{}:{digest}", envelope.peer_id);
        if !self.seen.insert(tag) {
            anyhow::bail!("replayed swarm envelope");
        }
        if self.seen.len() > 4096 {
            self.seen.clear();
        }
        Ok(envelope.message.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn swarm_iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let rem = secs % 86_400;
    let h = rem / 3_600;
    let m = (rem % 3_600) / 60;
    let s = rem % 60;
    let days = secs / 86_400;
    let (year, month, day) = swarm_days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

fn swarm_days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days as i64 + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y as u64, mo as u64, d as u64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn sign_and_verify_heartbeat() {
        let sk = make_key();
        let vk = sk.verifying_key();
        let signer = SwarmMessageSigner::new("node-1", sk);

        let msg = SwarmMessage::Heartbeat {
            leader_id: "node-1".to_string(),
            term: 42,
        };
        let envelope = signer.sign(msg).unwrap();

        assert!(verify_envelope(&envelope, &vk).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = make_key();
        let vk = sk.verifying_key();
        let signer = SwarmMessageSigner::new("node-1", sk);

        let msg = SwarmMessage::Heartbeat {
            leader_id: "node-1".to_string(),
            term: 1,
        };
        let mut envelope = signer.sign(msg).unwrap();

        // Tamper: change the term inside the message.
        envelope.message = SwarmMessage::Heartbeat {
            leader_id: "node-1".to_string(),
            term: 999,
        };

        assert!(verify_envelope(&envelope, &vk).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk1 = make_key();
        let sk2 = make_key();
        let vk2 = sk2.verifying_key();

        let signer = SwarmMessageSigner::new("node-1", sk1);
        let msg = SwarmMessage::AgentJoined {
            agent_id: "node-1".to_string(),
            capabilities: vec!["inference".to_string()],
        };
        let envelope = signer.sign(msg).unwrap();

        // Verify with different key — should fail.
        assert!(verify_envelope(&envelope, &vk2).is_err());
    }

    #[test]
    fn verify_rejects_empty_signature() {
        let sk = make_key();
        let vk = sk.verifying_key();
        let msg = SwarmMessage::AgentLeft {
            agent_id: "node-1".to_string(),
        };
        let envelope = SignedSwarmEnvelope {
            peer_id: "node-1".to_string(),
            timestamp: swarm_iso8601_now(),
            message: msg,
            signature: String::new(),
        };
        assert!(verify_envelope(&envelope, &vk).is_err());
    }

    #[test]
    fn signer_public_key_hex_is_64_chars() {
        let sk = make_key();
        let signer = SwarmMessageSigner::new("n", sk);
        assert_eq!(signer.public_key_hex().len(), 64);
    }

    #[test]
    fn timestamp_roundtrips_to_now() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = swarm_iso8601_now();
        let parsed = parse_envelope_time(&ts).unwrap();
        assert!(now.abs_diff(parsed) <= 2, "now={now} parsed={parsed}");
    }

    #[test]
    fn timestamp_rejects_malformed() {
        for bad in ["", "yesterday", "2026-13-01T00:00:00Z", "2026-01-01 00:00:00", "2026-01-01T24:00:00Z"] {
            assert!(parse_envelope_time(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn fresh_check_enforces_skew() {
        let sk = make_key();
        let vk = sk.verifying_key();
        let signer = SwarmMessageSigner::new("n", sk);
        let env = signer
            .sign(SwarmMessage::Heartbeat {
                leader_id: "n".to_string(),
                term: 1,
            })
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_envelope_fresh(&env, &vk, now, 60).is_ok());
        // Far future / far past delivery both drop.
        assert!(verify_envelope_fresh(&env, &vk, now + 3600, 60).is_err());
        assert!(verify_envelope_fresh(&env, &vk, now.saturating_sub(3600), 60).is_err());
    }

    #[test]
    fn registry_rejects_replay_but_allows_distinct() {
        let sk = make_key();
        let mut reg = PeerKeyRegistry::new(60);
        reg.register_peer("n", sk.verifying_key());
        let signer = SwarmMessageSigner::new("n", sk);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let e1 = signer
            .sign(SwarmMessage::Heartbeat {
                leader_id: "n".to_string(),
                term: 1,
            })
            .unwrap();
        assert!(reg.verify(&e1, now).is_ok());
        assert!(reg.verify(&e1, now).is_err());
        // Same second, different content: distinct digest, accepted.
        let e2 = signer
            .sign(SwarmMessage::Heartbeat {
                leader_id: "n".to_string(),
                term: 2,
            })
            .unwrap();
        assert!(reg.verify(&e2, now).is_ok());
    }
}
