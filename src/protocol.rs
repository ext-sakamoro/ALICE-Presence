//! Full presence protocol execution
//!
//! Orchestrates proximity check, ZKP exchange, and crossing record
//! creation between two parties.
//!
//! Author: Moroya Sakamoto

use crate::event::{CrossingRecord, PresenceEvent, ProximityProof};
use crate::fnv1a;
use crate::identity::{IdentityCommitment, ZkProof};
use crate::vivaldi::VivaldiCoord;

// ── Configuration ──────────────────────────────────────────────────────

/// Protocol configuration.
#[derive(Debug, Clone, Copy)]
pub struct PresenceConfig {
    /// Vivaldi distance threshold (default 10.0).
    pub proximity_threshold: f64,
    /// ZKP challenge size in bits (default 64).
    pub challenge_bits: u32,
    /// Both parties must confirm (default true).
    pub require_mutual: bool,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            proximity_threshold: 10.0,
            challenge_bits: 64,
            require_mutual: true,
        }
    }
}

// ── Party Info ──────────────────────────────────────────────────────────

/// Identity and location information for one party in a presence exchange.
#[derive(Debug, Clone, Copy)]
pub struct PartyInfo {
    /// Vivaldi network coordinate.
    pub coord: VivaldiCoord,
    /// Secret used for ZKP identity commitment.
    pub secret: u64,
    /// Compact 32-bit party identifier.
    pub id: u32,
}

impl PartyInfo {
    /// Create a new `PartyInfo`.
    pub fn new(coord: VivaldiCoord, secret: u64, id: u32) -> Self {
        Self { coord, secret, id }
    }
}

// ── Protocol Execution ─────────────────────────────────────────────────

/// Execute the full presence protocol between two parties.
///
/// 1. Check proximity via Vivaldi coordinates.
/// 2. Exchange ZKP identity proofs.
/// 3. Create minimal PresenceEvent.
/// 4. Build full CrossingRecord.
///
/// Returns `None` if the parties are not within `config.proximity_threshold`.
pub fn execute_presence_protocol(
    party_a: &PartyInfo,
    party_b: &PartyInfo,
    timestamp_ns: u64,
    config: &PresenceConfig,
) -> Option<CrossingRecord> {
    let proximity =
        ProximityProof::prove(&party_a.coord, &party_b.coord, config.proximity_threshold);
    if !proximity.is_proximate {
        return None;
    }

    let nonce_a = fnv1a(&party_a.id.to_le_bytes());
    let nonce_b = fnv1a(&party_b.id.to_le_bytes());
    let commitment_a = IdentityCommitment::new(party_a.secret, nonce_a, timestamp_ns);
    let commitment_b = IdentityCommitment::new(party_b.secret, nonce_b, timestamp_ns);

    let challenge_a = fnv1a(&timestamp_ns.to_le_bytes()) ^ 0xAAAA_AAAA_AAAA_AAAA;
    let challenge_b = fnv1a(&timestamp_ns.to_le_bytes()) ^ 0x5555_5555_5555_5555;

    let proof_a = ZkProof::prove(party_a.secret, &commitment_a, challenge_a);
    let proof_b = ZkProof::prove(party_b.secret, &commitment_b, challenge_b);

    let mut event = PresenceEvent::new(party_a.id, party_b.id, timestamp_ns);
    if config.require_mutual {
        event.set_mutual();
    }
    if proof_a.verified && proof_b.verified {
        event.set_verified();
    }
    if proximity.is_proximate {
        event.set_proximate();
    }

    Some(CrossingRecord::new(event, proof_a, proof_b, proximity))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = PresenceConfig::default();
        assert!((cfg.proximity_threshold - 10.0).abs() < 1e-12);
        assert_eq!(cfg.challenge_bits, 64);
        assert!(cfg.require_mutual);
    }

    #[test]
    fn protocol_proximate_succeeds() {
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 42, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), 99, 2);
        let cfg = PresenceConfig::default();
        let result = execute_presence_protocol(&a, &b, 1_000_000, &cfg);
        assert!(result.is_some());
        let record = result.unwrap();
        assert!(record.is_fully_verified());
        assert!(record.event.is_mutual());
        assert!(record.event.is_verified());
        assert!(record.event.is_proximate());
    }

    #[test]
    fn protocol_distant_returns_none() {
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 42, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1000.0, 1000.0), 99, 2);
        let cfg = PresenceConfig::default();
        let result = execute_presence_protocol(&a, &b, 1_000_000, &cfg);
        assert!(result.is_none());
    }

    #[test]
    fn protocol_custom_threshold() {
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 1, 1);
        let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), 2, 2);
        let tight = PresenceConfig {
            proximity_threshold: 4.0,
            ..Default::default()
        };
        assert!(execute_presence_protocol(&a, &b, 0, &tight).is_none());

        let loose = PresenceConfig {
            proximity_threshold: 6.0,
            ..Default::default()
        };
        assert!(execute_presence_protocol(&a, &b, 0, &loose).is_some());
    }

    #[test]
    fn protocol_deterministic() {
        let a = PartyInfo::new(VivaldiCoord::new(1.0, 2.0), 10, 1);
        let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), 20, 2);
        let cfg = PresenceConfig::default();
        let r1 = execute_presence_protocol(&a, &b, 500, &cfg).unwrap();
        let r2 = execute_presence_protocol(&a, &b, 500, &cfg).unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn protocol_not_mutual() {
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 42, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 0.0), 99, 2);
        let cfg = PresenceConfig {
            require_mutual: false,
            ..Default::default()
        };
        let record = execute_presence_protocol(&a, &b, 100, &cfg).unwrap();
        assert!(!record.event.is_mutual());
    }
}
