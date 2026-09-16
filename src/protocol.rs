//! Full presence protocol execution
//!
//! Orchestrates proximity check, challenge-response exchange, and crossing
//! record creation between two parties.
//!
//! Real deployments run the two halves on two devices; this module executes
//! both halves in one process so the flow can be tested end to end. The only
//! thing that has to cross the network in a real exchange is: each side's
//! public key, its coordinate hash, the challenge it draws for the other
//! side, and its [`ChallengeProof`].
//!
//! Author: Moroya Sakamoto

use rand_core::{CryptoRng, RngCore};

use crate::event::{encounter_transcript, CrossingRecord, PresenceEvent, ProximityProof};
use crate::identity::{Challenge, ChallengeProof, Identity};
use crate::vivaldi::VivaldiCoord;

// ── Configuration ──────────────────────────────────────────────────────

/// Protocol configuration.
#[derive(Debug, Clone, Copy)]
pub struct PresenceConfig {
    /// Vivaldi distance threshold (default 10.0).
    pub proximity_threshold: f64,
    /// Both parties must confirm (default true).
    pub require_mutual: bool,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            proximity_threshold: 10.0,
            require_mutual: true,
        }
    }
}

// ── Party Info ──────────────────────────────────────────────────────────

/// Identity and location information for one party in a presence exchange.
///
/// The private key stays with its owner: `PartyInfo` only borrows it.
#[derive(Debug, Clone, Copy)]
pub struct PartyInfo<'a> {
    /// Vivaldi network coordinate.
    pub coord: VivaldiCoord,
    /// Ed25519 identity used to answer the counterpart's challenge.
    pub identity: &'a Identity,
    /// Compact 32-bit party identifier.
    pub id: u32,
}

impl<'a> PartyInfo<'a> {
    /// Create a new `PartyInfo`.
    #[must_use]
    pub const fn new(coord: VivaldiCoord, identity: &'a Identity, id: u32) -> Self {
        Self {
            coord,
            identity,
            id,
        }
    }
}

// ── Challenges ─────────────────────────────────────────────────────────

/// The two verifier-issued challenges of one exchange.
///
/// `for_a` is drawn by **B** and answered by A; `for_b` is drawn by **A**
/// and answered by B. Each side must draw its own value with a CSPRNG
/// ([`ExchangeChallenges::random`]); a party that lets its counterpart pick
/// the challenge gets no replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeChallenges {
    /// Issued by B, answered by A.
    pub for_a: Challenge,
    /// Issued by A, answered by B.
    pub for_b: Challenge,
}

impl ExchangeChallenges {
    /// Draw both challenges from a cryptographic RNG.
    #[must_use]
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            for_a: Challenge::random(rng),
            for_b: Challenge::random(rng),
        }
    }

    /// Deterministic challenges derived from one seed (tests only).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut for_b = seed;
        for byte in &mut for_b {
            *byte = !*byte;
        }
        Self {
            for_a: Challenge::from_seed(seed),
            for_b: Challenge::from_seed(for_b),
        }
    }
}

// ── Protocol Execution ─────────────────────────────────────────────────

/// Execute the full presence protocol between two parties.
///
/// 1. Check proximity via Vivaldi coordinates.
/// 2. Build the shared transcript (event without the verified bit, proximity
///    payload, both public keys, both challenges).
/// 3. Each party signs the transcript with its own challenge.
/// 4. Each side verifies the other's proof against the challenge it issued.
/// 5. Only then is the event's `verified` flag set.
///
/// Returns `None` if the parties are not within `config.proximity_threshold`.
/// The returned record has `event.is_verified() == true` only when both
/// signatures checked out — but callers that receive a record over the wire
/// must still run [`crate::verification::verify_record`] themselves.
#[must_use]
pub fn execute_presence_protocol(
    party_a: &PartyInfo<'_>,
    party_b: &PartyInfo<'_>,
    challenges: &ExchangeChallenges,
    timestamp_ns: u64,
    config: &PresenceConfig,
) -> Option<CrossingRecord> {
    let proximity =
        ProximityProof::prove(&party_a.coord, &party_b.coord, config.proximity_threshold);
    if !proximity.is_proximate {
        return None;
    }

    let mut event = PresenceEvent::new(party_a.id, party_b.id, timestamp_ns);
    if config.require_mutual {
        event.set_mutual();
    }
    event.set_proximate();

    let pk_a = party_a.identity.public_key();
    let pk_b = party_b.identity.public_key();
    let transcript = encounter_transcript(
        &event,
        &proximity,
        &pk_a,
        &pk_b,
        &challenges.for_a,
        &challenges.for_b,
    );

    let proof_a = ChallengeProof::prove(party_a.identity, challenges.for_a, &transcript);
    let proof_b = ChallengeProof::prove(party_b.identity, challenges.for_b, &transcript);

    // B verifies A against the challenge B issued, and vice versa.
    let a_ok = proof_a
        .verify_with_key(&pk_a, &challenges.for_a, &transcript)
        .is_ok();
    let b_ok = proof_b
        .verify_with_key(&pk_b, &challenges.for_b, &transcript)
        .is_ok();
    if a_ok && b_ok {
        event.set_verified();
    }

    Some(CrossingRecord::new(event, proof_a, proof_b, proximity))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{verify_record, VerifyResult};

    fn ids() -> (Identity, Identity) {
        (Identity::from_seed([1; 32]), Identity::from_seed([2; 32]))
    }

    fn ch() -> ExchangeChallenges {
        ExchangeChallenges::from_seed([7; 32])
    }

    #[test]
    fn config_defaults() {
        let cfg = PresenceConfig::default();
        assert!((cfg.proximity_threshold - 10.0).abs() < 1e-12);
        assert!(cfg.require_mutual);
    }

    #[test]
    fn challenges_from_seed_differ_per_side() {
        let c = ch();
        assert_ne!(c.for_a, c.for_b);
        assert_eq!(c, ch());
    }

    #[test]
    fn challenges_random_differ() {
        let a = ExchangeChallenges::random(&mut rand_core::OsRng);
        let b = ExchangeChallenges::random(&mut rand_core::OsRng);
        assert_ne!(a, b);
        assert_ne!(a.for_a, a.for_b);
    }

    #[test]
    fn protocol_proximate_succeeds() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), &ib, 2);
        let cfg = PresenceConfig::default();
        let record = execute_presence_protocol(&a, &b, &ch(), 1_000_000, &cfg).unwrap();
        assert_eq!(verify_record(&record), VerifyResult::Valid);
        assert!(record.event.is_mutual());
        assert!(record.event.is_verified());
        assert!(record.event.is_proximate());
        assert_eq!(record.proof_a.public_key, ia.public_key());
        assert_eq!(record.proof_b.public_key, ib.public_key());
        assert_eq!(record.proof_a.challenge, ch().for_a);
        assert_eq!(record.proof_b.challenge, ch().for_b);
    }

    #[test]
    fn protocol_distant_returns_none() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1000.0, 1000.0), &ib, 2);
        let cfg = PresenceConfig::default();
        assert!(execute_presence_protocol(&a, &b, &ch(), 1_000_000, &cfg).is_none());
    }

    #[test]
    fn protocol_custom_threshold() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
        let tight = PresenceConfig {
            proximity_threshold: 4.0,
            ..Default::default()
        };
        assert!(execute_presence_protocol(&a, &b, &ch(), 0, &tight).is_none());

        let loose = PresenceConfig {
            proximity_threshold: 6.0,
            ..Default::default()
        };
        assert!(execute_presence_protocol(&a, &b, &ch(), 0, &loose).is_some());
    }

    #[test]
    fn protocol_deterministic() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(1.0, 2.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
        let cfg = PresenceConfig::default();
        let r1 = execute_presence_protocol(&a, &b, &ch(), 500, &cfg).unwrap();
        let r2 = execute_presence_protocol(&a, &b, &ch(), 500, &cfg).unwrap();
        // Ed25519 signatures are deterministic, so the whole record is.
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.proof_a, r2.proof_a);
    }

    #[test]
    fn protocol_different_challenges_different_signatures() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(1.0, 2.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
        let cfg = PresenceConfig::default();
        let r1 = execute_presence_protocol(&a, &b, &ch(), 500, &cfg).unwrap();
        let r2 =
            execute_presence_protocol(&a, &b, &ExchangeChallenges::from_seed([8; 32]), 500, &cfg)
                .unwrap();
        assert_ne!(r1.proof_a.signature, r2.proof_a.signature);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn protocol_not_mutual() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 0.0), &ib, 2);
        let cfg = PresenceConfig {
            require_mutual: false,
            ..Default::default()
        };
        let record = execute_presence_protocol(&a, &b, &ch(), 100, &cfg).unwrap();
        assert!(!record.event.is_mutual());
        assert_eq!(verify_record(&record), VerifyResult::Valid);
    }

    #[test]
    fn protocol_same_coords_is_proximate() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(5.0, 5.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(5.0, 5.0), &ib, 2);
        let cfg = PresenceConfig::default();
        let record = execute_presence_protocol(&a, &b, &ch(), 0, &cfg).unwrap();
        assert_eq!(verify_record(&record), VerifyResult::Valid);
        assert!((record.proximity.distance).abs() < 1e-12);
    }

    #[test]
    fn protocol_boundary_threshold_inclusive() {
        let (ia, ib) = ids();
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(10.0, 0.0), &ib, 2);
        let cfg_exact = PresenceConfig {
            proximity_threshold: 10.0,
            ..Default::default()
        };
        assert!(execute_presence_protocol(&a, &b, &ch(), 0, &cfg_exact).is_some());

        let cfg_tight = PresenceConfig {
            proximity_threshold: 9.999,
            ..Default::default()
        };
        assert!(execute_presence_protocol(&a, &b, &ch(), 0, &cfg_tight).is_none());
    }

    #[test]
    fn protocol_same_identity_both_sides_still_verifies() {
        // Degenerate but legal: one key answering both challenges.
        let ia = Identity::from_seed([3; 32]);
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 0.0), &ia, 2);
        let record =
            execute_presence_protocol(&a, &b, &ch(), 1, &PresenceConfig::default()).unwrap();
        assert_eq!(verify_record(&record), VerifyResult::Valid);
    }
}
