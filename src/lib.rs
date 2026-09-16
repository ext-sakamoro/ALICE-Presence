// テストコードではリテラルやf32比較でpedantic警告が出るため抑制
#![cfg_attr(test, allow(clippy::unreadable_literal, clippy::float_cmp,))]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::module_name_repetitions,
    clippy::inline_always,
    clippy::too_many_lines
)]

//! ALICE-Presence — Phase synchronization of presence
//!
//! Proof of encounter via Ed25519 challenge-response, Vivaldi coordinates,
//! and minimal P2P sync. Provides session FSM, group proximity,
//! and spatial indexing for efficient multi-party presence detection.
//!
//! # Security model (read this before relying on a record)
//!
//! What a verified [`CrossingRecord`] proves:
//!
//! - Both parties hold the Ed25519 private key behind the public key stored in
//!   their [`ChallengeProof`], and each of them signed the *same* transcript
//!   (party ids, timestamp, proximity payload, both public keys, both
//!   challenges). Tampering with any of those after signing invalidates the
//!   signatures; splicing a proof from another encounter fails because the
//!   transcript (and the verifier-issued challenge) differ.
//! - Verification is done by the verifier — there is no self-reported
//!   "verified" field anywhere in the record.
//!
//! What it does **not** prove:
//!
//! - It is **not zero-knowledge**: both public keys are part of the record.
//! - Proximity is a mutual *attestation* of self-reported Vivaldi coordinates,
//!   not distance bounding. A party can lie about its own coordinate.
//! - The `content_hash` / `coord_hash_*` / `session_id` values are BLAKE3
//!   derived identifiers for de-duplication and storage; they authenticate
//!   nothing. Integrity comes from the two signatures only.
//! - Identity binding to a real person / device is out of scope: the verifier
//!   must learn the expected public keys out of band and use
//!   [`verification::verify_record_with_keys`].
//!
//! # Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`event`] | Proximity events, crossing records, presence proofs |
//! | [`group`] | Group proximity detection and multi-party proofs |
//! | [`identity`] | Ed25519 identities, verifier challenges, challenge-response proofs |
//! | [`protocol`] | End-to-end presence protocol execution |
//! | [`verification`] | Verifier-side record checks (signatures, proximity, ids) |
//! | [`session`] | Session FSM (Idle → Discovered → Exchanging → Verified → Closed) |
//! | [`spatial`] | KD-tree spatial index for range queries |
//! | [`vivaldi`] | Vivaldi network coordinate system |
//!
//! # Quick Start
//!
//! ```rust
//! use alice_presence::{
//!     execute_presence_protocol, verify_record, ExchangeChallenges, Identity, PartyInfo,
//!     PresenceConfig, VerifyResult, VivaldiCoord,
//! };
//!
//! let id_a = Identity::from_seed([1u8; 32]);
//! let id_b = Identity::from_seed([2u8; 32]);
//! let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &id_a, 1);
//! let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), &id_b, 2);
//! // In a real exchange each side draws its challenge with `ExchangeChallenges::random()`.
//! let challenges = ExchangeChallenges::from_seed([7u8; 32]);
//! let cfg = PresenceConfig::default();
//!
//! let record = execute_presence_protocol(&a, &b, &challenges, 1000, &cfg).unwrap();
//! assert_eq!(verify_record(&record), VerifyResult::Valid);
//! ```

pub mod event;
pub mod group;
pub mod identity;
pub mod protocol;
pub mod replay_guard;
pub mod serialize;
pub mod session;
pub mod spatial;
pub mod verification;
pub mod vivaldi;

pub use event::{CrossingRecord, CrossingStatus, PresenceEvent, ProximityProof};
pub use group::{GroupConfig, GroupProximityProof, PresenceGroup};
pub use identity::{Challenge, ChallengeProof, Identity, ProofError, PublicKey};
pub use protocol::{execute_presence_protocol, ExchangeChallenges, PartyInfo, PresenceConfig};
pub use session::{CloseReason, Session, SessionConfig, SessionState};
pub use spatial::{KdTree, SpatialEntry};
pub use verification::{verify_record, verify_record_with_keys, VerifyResult};
pub use vivaldi::VivaldiCoord;

// ── Shared hash primitive ──────────────────────────────────────────────

/// 64-bit identifier hash: the first 8 bytes of BLAKE3.
///
/// Used for `session_id` / `coord_hash_*` / `content_hash` / replay nonces.
/// These are **identifiers** (de-duplication, storage keys), not
/// authentication: nothing in this crate treats a matching `hash64` as proof
/// of anything. Integrity of a record comes from its Ed25519 signatures.
#[inline]
#[must_use]
pub(crate) fn hash64(data: &[u8]) -> u64 {
    let digest = blake3::hash(data);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

// ── Integration tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash64_is_blake3_prefix() {
        let h = hash64(b"hello");
        let full = blake3::hash(b"hello");
        assert_eq!(h.to_le_bytes(), full.as_bytes()[..8]);
    }

    #[test]
    fn hash64_deterministic_and_input_sensitive() {
        assert_eq!(hash64(b"hello"), hash64(b"hello"));
        assert_ne!(hash64(b"hello"), hash64(b"hellp"));
        assert_ne!(hash64(&[]), 0);
    }

    #[test]
    fn end_to_end_protocol_with_session() {
        // Full flow: session FSM + protocol execution
        let mut sess = Session::new(1, 1000, SessionConfig::default());
        assert!(sess.discover(2, 2000));

        let id_a = Identity::from_seed([1u8; 32]);
        let id_b = Identity::from_seed([2u8; 32]);
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &id_a, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), &id_b, 2);
        let cfg = PresenceConfig::default();
        let challenges = ExchangeChallenges::from_seed([9u8; 32]);

        // Proximity OK → begin exchange
        assert!(sess.begin_exchange(3000));

        let record = execute_presence_protocol(&a, &b, &challenges, 3000, &cfg).unwrap();
        assert_eq!(verify_record(&record), VerifyResult::Valid);

        // both signatures OK → verified
        assert!(sess.verify(4000));
        assert!(sess.close(CloseReason::Success, 5000));
        assert_eq!(sess.state, SessionState::Closed);
    }

    #[test]
    fn end_to_end_group_spatial() {
        // Build spatial index, range query, then group proof
        let entries = vec![
            SpatialEntry {
                id: 1,
                coord: VivaldiCoord::new(0.0, 0.0),
            },
            SpatialEntry {
                id: 2,
                coord: VivaldiCoord::new(1.0, 0.0),
            },
            SpatialEntry {
                id: 3,
                coord: VivaldiCoord::new(0.0, 1.0),
            },
            SpatialEntry {
                id: 4,
                coord: VivaldiCoord::new(100.0, 100.0),
            },
        ];
        let tree = KdTree::build(&entries);

        // Range query from origin with radius 5
        let nearby = tree.range_query(&VivaldiCoord::new(0.0, 0.0), 5.0);
        assert_eq!(nearby.len(), 3); // ids 1, 2, 3

        // Build group from nearby entries
        let mut group = PresenceGroup::new(GroupConfig {
            proximity_threshold: 5.0,
            min_members: 2,
        });
        for (id, _dist) in &nearby {
            let e = entries.iter().find(|e| e.id == *id).unwrap();
            group.add_member(e.id, e.coord, 0);
        }
        let proof = group.prove_proximity().unwrap();
        assert!(proof.all_proximate);
        assert_eq!(proof.member_count, 3);
    }
}
