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
//! Cryptographic proof of encounter via ZKP, Vivaldi coordinates,
//! and minimal P2P sync. Provides session FSM, group proximity,
//! and spatial indexing for efficient multi-party presence detection.
//!
//! # Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`event`] | Proximity events, crossing records, presence proofs |
//! | [`group`] | Group proximity detection and multi-party proofs |
//! | [`identity`] | Identity commitments and ZKP structures |
//! | [`protocol`] | End-to-end presence protocol execution |
//! | [`session`] | Session FSM (Idle → Discovered → Exchanging → Verified → Closed) |
//! | [`spatial`] | KD-tree spatial index for range queries |
//! | [`vivaldi`] | Vivaldi network coordinate system |
//!
//! # Quick Start
//!
//! ```rust
//! use alice_presence::{VivaldiCoord, PartyInfo, PresenceConfig, execute_presence_protocol};
//!
//! let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 42, 1);
//! let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), 99, 2);
//! let cfg = PresenceConfig::default();
//!
//! let record = execute_presence_protocol(&a, &b, 1000, &cfg).unwrap();
//! assert!(record.is_fully_verified());
//! ```

pub mod event;
pub mod group;
pub mod identity;
pub mod protocol;
pub mod session;
pub mod spatial;
pub mod vivaldi;

pub use event::{CrossingRecord, CrossingStatus, PresenceEvent, ProximityProof};
pub use group::{GroupConfig, GroupProximityProof, PresenceGroup};
pub use identity::{IdentityCommitment, ZkProof};
pub use protocol::{execute_presence_protocol, PartyInfo, PresenceConfig};
pub use session::{CloseReason, Session, SessionConfig, SessionState};
pub use spatial::{KdTree, SpatialEntry};
pub use vivaldi::VivaldiCoord;

// ── Shared hash primitive ──────────────────────────────────────────────

/// Standard FNV-1a 64-bit hash.
#[inline(always)]
pub(crate) fn fnv1a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// ── Integration tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_empty() {
        let h = fnv1a(&[]);
        assert_eq!(h, 0xcbf29ce484222325);
    }

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(fnv1a(b"hello"), fnv1a(b"hello"));
    }

    #[test]
    fn end_to_end_protocol_with_session() {
        // Full flow: session FSM + protocol execution
        let mut sess = Session::new(1, 1000, SessionConfig::default());
        assert!(sess.discover(2, 2000));

        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 42, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), 99, 2);
        let cfg = PresenceConfig::default();

        // Proximity OK → begin exchange
        assert!(sess.begin_exchange(3000));

        let record = execute_presence_protocol(&a, &b, 3000, &cfg).unwrap();
        assert!(record.is_fully_verified());

        // ZKP OK → verified
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
