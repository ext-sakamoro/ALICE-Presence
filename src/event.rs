//! Presence events and crossing records
//!
//! Minimal 18-byte presence events for P2P sync and permanent
//! crossing records with ZKP verification.
//!
//! Author: Moroya Sakamoto

use crate::fnv1a;
use crate::identity::ZkProof;
use crate::vivaldi::VivaldiCoord;

// ── Proximity Proof ────────────────────────────────────────────────────

/// Evidence that two Vivaldi coordinates are within threshold distance.
#[derive(Debug, Clone, Copy)]
pub struct ProximityProof {
    /// Vivaldi distance between the two parties.
    pub distance: f64,
    /// Maximum distance for "proximity".
    pub threshold: f64,
    /// `distance <= threshold`
    pub is_proximate: bool,
    /// Hash of party A's coordinate (privacy).
    pub coord_hash_a: u64,
    /// Hash of party B's coordinate (privacy).
    pub coord_hash_b: u64,
    /// Hash of the entire proof payload.
    pub content_hash: u64,
}

impl ProximityProof {
    /// Generate a proximity proof between two coordinates.
    pub fn prove(coord_a: &VivaldiCoord, coord_b: &VivaldiCoord, threshold: f64) -> Self {
        let distance = coord_a.distance(coord_b);
        let is_proximate = distance <= threshold;
        let coord_hash_a = coord_a.hash();
        let coord_hash_b = coord_b.hash();

        let mut buf = [0u8; 40];
        buf[..8].copy_from_slice(&distance.to_le_bytes());
        buf[8..16].copy_from_slice(&threshold.to_le_bytes());
        buf[16..24].copy_from_slice(&coord_hash_a.to_le_bytes());
        buf[24..32].copy_from_slice(&coord_hash_b.to_le_bytes());
        buf[32..40].copy_from_slice(&(is_proximate as u64).to_le_bytes());
        let content_hash = fnv1a(&buf);

        Self {
            distance,
            threshold,
            is_proximate,
            coord_hash_a,
            coord_hash_b,
            content_hash,
        }
    }
}

// ── Presence Event (18 bytes) ──────────────────────────────────────────

/// Minimal 18-byte presence event for P2P sync (ALICE-Sync compatible).
///
/// Wire layout: `[event_type: u8][flags: u8][party_a_id: u32 LE][party_b_id: u32 LE][timestamp: u64 LE]`
#[derive(Debug, Clone, Copy)]
pub struct PresenceEvent {
    /// 0x50 = 'P' for Presence.
    pub event_type: u8,
    /// bit 0: mutual, bit 1: verified, bit 2: proximate.
    pub flags: u8,
    /// Compact ID for party A.
    pub party_a_id: u32,
    /// Compact ID for party B.
    pub party_b_id: u32,
    /// Nanosecond timestamp of the crossing.
    pub timestamp_ns: u64,
}

impl PresenceEvent {
    /// Create a new presence event with default flags.
    pub fn new(party_a_id: u32, party_b_id: u32, timestamp_ns: u64) -> Self {
        Self {
            event_type: 0x50,
            flags: 0,
            party_a_id,
            party_b_id,
            timestamp_ns,
        }
    }

    pub fn set_mutual(&mut self) {
        self.flags |= 0b0000_0001;
    }

    pub fn set_verified(&mut self) {
        self.flags |= 0b0000_0010;
    }

    pub fn set_proximate(&mut self) {
        self.flags |= 0b0000_0100;
    }

    pub fn is_mutual(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }

    pub fn is_verified(&self) -> bool {
        self.flags & 0b0000_0010 != 0
    }

    pub fn is_proximate(&self) -> bool {
        self.flags & 0b0000_0100 != 0
    }

    /// Serialize to exactly 18 bytes.
    pub fn to_bytes(&self) -> [u8; 18] {
        let mut out = [0u8; 18];
        out[0] = self.event_type;
        out[1] = self.flags;
        out[2..6].copy_from_slice(&self.party_a_id.to_le_bytes());
        out[6..10].copy_from_slice(&self.party_b_id.to_le_bytes());
        out[10..18].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        out
    }

    /// Deserialize from exactly 18 bytes.
    pub fn from_bytes(bytes: &[u8; 18]) -> Self {
        let event_type = bytes[0];
        let flags = bytes[1];
        let party_a_id = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let party_b_id = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let timestamp_ns = u64::from_le_bytes([
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17],
        ]);
        Self {
            event_type,
            flags,
            party_a_id,
            party_b_id,
            timestamp_ns,
        }
    }

    /// Wire size (always 18).
    pub fn byte_size() -> usize {
        18
    }
}

// ── Crossing Status ────────────────────────────────────────────────────

/// Crossing status state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossingStatus {
    /// One party started.
    Initiated,
    /// Both parties confirmed.
    Mutual,
    /// ZKP verified on both sides.
    Verified,
    /// Written to permanent store.
    Recorded,
    /// One party revoked.
    Revoked,
}

// ── Crossing Record ────────────────────────────────────────────────────

/// Permanent crossing record — the full record stored in DB.
#[derive(Debug, Clone, Copy)]
pub struct CrossingRecord {
    pub event: PresenceEvent,
    /// Party A's identity proof.
    pub proof_a: ZkProof,
    /// Party B's identity proof.
    pub proof_b: ZkProof,
    pub proximity: ProximityProof,
    /// Hash of the entire record.
    pub content_hash: u64,
}

impl CrossingRecord {
    /// Build a full crossing record from component proofs.
    pub fn new(
        event: PresenceEvent,
        proof_a: ZkProof,
        proof_b: ZkProof,
        proximity: ProximityProof,
    ) -> Self {
        let ev_bytes = event.to_bytes();
        let mut buf = Vec::with_capacity(18 + 8 * 4);
        buf.extend_from_slice(&ev_bytes);
        buf.extend_from_slice(&proof_a.response.to_le_bytes());
        buf.extend_from_slice(&proof_b.response.to_le_bytes());
        buf.extend_from_slice(&proximity.content_hash.to_le_bytes());
        buf.extend_from_slice(&proximity.distance.to_le_bytes());
        let content_hash = fnv1a(&buf);

        Self {
            event,
            proof_a,
            proof_b,
            proximity,
            content_hash,
        }
    }

    /// Fully verified: both ZKPs verified + proximity confirmed.
    pub fn is_fully_verified(&self) -> bool {
        self.proof_a.verified && self.proof_b.verified && self.proximity.is_proximate
    }

    /// Derive the crossing status from the current state of the record.
    pub fn status(&self) -> CrossingStatus {
        if !self.event.is_mutual() {
            return CrossingStatus::Initiated;
        }
        if !self.proof_a.verified || !self.proof_b.verified {
            return CrossingStatus::Mutual;
        }
        if !self.event.is_verified() {
            return CrossingStatus::Verified;
        }
        CrossingStatus::Recorded
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityCommitment;

    #[test]
    fn proximity_within_threshold() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let proof = ProximityProof::prove(&a, &b, 10.0);
        assert!(proof.is_proximate);
        assert!((proof.distance - 1.0).abs() < 1e-12);
    }

    #[test]
    fn proximity_beyond_threshold() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(100.0, 0.0);
        let proof = ProximityProof::prove(&a, &b, 10.0);
        assert!(!proof.is_proximate);
    }

    #[test]
    fn proximity_exact_threshold() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(10.0, 0.0);
        let proof = ProximityProof::prove(&a, &b, 10.0);
        assert!(proof.is_proximate);
    }

    #[test]
    fn proximity_content_hash_determinism() {
        let a = VivaldiCoord::new(1.0, 2.0);
        let b = VivaldiCoord::new(3.0, 4.0);
        let p1 = ProximityProof::prove(&a, &b, 10.0);
        let p2 = ProximityProof::prove(&a, &b, 10.0);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn event_byte_size() {
        assert_eq!(PresenceEvent::byte_size(), 18);
    }

    #[test]
    fn event_creation() {
        let e = PresenceEvent::new(1, 2, 1000);
        assert_eq!(e.event_type, 0x50);
        assert_eq!(e.flags, 0);
        assert_eq!(e.party_a_id, 1);
        assert_eq!(e.party_b_id, 2);
        assert_eq!(e.timestamp_ns, 1000);
    }

    #[test]
    fn event_roundtrip() {
        let mut e = PresenceEvent::new(0xAABBCCDD, 0x11223344, 0xDEAD_BEEF_CAFE_BABE);
        e.set_mutual();
        e.set_verified();
        e.set_proximate();
        let bytes = e.to_bytes();
        assert_eq!(bytes.len(), 18);
        let e2 = PresenceEvent::from_bytes(&bytes);
        assert_eq!(e2.event_type, e.event_type);
        assert_eq!(e2.flags, e.flags);
        assert_eq!(e2.party_a_id, e.party_a_id);
        assert_eq!(e2.party_b_id, e.party_b_id);
        assert_eq!(e2.timestamp_ns, e.timestamp_ns);
    }

    #[test]
    fn event_flags_mutual() {
        let mut e = PresenceEvent::new(1, 2, 0);
        assert!(!e.is_mutual());
        e.set_mutual();
        assert!(e.is_mutual());
        assert!(!e.is_verified());
        assert!(!e.is_proximate());
    }

    #[test]
    fn event_flags_verified() {
        let mut e = PresenceEvent::new(1, 2, 0);
        assert!(!e.is_verified());
        e.set_verified();
        assert!(e.is_verified());
        assert!(!e.is_mutual());
    }

    #[test]
    fn event_flags_proximate() {
        let mut e = PresenceEvent::new(1, 2, 0);
        assert!(!e.is_proximate());
        e.set_proximate();
        assert!(e.is_proximate());
    }

    #[test]
    fn event_all_flags() {
        let mut e = PresenceEvent::new(1, 2, 0);
        e.set_mutual();
        e.set_verified();
        e.set_proximate();
        assert_eq!(e.flags, 0b0000_0111);
    }

    #[test]
    fn event_max_ids() {
        let e = PresenceEvent::new(u32::MAX, u32::MAX, u64::MAX);
        let bytes = e.to_bytes();
        let e2 = PresenceEvent::from_bytes(&bytes);
        assert_eq!(e2.party_a_id, u32::MAX);
        assert_eq!(e2.party_b_id, u32::MAX);
        assert_eq!(e2.timestamp_ns, u64::MAX);
    }

    #[test]
    fn event_zero_timestamp() {
        let e = PresenceEvent::new(0, 0, 0);
        let bytes = e.to_bytes();
        let e2 = PresenceEvent::from_bytes(&bytes);
        assert_eq!(e2.timestamp_ns, 0);
        assert_eq!(e2.party_a_id, 0);
    }

    #[test]
    fn crossing_fully_verified() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        let ca = IdentityCommitment::new(42, 1, 100);
        let cb = IdentityCommitment::new(99, 2, 100);
        let pa = ZkProof::prove(42, &ca, 0xAA);
        let pb = ZkProof::prove(99, &cb, 0xBB);
        let mut event = PresenceEvent::new(1, 2, 100);
        event.set_mutual();
        event.set_verified();
        event.set_proximate();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert!(record.is_fully_verified());
        assert_eq!(record.status(), CrossingStatus::Recorded);
    }

    #[test]
    fn crossing_not_mutual() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        let ca = IdentityCommitment::new(42, 1, 100);
        let cb = IdentityCommitment::new(99, 2, 100);
        let pa = ZkProof::prove(42, &ca, 0xAA);
        let pb = ZkProof::prove(99, &cb, 0xBB);
        let event = PresenceEvent::new(1, 2, 100);
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(record.status(), CrossingStatus::Initiated);
    }

    #[test]
    fn crossing_mutual_but_not_verified_flag() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        let ca = IdentityCommitment::new(42, 1, 100);
        let cb = IdentityCommitment::new(99, 2, 100);
        let pa = ZkProof::prove(42, &ca, 0xAA);
        let pb = ZkProof::prove(99, &cb, 0xBB);
        let mut event = PresenceEvent::new(1, 2, 100);
        event.set_mutual();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(record.status(), CrossingStatus::Verified);
    }

    #[test]
    fn crossing_content_hash_nonzero() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        let ca = IdentityCommitment::new(1, 1, 0);
        let cb = IdentityCommitment::new(2, 2, 0);
        let pa = ZkProof::prove(1, &ca, 10);
        let pb = ZkProof::prove(2, &cb, 20);
        let event = PresenceEvent::new(1, 2, 0);
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_ne!(record.content_hash, 0);
    }
}
