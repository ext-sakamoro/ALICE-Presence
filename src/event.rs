//! Presence events and crossing records
//!
//! Minimal 18-byte presence events for P2P sync and permanent
//! crossing records carrying both parties' Ed25519 challenge-response proofs.
//!
//! Author: Moroya Sakamoto

use crate::hash64;
use crate::identity::{Challenge, ChallengeProof, PublicKey};
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
    /// `hash64` of [`Self::canonical_bytes`] — an identifier, not authentication.
    pub content_hash: u64,
}

impl ProximityProof {
    /// Generate a proximity proof between two coordinates.
    #[must_use]
    pub fn prove(coord_a: &VivaldiCoord, coord_b: &VivaldiCoord, threshold: f64) -> Self {
        let distance = coord_a.distance(coord_b);
        let is_proximate = distance <= threshold;
        let coord_hash_a = coord_a.hash();
        let coord_hash_b = coord_b.hash();
        let content_hash = hash64(&Self::payload_bytes(
            distance,
            threshold,
            coord_hash_a,
            coord_hash_b,
            is_proximate,
        ));

        Self {
            distance,
            threshold,
            is_proximate,
            coord_hash_a,
            coord_hash_b,
            content_hash,
        }
    }

    fn payload_bytes(
        distance: f64,
        threshold: f64,
        coord_hash_a: u64,
        coord_hash_b: u64,
        is_proximate: bool,
    ) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..8].copy_from_slice(&distance.to_le_bytes());
        buf[8..16].copy_from_slice(&threshold.to_le_bytes());
        buf[16..24].copy_from_slice(&coord_hash_a.to_le_bytes());
        buf[24..32].copy_from_slice(&coord_hash_b.to_le_bytes());
        buf[32..40].copy_from_slice(&u64::from(is_proximate).to_le_bytes());
        buf
    }

    /// Canonical 40-byte payload (everything except `content_hash`). This is
    /// what enters the signed transcript, so any change to distance /
    /// threshold / coordinate hashes / the proximate bit after signing is
    /// detected by signature verification.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 40] {
        Self::payload_bytes(
            self.distance,
            self.threshold,
            self.coord_hash_a,
            self.coord_hash_b,
            self.is_proximate,
        )
    }

    /// Recompute `content_hash` from the payload and compare.
    #[must_use]
    pub fn content_hash_matches(&self) -> bool {
        hash64(&self.canonical_bytes()) == self.content_hash
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
    #[must_use]
    pub const fn new(party_a_id: u32, party_b_id: u32, timestamp_ns: u64) -> Self {
        Self {
            event_type: 0x50,
            flags: 0,
            party_a_id,
            party_b_id,
            timestamp_ns,
        }
    }

    /// Flag bit set once both proofs were checked by the verifier.
    pub const FLAG_VERIFIED: u8 = 0b0000_0010;

    pub const fn set_mutual(&mut self) {
        self.flags |= 0b0000_0001;
    }

    pub const fn set_verified(&mut self) {
        self.flags |= Self::FLAG_VERIFIED;
    }

    pub const fn set_proximate(&mut self) {
        self.flags |= 0b0000_0100;
    }

    #[must_use]
    pub const fn is_mutual(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }

    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.flags & 0b0000_0010 != 0
    }

    #[must_use]
    pub const fn is_proximate(&self) -> bool {
        self.flags & 0b0000_0100 != 0
    }

    /// Serialize to exactly 18 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 18] {
        let mut out = [0u8; 18];
        out[0] = self.event_type;
        out[1] = self.flags;
        out[2..6].copy_from_slice(&self.party_a_id.to_le_bytes());
        out[6..10].copy_from_slice(&self.party_b_id.to_le_bytes());
        out[10..18].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        out
    }

    /// The 18 wire bytes with the `verified` flag cleared — the form that
    /// enters the signed transcript. `verified` is set *after* both signatures
    /// have been checked, so it cannot be part of what is signed.
    #[must_use]
    pub fn to_bytes_unverified(&self) -> [u8; 18] {
        let mut out = self.to_bytes();
        out[1] &= !Self::FLAG_VERIFIED;
        out
    }

    /// Deserialize from exactly 18 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: &[u8; 18]) -> Self {
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
    #[must_use]
    pub const fn byte_size() -> usize {
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
    /// Both signatures verified.
    Verified,
    /// Written to permanent store.
    Recorded,
    /// One party revoked.
    Revoked,
}

// ── Crossing Record ────────────────────────────────────────────────────

/// Bytes both parties sign for one encounter:
///
/// `event (18, verified bit cleared) || proximity canonical (40) || pk_a (32) || pk_b (32) || challenge_a (32) || challenge_b (32)`
///
/// Binding both keys and both challenges into what each side signs means a
/// proof cannot be lifted out of this record and reused with another
/// counterpart, timestamp or challenge.
#[must_use]
pub fn encounter_transcript(
    event: &PresenceEvent,
    proximity: &ProximityProof,
    pk_a: &PublicKey,
    pk_b: &PublicKey,
    challenge_a: &Challenge,
    challenge_b: &Challenge,
) -> [u8; 186] {
    let mut out = [0u8; 186];
    out[..18].copy_from_slice(&event.to_bytes_unverified());
    out[18..58].copy_from_slice(&proximity.canonical_bytes());
    out[58..90].copy_from_slice(pk_a);
    out[90..122].copy_from_slice(pk_b);
    out[122..154].copy_from_slice(challenge_a.as_bytes());
    out[154..186].copy_from_slice(challenge_b.as_bytes());
    out
}

/// Permanent crossing record — the full record stored in DB.
///
/// Nothing in this struct is self-certifying: call
/// [`crate::verification::verify_record`] before trusting it.
#[derive(Debug, Clone, Copy)]
pub struct CrossingRecord {
    pub event: PresenceEvent,
    /// Party A's challenge-response proof (answers the challenge B issued).
    pub proof_a: ChallengeProof,
    /// Party B's challenge-response proof (answers the challenge A issued).
    pub proof_b: ChallengeProof,
    pub proximity: ProximityProof,
    /// `hash64` over the transcript and both signatures — a storage /
    /// de-duplication identifier, not authentication.
    pub content_hash: u64,
}

impl CrossingRecord {
    /// Build a full crossing record from component proofs.
    #[must_use]
    pub fn new(
        event: PresenceEvent,
        proof_a: ChallengeProof,
        proof_b: ChallengeProof,
        proximity: ProximityProof,
    ) -> Self {
        let mut record = Self {
            event,
            proof_a,
            proof_b,
            proximity,
            content_hash: 0,
        };
        record.content_hash = record.compute_content_hash();
        record
    }

    /// The transcript both parties signed, rebuilt from the record's own
    /// fields (event, proximity, the keys and challenges inside the proofs).
    #[must_use]
    pub fn transcript(&self) -> [u8; 186] {
        encounter_transcript(
            &self.event,
            &self.proximity,
            &self.proof_a.public_key,
            &self.proof_b.public_key,
            &self.proof_a.challenge,
            &self.proof_b.challenge,
        )
    }

    /// Identifier hash over transcript + both signatures.
    #[must_use]
    pub fn compute_content_hash(&self) -> u64 {
        let mut buf = Vec::with_capacity(186 + 64 * 2);
        buf.extend_from_slice(&self.transcript());
        buf.extend_from_slice(&self.proof_a.signature);
        buf.extend_from_slice(&self.proof_b.signature);
        hash64(&buf)
    }

    /// Derive the crossing status from the event flags.
    ///
    /// The flags are set by the protocol runner *after* verification; they
    /// are a summary, not evidence. Verify the record before reading them.
    #[must_use]
    pub const fn status(&self) -> CrossingStatus {
        if !self.event.is_mutual() {
            return CrossingStatus::Initiated;
        }
        if !self.event.is_verified() {
            return CrossingStatus::Mutual;
        }
        CrossingStatus::Recorded
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

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

    fn proofs() -> (
        ChallengeProof,
        ChallengeProof,
        ProximityProof,
        PresenceEvent,
    ) {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        let id_a = Identity::from_seed([1; 32]);
        let id_b = Identity::from_seed([2; 32]);
        let ch_a = Challenge::from_seed([0xAA; 32]);
        let ch_b = Challenge::from_seed([0xBB; 32]);
        let event = PresenceEvent::new(1, 2, 100);
        let t = encounter_transcript(
            &event,
            &prox,
            &id_a.public_key(),
            &id_b.public_key(),
            &ch_a,
            &ch_b,
        );
        (
            ChallengeProof::prove(&id_a, ch_a, &t),
            ChallengeProof::prove(&id_b, ch_b, &t),
            prox,
            event,
        )
    }

    #[test]
    fn crossing_status_recorded() {
        let (pa, pb, prox, mut event) = proofs();
        event.set_mutual();
        event.set_verified();
        event.set_proximate();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(record.status(), CrossingStatus::Recorded);
    }

    #[test]
    fn crossing_not_mutual() {
        let (pa, pb, prox, event) = proofs();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(record.status(), CrossingStatus::Initiated);
    }

    #[test]
    fn crossing_mutual_but_not_verified_flag() {
        let (pa, pb, prox, mut event) = proofs();
        event.set_mutual();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(record.status(), CrossingStatus::Mutual);
    }

    #[test]
    fn crossing_content_hash_nonzero_and_recomputable() {
        let (pa, pb, prox, event) = proofs();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_ne!(record.content_hash, 0);
        assert_eq!(record.content_hash, record.compute_content_hash());
    }

    #[test]
    fn transcript_ignores_verified_flag_only() {
        let (pa, pb, prox, mut event) = proofs();
        let r0 = CrossingRecord::new(event, pa, pb, prox);
        event.set_verified();
        let r1 = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(r0.transcript(), r1.transcript());
        event.set_mutual();
        let r2 = CrossingRecord::new(event, pa, pb, prox);
        assert_ne!(r0.transcript(), r2.transcript());
    }

    #[test]
    fn proximity_canonical_bytes_match_content_hash() {
        let prox = ProximityProof::prove(
            &VivaldiCoord::new(1.0, 2.0),
            &VivaldiCoord::new(3.0, 4.0),
            10.0,
        );
        assert!(prox.content_hash_matches());
        let mut tampered = prox;
        tampered.distance += 1.0;
        assert!(!tampered.content_hash_matches());
    }
}
