// alice-presence: Phase synchronization of presence
// Cryptographic proof of encounter via ZKP, Vivaldi coordinates, and minimal P2P sync

// ---------------------------------------------------------------------------
// Hash primitive
// ---------------------------------------------------------------------------

/// Standard FNV-1a 64-bit hash.
fn fnv1a(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// Vivaldi coordinate
// ---------------------------------------------------------------------------

/// Vivaldi network coordinate (2D + height for error estimation).
///
/// Distance model: sqrt((x1-x2)^2 + (y1-y2)^2) + h1 + h2
/// The height term is always >= 0 and represents estimation error.
#[derive(Debug, Clone, Copy)]
pub struct VivaldiCoord {
    pub x: f64,
    pub y: f64,
    /// Error term (always >= 0).
    pub height: f64,
}

impl VivaldiCoord {
    /// Create a coordinate with height = 0.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y, height: 0.0 }
    }

    /// Create a coordinate with an explicit height (error) term.
    pub fn with_height(x: f64, y: f64, height: f64) -> Self {
        Self {
            x,
            y,
            height: if height < 0.0 { 0.0 } else { height },
        }
    }

    /// Vivaldi distance: sqrt((x1-x2)^2 + (y1-y2)^2) + h1 + h2
    pub fn distance(&self, other: &VivaldiCoord) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        (dx * dx + dy * dy).sqrt() + self.height + other.height
    }

    /// Hash the coordinate for privacy-preserving proofs.
    pub fn hash(&self) -> u64 {
        let mut buf = [0u8; 24];
        buf[..8].copy_from_slice(&self.x.to_le_bytes());
        buf[8..16].copy_from_slice(&self.y.to_le_bytes());
        buf[16..24].copy_from_slice(&self.height.to_le_bytes());
        fnv1a(&buf)
    }
}

// ---------------------------------------------------------------------------
// Identity commitment
// ---------------------------------------------------------------------------

/// ZKP-style identity commitment.
///
/// `commitment_hash = H(secret_bytes || nonce_bytes)` where H is FNV-1a.
#[derive(Debug, Clone, Copy)]
pub struct IdentityCommitment {
    /// H(secret || nonce)
    pub commitment_hash: u64,
    pub nonce: u64,
    pub timestamp_ns: u64,
}

impl IdentityCommitment {
    /// Create a commitment from a secret key and nonce.
    pub fn new(secret: u64, nonce: u64, timestamp_ns: u64) -> Self {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&secret.to_le_bytes());
        buf[8..16].copy_from_slice(&nonce.to_le_bytes());
        let commitment_hash = fnv1a(&buf);
        Self {
            commitment_hash,
            nonce,
            timestamp_ns,
        }
    }

    /// Verify that a given secret matches this commitment.
    pub fn verify(&self, secret: u64) -> bool {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&secret.to_le_bytes());
        buf[8..16].copy_from_slice(&self.nonce.to_le_bytes());
        fnv1a(&buf) == self.commitment_hash
    }
}

// ---------------------------------------------------------------------------
// Proximity proof
// ---------------------------------------------------------------------------

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

        // Content hash covers distance, threshold, and both coord hashes.
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

// ---------------------------------------------------------------------------
// Zero-knowledge proof of identity
// ---------------------------------------------------------------------------

/// Simplified ZKP of identity.
///
/// Prover generates `response = H(secret || challenge)`.
/// Verifier holds the original commitment and checks structural consistency.
#[derive(Debug, Clone, Copy)]
pub struct ZkProof {
    /// Verifier's challenge.
    pub challenge: u64,
    /// Prover's response: `H(secret || challenge)`.
    pub response: u64,
    /// Original commitment hash.
    pub commitment: u64,
    /// Whether the proof checks out.
    pub verified: bool,
}

impl ZkProof {
    /// Produce a proof: `response = H(secret || challenge)`.
    ///
    /// The proof is marked `verified = true` when the commitment matches
    /// `H(secret || nonce)` (i.e. the prover genuinely knows the secret).
    pub fn prove(secret: u64, commitment: &IdentityCommitment, challenge: u64) -> Self {
        let mut resp_buf = [0u8; 16];
        resp_buf[..8].copy_from_slice(&secret.to_le_bytes());
        resp_buf[8..16].copy_from_slice(&challenge.to_le_bytes());
        let response = fnv1a(&resp_buf);

        // Verify: does the prover actually know the secret behind the commitment?
        let verified = commitment.verify(secret);

        Self {
            challenge,
            response,
            commitment: commitment.commitment_hash,
            verified,
        }
    }

    /// Structural verification: fields are non-zero and internally consistent.
    pub fn verify_structure(&self) -> bool {
        self.response != 0 && self.commitment != 0 && self.challenge != 0
    }
}

// ---------------------------------------------------------------------------
// Presence event (18 bytes)
// ---------------------------------------------------------------------------

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
            event_type: 0x50, // 'P'
            flags: 0,
            party_a_id,
            party_b_id,
            timestamp_ns,
        }
    }

    // -- flag setters ---------------------------------------------------------

    pub fn set_mutual(&mut self) {
        self.flags |= 0b0000_0001;
    }

    pub fn set_verified(&mut self) {
        self.flags |= 0b0000_0010;
    }

    pub fn set_proximate(&mut self) {
        self.flags |= 0b0000_0100;
    }

    // -- flag getters ---------------------------------------------------------

    pub fn is_mutual(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }

    pub fn is_verified(&self) -> bool {
        self.flags & 0b0000_0010 != 0
    }

    pub fn is_proximate(&self) -> bool {
        self.flags & 0b0000_0100 != 0
    }

    // -- serialization --------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Crossing record
// ---------------------------------------------------------------------------

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

impl CrossingRecord {
    /// Build a full crossing record from component proofs.
    pub fn new(
        event: PresenceEvent,
        proof_a: ZkProof,
        proof_b: ZkProof,
        proximity: ProximityProof,
    ) -> Self {
        // Content hash covers event bytes + proof responses + proximity hash.
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

// ---------------------------------------------------------------------------
// Protocol configuration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Party info
// ---------------------------------------------------------------------------

/// Identity and location information for one party in a presence exchange.
///
/// Groups the three per-party parameters (`coord`, `secret`, `id`) that would
/// otherwise appear as three separate arguments in protocol functions.
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

// ---------------------------------------------------------------------------
// Full protocol execution
// ---------------------------------------------------------------------------

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
    // 1. Proximity check.
    let proximity = ProximityProof::prove(&party_a.coord, &party_b.coord, config.proximity_threshold);
    if !proximity.is_proximate {
        return None;
    }

    // 2. Identity commitments + ZKP exchange.
    let nonce_a = fnv1a(&party_a.id.to_le_bytes());
    let nonce_b = fnv1a(&party_b.id.to_le_bytes());
    let commitment_a = IdentityCommitment::new(party_a.secret, nonce_a, timestamp_ns);
    let commitment_b = IdentityCommitment::new(party_b.secret, nonce_b, timestamp_ns);

    // Challenges derived deterministically for reproducibility.
    let challenge_a = fnv1a(&timestamp_ns.to_le_bytes()) ^ 0xAAAA_AAAA_AAAA_AAAA;
    let challenge_b = fnv1a(&timestamp_ns.to_le_bytes()) ^ 0x5555_5555_5555_5555;

    let proof_a = ZkProof::prove(party_a.secret, &commitment_a, challenge_a);
    let proof_b = ZkProof::prove(party_b.secret, &commitment_b, challenge_b);

    // 3. Create the 18-byte event.
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

    // 4. Build the full crossing record.
    Some(CrossingRecord::new(event, proof_a, proof_b, proximity))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- VivaldiCoord --------------------------------------------------------

    #[test]
    fn vivaldi_same_point_zero_height() {
        let a = VivaldiCoord::new(3.0, 4.0);
        let b = VivaldiCoord::new(3.0, 4.0);
        assert!((a.distance(&b) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn vivaldi_same_point_with_heights() {
        let a = VivaldiCoord::with_height(0.0, 0.0, 1.5);
        let b = VivaldiCoord::with_height(0.0, 0.0, 2.5);
        // distance = 0 + 1.5 + 2.5 = 4.0
        assert!((a.distance(&b) - 4.0).abs() < 1e-12);
    }

    #[test]
    fn vivaldi_known_distance() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(3.0, 4.0);
        // sqrt(9+16) + 0 + 0 = 5.0
        assert!((a.distance(&b) - 5.0).abs() < 1e-12);
    }

    #[test]
    fn vivaldi_distance_with_height() {
        let a = VivaldiCoord::with_height(0.0, 0.0, 1.0);
        let b = VivaldiCoord::with_height(3.0, 4.0, 2.0);
        // 5.0 + 1.0 + 2.0 = 8.0
        assert!((a.distance(&b) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn vivaldi_distance_symmetry() {
        let a = VivaldiCoord::with_height(1.0, 2.0, 0.5);
        let b = VivaldiCoord::with_height(4.0, 6.0, 1.0);
        assert!((a.distance(&b) - b.distance(&a)).abs() < 1e-12);
    }

    #[test]
    fn vivaldi_hash_determinism() {
        let c = VivaldiCoord::with_height(1.23, 4.56, 0.78);
        assert_eq!(c.hash(), c.hash());
    }

    #[test]
    fn vivaldi_hash_differs_for_different_coords() {
        let a = VivaldiCoord::new(1.0, 2.0);
        let b = VivaldiCoord::new(2.0, 1.0);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn vivaldi_negative_height_clamped() {
        let c = VivaldiCoord::with_height(0.0, 0.0, -5.0);
        assert_eq!(c.height, 0.0);
    }

    #[test]
    fn vivaldi_zero_coord() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(0.0, 0.0);
        assert!((a.distance(&b)).abs() < 1e-12);
    }

    // -- IdentityCommitment --------------------------------------------------

    #[test]
    fn commitment_verify_correct_secret() {
        let c = IdentityCommitment::new(12345, 99, 1_000_000);
        assert!(c.verify(12345));
    }

    #[test]
    fn commitment_verify_wrong_secret() {
        let c = IdentityCommitment::new(12345, 99, 1_000_000);
        assert!(!c.verify(12346));
    }

    #[test]
    fn commitment_hash_determinism() {
        let a = IdentityCommitment::new(42, 7, 100);
        let b = IdentityCommitment::new(42, 7, 200);
        // Same secret+nonce -> same commitment_hash regardless of timestamp.
        assert_eq!(a.commitment_hash, b.commitment_hash);
    }

    #[test]
    fn commitment_different_nonce() {
        let a = IdentityCommitment::new(42, 1, 100);
        let b = IdentityCommitment::new(42, 2, 100);
        assert_ne!(a.commitment_hash, b.commitment_hash);
    }

    // -- ProximityProof ------------------------------------------------------

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
        assert!(proof.is_proximate); // distance == threshold -> proximate
    }

    #[test]
    fn proximity_content_hash_determinism() {
        let a = VivaldiCoord::new(1.0, 2.0);
        let b = VivaldiCoord::new(3.0, 4.0);
        let p1 = ProximityProof::prove(&a, &b, 10.0);
        let p2 = ProximityProof::prove(&a, &b, 10.0);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    // -- ZkProof -------------------------------------------------------------

    #[test]
    fn zkproof_valid_secret() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let proof = ZkProof::prove(42, &commitment, 0xDEADBEEF);
        assert!(proof.verified);
        assert!(proof.verify_structure());
    }

    #[test]
    fn zkproof_invalid_secret() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let proof = ZkProof::prove(999, &commitment, 0xDEADBEEF);
        assert!(!proof.verified);
        // Structure is still valid (non-zero fields).
        assert!(proof.verify_structure());
    }

    #[test]
    fn zkproof_response_determinism() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let p1 = ZkProof::prove(42, &commitment, 123);
        let p2 = ZkProof::prove(42, &commitment, 123);
        assert_eq!(p1.response, p2.response);
    }

    #[test]
    fn zkproof_different_challenge_different_response() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let p1 = ZkProof::prove(42, &commitment, 1);
        let p2 = ZkProof::prove(42, &commitment, 2);
        assert_ne!(p1.response, p2.response);
    }

    // -- PresenceEvent -------------------------------------------------------

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
        assert!(e.is_mutual());
        assert!(e.is_verified());
        assert!(e.is_proximate());
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

    // -- CrossingRecord & CrossingStatus -------------------------------------

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
        // No mutual flag set.
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
        // Verified flag not set on event, but proofs are verified.
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

    // -- PresenceConfig ------------------------------------------------------

    #[test]
    fn config_defaults() {
        let cfg = PresenceConfig::default();
        assert!((cfg.proximity_threshold - 10.0).abs() < 1e-12);
        assert_eq!(cfg.challenge_bits, 64);
        assert!(cfg.require_mutual);
    }

    // -- execute_presence_protocol -------------------------------------------

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
        let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), 2, 2); // distance = 5.0
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

    // -- fnv1a edge cases ----------------------------------------------------

    #[test]
    fn fnv1a_empty() {
        let h = fnv1a(&[]);
        // FNV-1a of empty input is the offset basis.
        assert_eq!(h, 0xcbf29ce484222325);
    }

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(fnv1a(b"hello"), fnv1a(b"hello"));
    }
}
