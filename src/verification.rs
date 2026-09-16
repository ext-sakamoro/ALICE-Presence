//! Verifier-side checks for `CrossingRecord`
//!
//! A record is trusted only after this module says so. The order of checks
//! is deliberate: the two Ed25519 signatures are what authenticate the
//! record; the identifier hashes are checked last and only guard against
//! storage corruption.
//!
//! Author: Moroya Sakamoto

use crate::event::{CrossingRecord, ProximityProof};
use crate::identity::PublicKey;

/// Outcome of [`verify_record`] / [`verify_record_with_keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Both signatures verify over the record's transcript, the parties were
    /// proximate, and the identifier hashes are consistent.
    Valid,
    /// Party A's proof does not verify (wrong key, wrong challenge, or the
    /// transcript was altered after signing).
    SignatureInvalidA,
    /// Party B's proof does not verify.
    SignatureInvalidB,
    /// A public key inside the record differs from the one the verifier
    /// expected ([`verify_record_with_keys`] only).
    KeyMismatch,
    /// Proximity was not attested.
    NotProximate,
    /// An identifier hash (`content_hash` of the record or the proximity
    /// payload) does not match its payload — storage corruption or a
    /// half-applied edit. Signatures already passed at this point.
    HashMismatch,
}

/// Recompute the `ProximityProof` identifier hash.
#[must_use]
pub fn verify_proximity(proof: &ProximityProof) -> bool {
    proof.content_hash_matches()
}

/// Recompute the `CrossingRecord` identifier hash.
#[must_use]
pub fn verify_record_hash(record: &CrossingRecord) -> bool {
    record.compute_content_hash() == record.content_hash
}

/// Full verification against whatever keys the record carries.
///
/// Use this when the verifier is one of the two parties (it already knows
/// the counterpart's key from the exchange) or when any two valid keys are
/// acceptable. To pin the keys, use [`verify_record_with_keys`].
#[must_use]
pub fn verify_record(record: &CrossingRecord) -> VerifyResult {
    let transcript = record.transcript();
    if record
        .proof_a
        .verify(&record.proof_a.challenge, &transcript)
        .is_err()
    {
        return VerifyResult::SignatureInvalidA;
    }
    if record
        .proof_b
        .verify(&record.proof_b.challenge, &transcript)
        .is_err()
    {
        return VerifyResult::SignatureInvalidB;
    }
    if !record.proximity.is_proximate {
        return VerifyResult::NotProximate;
    }
    if !verify_proximity(&record.proximity) || !verify_record_hash(record) {
        return VerifyResult::HashMismatch;
    }
    VerifyResult::Valid
}

/// [`verify_record`] plus a requirement that the keys inside the record are
/// exactly `expected_a` / `expected_b` (learned out of band).
///
/// This is the check that stops an attacker from presenting a record made
/// with their *own* keys while claiming the party ids of someone else: the
/// ids are just `u32` labels, the keys are the identity.
#[must_use]
pub fn verify_record_with_keys(
    record: &CrossingRecord,
    expected_a: &PublicKey,
    expected_b: &PublicKey,
) -> VerifyResult {
    if record.proof_a.public_key != *expected_a || record.proof_b.public_key != *expected_b {
        return VerifyResult::KeyMismatch;
    }
    verify_record(record)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::protocol::{
        execute_presence_protocol, ExchangeChallenges, PartyInfo, PresenceConfig,
    };
    use crate::vivaldi::VivaldiCoord;

    fn ids() -> (Identity, Identity) {
        (Identity::from_seed([1; 32]), Identity::from_seed([2; 32]))
    }

    fn make_valid_record(ia: &Identity, ib: &Identity) -> CrossingRecord {
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 0.0), ib, 2);
        execute_presence_protocol(
            &a,
            &b,
            &ExchangeChallenges::from_seed([5; 32]),
            100,
            &PresenceConfig::default(),
        )
        .unwrap()
    }

    #[test]
    fn valid_record() {
        let (ia, ib) = ids();
        let record = make_valid_record(&ia, &ib);
        assert_eq!(verify_record(&record), VerifyResult::Valid);
        assert_eq!(
            verify_record_with_keys(&record, &ia.public_key(), &ib.public_key()),
            VerifyResult::Valid
        );
    }

    #[test]
    fn valid_record_hash() {
        let (ia, ib) = ids();
        assert!(verify_record_hash(&make_valid_record(&ia, &ib)));
    }

    #[test]
    fn valid_proximity_hash() {
        let prox = ProximityProof::prove(
            &VivaldiCoord::new(0.0, 0.0),
            &VivaldiCoord::new(1.0, 0.0),
            10.0,
        );
        assert!(verify_proximity(&prox));
    }

    #[test]
    fn tampered_record_hash() {
        let (ia, ib) = ids();
        let mut record = make_valid_record(&ia, &ib);
        record.content_hash ^= 0xDEAD;
        assert_eq!(verify_record(&record), VerifyResult::HashMismatch);
    }

    #[test]
    fn tampered_proximity_hash_only() {
        let (ia, ib) = ids();
        let mut record = make_valid_record(&ia, &ib);
        record.proximity.content_hash ^= 1;
        // proximity.content_hash is not in the transcript, so signatures still
        // pass and the identifier check catches it.
        assert_eq!(verify_record(&record), VerifyResult::HashMismatch);
    }

    #[test]
    fn tampered_proximity_payload_breaks_signatures() {
        let (ia, ib) = ids();
        let mut record = make_valid_record(&ia, &ib);
        record.proximity.distance = 0.0;
        assert_eq!(verify_record(&record), VerifyResult::SignatureInvalidA);
    }

    #[test]
    fn not_proximate_record_from_parts() {
        // Build a record whose proximity says "not proximate" but is signed
        // consistently — verify must still reject it.
        use crate::event::{encounter_transcript, PresenceEvent};
        use crate::identity::{Challenge, ChallengeProof};
        let (ia, ib) = ids();
        let prox = ProximityProof::prove(
            &VivaldiCoord::new(0.0, 0.0),
            &VivaldiCoord::new(100.0, 0.0),
            1.0,
        );
        let event = PresenceEvent::new(1, 2, 100);
        let ca = Challenge::from_seed([1; 32]);
        let cb = Challenge::from_seed([2; 32]);
        let t = encounter_transcript(&event, &prox, &ia.public_key(), &ib.public_key(), &ca, &cb);
        let record = CrossingRecord::new(
            event,
            ChallengeProof::prove(&ia, ca, &t),
            ChallengeProof::prove(&ib, cb, &t),
            prox,
        );
        assert_eq!(verify_record(&record), VerifyResult::NotProximate);
    }

    #[test]
    fn key_mismatch() {
        let (ia, ib) = ids();
        let record = make_valid_record(&ia, &ib);
        let other = Identity::from_seed([9; 32]).public_key();
        assert_eq!(
            verify_record_with_keys(&record, &other, &ib.public_key()),
            VerifyResult::KeyMismatch
        );
        assert_eq!(
            verify_record_with_keys(&record, &ia.public_key(), &other),
            VerifyResult::KeyMismatch
        );
    }

    #[test]
    fn verify_result_eq() {
        assert_eq!(VerifyResult::Valid, VerifyResult::Valid);
        assert_ne!(VerifyResult::Valid, VerifyResult::HashMismatch);
    }

    #[test]
    fn verify_record_hash_false_on_tamper() {
        let (ia, ib) = ids();
        let mut record = make_valid_record(&ia, &ib);
        record.content_hash = 0;
        assert!(!verify_record_hash(&record));
    }
}
