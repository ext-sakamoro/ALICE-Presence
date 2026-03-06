//! Crossing record 完全性検証。
//!
//! `CrossingRecord` の content hash を再計算し、改ざんの有無を検出する。
//! また `ProximityProof` の content hash も独立検証可能。

use crate::event::{CrossingRecord, ProximityProof};
use crate::fnv1a;

/// 検証結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// content hash が一致。
    Valid,
    /// content hash 不一致（改ざん疑い）。
    HashMismatch,
    /// ZKP 未検証。
    ZkpNotVerified,
    /// 近接未確認。
    NotProximate,
}

/// `ProximityProof` の content hash を再計算し検証。
#[must_use]
pub fn verify_proximity(proof: &ProximityProof) -> bool {
    let mut buf = [0u8; 40];
    buf[..8].copy_from_slice(&proof.distance.to_le_bytes());
    buf[8..16].copy_from_slice(&proof.threshold.to_le_bytes());
    buf[16..24].copy_from_slice(&proof.coord_hash_a.to_le_bytes());
    buf[24..32].copy_from_slice(&proof.coord_hash_b.to_le_bytes());
    buf[32..40].copy_from_slice(&(proof.is_proximate as u64).to_le_bytes());
    let expected = fnv1a(&buf);
    expected == proof.content_hash
}

/// `CrossingRecord` の content hash を再計算し検証。
#[must_use]
pub fn verify_record_hash(record: &CrossingRecord) -> bool {
    let ev_bytes = record.event.to_bytes();
    let mut buf = Vec::with_capacity(18 + 8 * 4);
    buf.extend_from_slice(&ev_bytes);
    buf.extend_from_slice(&record.proof_a.response.to_le_bytes());
    buf.extend_from_slice(&record.proof_b.response.to_le_bytes());
    buf.extend_from_slice(&record.proximity.content_hash.to_le_bytes());
    buf.extend_from_slice(&record.proximity.distance.to_le_bytes());
    let expected = fnv1a(&buf);
    expected == record.content_hash
}

/// `CrossingRecord` の総合検証。
///
/// 1. content hash 一致
/// 2. 両方の ZKP が verified
/// 3. proximity が確認済み
/// 4. proximity proof の content hash も検証
#[must_use]
pub fn verify_record(record: &CrossingRecord) -> VerifyResult {
    if !verify_record_hash(record) {
        return VerifyResult::HashMismatch;
    }
    if !record.proof_a.verified || !record.proof_b.verified {
        return VerifyResult::ZkpNotVerified;
    }
    if !record.proximity.is_proximate {
        return VerifyResult::NotProximate;
    }
    if !verify_proximity(&record.proximity) {
        return VerifyResult::HashMismatch;
    }
    VerifyResult::Valid
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PresenceEvent;
    use crate::identity::{IdentityCommitment, ZkProof};
    use crate::vivaldi::VivaldiCoord;

    fn make_valid_record() -> CrossingRecord {
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
        CrossingRecord::new(event, pa, pb, prox)
    }

    #[test]
    fn valid_record() {
        let record = make_valid_record();
        assert_eq!(verify_record(&record), VerifyResult::Valid);
    }

    #[test]
    fn valid_record_hash() {
        let record = make_valid_record();
        assert!(verify_record_hash(&record));
    }

    #[test]
    fn valid_proximity_hash() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        assert!(verify_proximity(&prox));
    }

    #[test]
    fn tampered_record_hash() {
        let mut record = make_valid_record();
        record.content_hash ^= 0xDEAD; // 改ざん
        assert_eq!(verify_record(&record), VerifyResult::HashMismatch);
    }

    #[test]
    fn tampered_proximity_hash() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let mut prox = ProximityProof::prove(&a, &b, 10.0);
        prox.content_hash ^= 1; // 改ざん
        assert!(!verify_proximity(&prox));
    }

    #[test]
    fn zkp_not_verified() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(1.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 10.0);
        let ca = IdentityCommitment::new(42, 1, 100);
        let cb = IdentityCommitment::new(99, 2, 100);
        // 不正な秘密鍵で proof_a を作成 → verified = false
        let pa = ZkProof::prove(999, &ca, 0xAA);
        let pb = ZkProof::prove(99, &cb, 0xBB);
        let mut event = PresenceEvent::new(1, 2, 100);
        event.set_mutual();
        event.set_verified();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(verify_record(&record), VerifyResult::ZkpNotVerified);
    }

    #[test]
    fn not_proximate() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(100.0, 0.0);
        let prox = ProximityProof::prove(&a, &b, 1.0); // 範囲外
        let ca = IdentityCommitment::new(42, 1, 100);
        let cb = IdentityCommitment::new(99, 2, 100);
        let pa = ZkProof::prove(42, &ca, 0xAA);
        let pb = ZkProof::prove(99, &cb, 0xBB);
        let mut event = PresenceEvent::new(1, 2, 100);
        event.set_mutual();
        event.set_verified();
        let record = CrossingRecord::new(event, pa, pb, prox);
        assert_eq!(verify_record(&record), VerifyResult::NotProximate);
    }

    #[test]
    fn tampered_proximity_in_record() {
        let mut record = make_valid_record();
        record.proximity.content_hash ^= 1; // proximity hash 改ざん
        // record hash は再計算しないのでまず record hash が不一致
        assert_eq!(verify_record(&record), VerifyResult::HashMismatch);
    }

    #[test]
    fn verify_result_eq() {
        assert_eq!(VerifyResult::Valid, VerifyResult::Valid);
        assert_ne!(VerifyResult::Valid, VerifyResult::HashMismatch);
    }

    #[test]
    fn verify_record_hash_false_on_tamper() {
        let mut record = make_valid_record();
        record.content_hash = 0;
        assert!(!verify_record_hash(&record));
    }
}
