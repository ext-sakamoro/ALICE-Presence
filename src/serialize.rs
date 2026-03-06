//! バイナリシリアライズ — `CrossingRecord` / `ProximityProof` の保存/復元。
//!
//! 外部依存ゼロの固定フォーマット。マジックナンバーで識別。

use crate::event::{CrossingRecord, PresenceEvent, ProximityProof};
use crate::identity::ZkProof;

/// `ProximityProof` マジック。
const MAGIC_PROX: [u8; 4] = *b"APRX";
/// `CrossingRecord` マジック。
const MAGIC_CROSS: [u8; 4] = *b"ACRS";

// ── ProximityProof: 4 + 8*5 + 1 = 45 bytes ──

/// `ProximityProof` をバイト列にシリアライズ。
#[must_use]
pub fn serialize_proximity(proof: &ProximityProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(45);
    buf.extend_from_slice(&MAGIC_PROX);
    buf.extend_from_slice(&proof.distance.to_le_bytes());
    buf.extend_from_slice(&proof.threshold.to_le_bytes());
    buf.push(u8::from(proof.is_proximate));
    buf.extend_from_slice(&proof.coord_hash_a.to_le_bytes());
    buf.extend_from_slice(&proof.coord_hash_b.to_le_bytes());
    buf.extend_from_slice(&proof.content_hash.to_le_bytes());
    buf
}

/// バイト列から `ProximityProof` を復元。
#[must_use]
pub fn deserialize_proximity(data: &[u8]) -> Option<ProximityProof> {
    if data.len() < 45 || data[..4] != MAGIC_PROX {
        return None;
    }
    let distance = f64::from_le_bytes(data[4..12].try_into().ok()?);
    let threshold = f64::from_le_bytes(data[12..20].try_into().ok()?);
    let is_proximate = data[20] != 0;
    let coord_hash_a = u64::from_le_bytes(data[21..29].try_into().ok()?);
    let coord_hash_b = u64::from_le_bytes(data[29..37].try_into().ok()?);
    let content_hash = u64::from_le_bytes(data[37..45].try_into().ok()?);

    Some(ProximityProof {
        distance,
        threshold,
        is_proximate,
        coord_hash_a,
        coord_hash_b,
        content_hash,
    })
}

// ── ZkProof helper: 8 + 8 + 8 + 1 = 25 bytes ──

const ZKPROOF_SIZE: usize = 25;

fn serialize_zkproof(proof: &ZkProof, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&proof.challenge.to_le_bytes());
    buf.extend_from_slice(&proof.response.to_le_bytes());
    buf.extend_from_slice(&proof.commitment.to_le_bytes());
    buf.push(u8::from(proof.verified));
}

fn deserialize_zkproof(data: &[u8]) -> Option<ZkProof> {
    if data.len() < ZKPROOF_SIZE {
        return None;
    }
    let challenge = u64::from_le_bytes(data[..8].try_into().ok()?);
    let response = u64::from_le_bytes(data[8..16].try_into().ok()?);
    let commitment = u64::from_le_bytes(data[16..24].try_into().ok()?);
    let verified = data[24] != 0;
    Some(ZkProof {
        challenge,
        response,
        commitment,
        verified,
    })
}

// ── CrossingRecord: 4 + 18 + 25*2 + 41 + 8 = 121 bytes ──
// proximity は magic なしで inline 埋め込み (41 bytes)

/// `CrossingRecord` の固定バイトサイズ。
pub const CROSSING_RECORD_SIZE: usize = 4 + 18 + ZKPROOF_SIZE * 2 + 41 + 8;

/// `CrossingRecord` をバイト列にシリアライズ。
#[must_use]
pub fn serialize_crossing(record: &CrossingRecord) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CROSSING_RECORD_SIZE);
    buf.extend_from_slice(&MAGIC_CROSS);
    // PresenceEvent (18 bytes)
    buf.extend_from_slice(&record.event.to_bytes());
    // ZkProof A (17 bytes)
    serialize_zkproof(&record.proof_a, &mut buf);
    // ZkProof B (17 bytes)
    serialize_zkproof(&record.proof_b, &mut buf);
    // ProximityProof inline (41 bytes, magic なし)
    buf.extend_from_slice(&record.proximity.distance.to_le_bytes());
    buf.extend_from_slice(&record.proximity.threshold.to_le_bytes());
    buf.push(u8::from(record.proximity.is_proximate));
    buf.extend_from_slice(&record.proximity.coord_hash_a.to_le_bytes());
    buf.extend_from_slice(&record.proximity.coord_hash_b.to_le_bytes());
    buf.extend_from_slice(&record.proximity.content_hash.to_le_bytes());
    // content_hash (8 bytes)
    buf.extend_from_slice(&record.content_hash.to_le_bytes());
    buf
}

/// バイト列から `CrossingRecord` を復元。
#[must_use]
pub fn deserialize_crossing(data: &[u8]) -> Option<CrossingRecord> {
    if data.len() < CROSSING_RECORD_SIZE || data[..4] != MAGIC_CROSS {
        return None;
    }
    let mut off = 4;

    // PresenceEvent (18 bytes)
    let ev_bytes: &[u8; 18] = data[off..off + 18].try_into().ok()?;
    let event = PresenceEvent::from_bytes(ev_bytes);
    off += 18;

    // ZkProof A
    let proof_a = deserialize_zkproof(&data[off..off + ZKPROOF_SIZE])?;
    off += ZKPROOF_SIZE;

    // ZkProof B
    let proof_b = deserialize_zkproof(&data[off..off + ZKPROOF_SIZE])?;
    off += ZKPROOF_SIZE;

    // ProximityProof inline (41 bytes)
    let distance = f64::from_le_bytes(data[off..off + 8].try_into().ok()?);
    off += 8;
    let threshold = f64::from_le_bytes(data[off..off + 8].try_into().ok()?);
    off += 8;
    let is_proximate = data[off] != 0;
    off += 1;
    let coord_hash_a = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
    off += 8;
    let coord_hash_b = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
    off += 8;
    let prox_content_hash = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
    off += 8;

    let proximity = ProximityProof {
        distance,
        threshold,
        is_proximate,
        coord_hash_a,
        coord_hash_b,
        content_hash: prox_content_hash,
    };

    let content_hash = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);

    Some(CrossingRecord {
        event,
        proof_a,
        proof_b,
        proximity,
        content_hash,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityCommitment;
    use crate::vivaldi::VivaldiCoord;

    fn make_record() -> CrossingRecord {
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
        CrossingRecord::new(event, pa, pb, prox)
    }

    #[test]
    fn proximity_roundtrip() {
        let a = VivaldiCoord::new(1.5, 2.5);
        let b = VivaldiCoord::new(3.5, 4.5);
        let proof = ProximityProof::prove(&a, &b, 10.0);
        let bytes = serialize_proximity(&proof);
        assert_eq!(bytes.len(), 45);
        let restored = deserialize_proximity(&bytes).unwrap();
        assert!((restored.distance - proof.distance).abs() < 1e-12);
        assert!((restored.threshold - proof.threshold).abs() < 1e-12);
        assert_eq!(restored.is_proximate, proof.is_proximate);
        assert_eq!(restored.coord_hash_a, proof.coord_hash_a);
        assert_eq!(restored.coord_hash_b, proof.coord_hash_b);
        assert_eq!(restored.content_hash, proof.content_hash);
    }

    #[test]
    fn proximity_invalid_magic() {
        let mut bytes = serialize_proximity(&ProximityProof::prove(
            &VivaldiCoord::new(0.0, 0.0),
            &VivaldiCoord::new(1.0, 0.0),
            10.0,
        ));
        bytes[0] = b'X';
        assert!(deserialize_proximity(&bytes).is_none());
    }

    #[test]
    fn proximity_too_short() {
        assert!(deserialize_proximity(&[0; 10]).is_none());
    }

    #[test]
    fn crossing_roundtrip() {
        let record = make_record();
        let bytes = serialize_crossing(&record);
        assert_eq!(bytes.len(), CROSSING_RECORD_SIZE);
        let restored = deserialize_crossing(&bytes).unwrap();
        assert_eq!(restored.event.party_a_id, record.event.party_a_id);
        assert_eq!(restored.event.party_b_id, record.event.party_b_id);
        assert_eq!(restored.event.timestamp_ns, record.event.timestamp_ns);
        assert_eq!(restored.event.flags, record.event.flags);
        assert_eq!(restored.proof_a.verified, record.proof_a.verified);
        assert_eq!(restored.proof_b.verified, record.proof_b.verified);
        assert_eq!(restored.proof_a.response, record.proof_a.response);
        assert_eq!(restored.proof_b.response, record.proof_b.response);
        assert_eq!(restored.content_hash, record.content_hash);
        assert!((restored.proximity.distance - record.proximity.distance).abs() < 1e-12);
    }

    #[test]
    fn crossing_invalid_magic() {
        let mut bytes = serialize_crossing(&make_record());
        bytes[0] = b'Z';
        assert!(deserialize_crossing(&bytes).is_none());
    }

    #[test]
    fn crossing_too_short() {
        assert!(deserialize_crossing(&[0; 10]).is_none());
    }

    #[test]
    fn crossing_record_size_constant() {
        // 4 + 18 + 25*2 + 41 + 8 = 121
        assert_eq!(CROSSING_RECORD_SIZE, 121);
    }

    #[test]
    fn crossing_roundtrip_preserves_verification() {
        let record = make_record();
        let bytes = serialize_crossing(&record);
        let restored = deserialize_crossing(&bytes).unwrap();
        // verification モジュールで検証可能
        assert_eq!(
            crate::verification::verify_record(&restored),
            crate::verification::VerifyResult::Valid
        );
    }

    #[test]
    fn proximity_not_proximate_roundtrip() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(100.0, 0.0);
        let proof = ProximityProof::prove(&a, &b, 1.0);
        assert!(!proof.is_proximate);
        let bytes = serialize_proximity(&proof);
        let restored = deserialize_proximity(&bytes).unwrap();
        assert!(!restored.is_proximate);
    }
}
