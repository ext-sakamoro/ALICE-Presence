//! バイナリシリアライズ — `CrossingRecord` / `ProximityProof` の保存/復元。
//!
//! 外部依存ゼロの固定フォーマット。マジックナンバーで識別。

use crate::event::{CrossingRecord, PresenceEvent, ProximityProof};
use crate::identity::ChallengeProof;

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

// ── ChallengeProof: 32 + 32 + 64 = 128 bytes (magic なし、inline) ──

const PROOF_SIZE: usize = ChallengeProof::SIZE;

fn deserialize_proof(data: &[u8]) -> Option<ChallengeProof> {
    let bytes: &[u8; PROOF_SIZE] = data.get(..PROOF_SIZE)?.try_into().ok()?;
    Some(ChallengeProof::from_bytes(bytes))
}

// ── CrossingRecord: 4 + 18 + 128*2 + 41 + 8 = 327 bytes ──
// proximity は magic なしで inline 埋め込み (41 bytes)
// 復元した record は署名未検証、必ず verification::verify_record を通す

/// `CrossingRecord` の固定バイトサイズ。
pub const CROSSING_RECORD_SIZE: usize = 4 + 18 + PROOF_SIZE * 2 + 41 + 8;

/// `CrossingRecord` をバイト列にシリアライズ。
#[must_use]
pub fn serialize_crossing(record: &CrossingRecord) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CROSSING_RECORD_SIZE);
    buf.extend_from_slice(&MAGIC_CROSS);
    // PresenceEvent (18 bytes)
    buf.extend_from_slice(&record.event.to_bytes());
    // ChallengeProof A / B (128 bytes each)
    buf.extend_from_slice(&record.proof_a.to_bytes());
    buf.extend_from_slice(&record.proof_b.to_bytes());
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

    // ChallengeProof A / B
    let proof_a = deserialize_proof(&data[off..off + PROOF_SIZE])?;
    off += PROOF_SIZE;
    let proof_b = deserialize_proof(&data[off..off + PROOF_SIZE])?;
    off += PROOF_SIZE;

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
    use crate::identity::Identity;
    use crate::protocol::{
        execute_presence_protocol, ExchangeChallenges, PartyInfo, PresenceConfig,
    };
    use crate::vivaldi::VivaldiCoord;

    fn make_record() -> CrossingRecord {
        let ia = Identity::from_seed([1; 32]);
        let ib = Identity::from_seed([2; 32]);
        let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
        let b = PartyInfo::new(VivaldiCoord::new(1.0, 0.0), &ib, 2);
        execute_presence_protocol(
            &a,
            &b,
            &ExchangeChallenges::from_seed([3; 32]),
            100,
            &PresenceConfig::default(),
        )
        .unwrap()
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
        assert_eq!(restored.proof_a, record.proof_a);
        assert_eq!(restored.proof_b, record.proof_b);
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
        // 4 + 18 + 128*2 + 41 + 8 = 327
        assert_eq!(CROSSING_RECORD_SIZE, 327);
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
