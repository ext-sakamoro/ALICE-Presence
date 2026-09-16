//! Adversarial tests — "can I make `verify_record` say Valid without the
//! private key?"
//!
//! Every test here plays an attacker (Mallory) who has everything except the
//! parties' private keys: the public keys, old valid records, the wire format,
//! the source code. Each test asserts that the attack is rejected. This is the
//! test class the 0.1 design had none of.
//!
//! Author: Moroya Sakamoto

use alice_presence::event::{encounter_transcript, PresenceEvent};
use alice_presence::serialize::{deserialize_crossing, serialize_crossing};
use alice_presence::{
    execute_presence_protocol, verify_record, verify_record_with_keys, Challenge, ChallengeProof,
    CrossingRecord, ExchangeChallenges, Identity, PartyInfo, PresenceConfig, ProofError,
    VerifyResult, VivaldiCoord,
};

fn alice() -> Identity {
    Identity::from_seed([0xA1; 32])
}
fn bob() -> Identity {
    Identity::from_seed([0xB0; 32])
}
fn mallory() -> Identity {
    Identity::from_seed([0x4A; 32])
}

fn honest_record(seed: u8, ts: u64) -> CrossingRecord {
    let ia = alice();
    let ib = bob();
    let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &ia, 1);
    let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
    execute_presence_protocol(
        &a,
        &b,
        &ExchangeChallenges::from_seed([seed; 32]),
        ts,
        &PresenceConfig::default(),
    )
    .expect("proximate")
}

#[test]
fn honest_record_is_valid_baseline() {
    let r = honest_record(1, 1000);
    assert_eq!(verify_record(&r), VerifyResult::Valid);
    assert_eq!(
        verify_record_with_keys(&r, &alice().public_key(), &bob().public_key()),
        VerifyResult::Valid
    );
}

// ── 1. Forgery without any key ─────────────────────────────────────────

#[test]
fn forged_proof_with_zero_signature_fails() {
    let mut r = honest_record(1, 1000);
    r.proof_a.signature = [0u8; 64];
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn forged_proof_with_random_looking_signature_fails() {
    let mut r = honest_record(1, 1000);
    for (i, b) in r.proof_b.signature.iter_mut().enumerate() {
        *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(0x9d) ^ 0x5a;
    }
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidB);
}

#[test]
fn the_old_self_declared_verified_field_no_longer_exists() {
    // In 0.1 an attacker could write `ZkProof { verified: true, .. }` and the
    // verifier believed it. There is no such field now: every field of a
    // ChallengeProof is covered by the signature check.
    let ch = Challenge::from_seed([1; 32]);
    let fake = ChallengeProof {
        public_key: mallory().public_key(),
        challenge: ch,
        signature: [1u8; 64],
    };
    assert_eq!(
        fake.verify(&ch, b"anything"),
        Err(ProofError::InvalidSignature)
    );
}

// ── 2. Impersonation: Mallory signs with her own key, claims Alice's id ─

#[test]
fn mallory_cannot_impersonate_alice_when_keys_are_pinned() {
    let im = mallory();
    let ib = bob();
    // Mallory runs the protocol with Bob using Alice's party id (1).
    let m = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &im, 1);
    let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
    let r = execute_presence_protocol(
        &m,
        &b,
        &ExchangeChallenges::from_seed([2; 32]),
        1000,
        &PresenceConfig::default(),
    )
    .unwrap();
    // The record is internally consistent (Mallory really did sign it) …
    assert_eq!(verify_record(&r), VerifyResult::Valid);
    // … but it is not a record about Alice: pinning Alice's key rejects it.
    assert_eq!(
        verify_record_with_keys(&r, &alice().public_key(), &ib.public_key()),
        VerifyResult::KeyMismatch
    );
}

#[test]
fn swapping_in_alices_public_key_after_signing_fails() {
    // Mallory takes her own valid record and just overwrites the key bytes
    // with Alice's, hoping the verifier compares keys but not signatures.
    let im = mallory();
    let ib = bob();
    let m = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &im, 1);
    let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
    let mut r = execute_presence_protocol(
        &m,
        &b,
        &ExchangeChallenges::from_seed([2; 32]),
        1000,
        &PresenceConfig::default(),
    )
    .unwrap();
    r.proof_a.public_key = alice().public_key();
    assert_eq!(
        verify_record_with_keys(&r, &alice().public_key(), &ib.public_key()),
        VerifyResult::SignatureInvalidA
    );
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

// ── 3. Replay: reuse a proof from an old encounter ─────────────────────

#[test]
fn proof_from_old_encounter_cannot_be_spliced_into_new_one() {
    let old = honest_record(1, 1000);
    // New exchange: Bob issues a fresh challenge to "Alice" (really Mallory,
    // who only has Alice's old proof).
    let ib = bob();
    let im = mallory();
    let m = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &im, 1);
    let b = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), &ib, 2);
    let fresh = ExchangeChallenges::from_seed([9; 32]);
    let mut new =
        execute_presence_protocol(&m, &b, &fresh, 2000, &PresenceConfig::default()).unwrap();
    // Splice Alice's old proof in place of Mallory's.
    new.proof_a = old.proof_a;
    // The record now carries Alice's real key and a real signature by Alice,
    // but over the *old* transcript (old timestamp / old challenges), so the
    // recomputed transcript does not match.
    assert_eq!(verify_record(&new), VerifyResult::SignatureInvalidA);
    assert_eq!(
        verify_record_with_keys(&new, &alice().public_key(), &ib.public_key()),
        VerifyResult::SignatureInvalidA
    );
}

#[test]
fn proof_answering_a_different_challenge_is_rejected_by_verifier() {
    // Direct check at the proof level: Bob issued X, the proof answers Y.
    let ia = alice();
    let issued = Challenge::from_seed([0x11; 32]);
    let answered = Challenge::from_seed([0x22; 32]);
    let proof = ChallengeProof::prove(&ia, answered, b"transcript");
    assert_eq!(
        proof.verify(&issued, b"transcript"),
        Err(ProofError::ChallengeMismatch)
    );
}

#[test]
fn replaying_whole_old_record_under_new_challenge_fails() {
    // Verifier (Bob) remembers the challenge he issued this time and checks
    // the stored proof against it, as `execute_presence_protocol` does.
    let old = honest_record(1, 1000);
    let issued_now = Challenge::from_seed([0x77; 32]);
    let t = old.transcript();
    assert_eq!(
        old.proof_a.verify(&issued_now, &t),
        Err(ProofError::ChallengeMismatch)
    );
}

// ── 4. Tampering after signing ─────────────────────────────────────────

#[test]
fn tampering_timestamp_fails() {
    let mut r = honest_record(1, 1000);
    r.event.timestamp_ns = 999_999;
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn tampering_party_ids_fails() {
    let mut r = honest_record(1, 1000);
    r.event.party_b_id = 42;
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn tampering_mutual_flag_fails() {
    let mut r = honest_record(1, 1000);
    r.event.flags &= !0b1; // clear mutual
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn tampering_distance_fails() {
    let mut r = honest_record(1, 1000);
    r.proximity.distance = 0.0;
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn tampering_coordinate_hash_fails() {
    let mut r = honest_record(1, 1000);
    r.proximity.coord_hash_b ^= 1;
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn flipping_not_proximate_to_proximate_fails() {
    // Build a signed "not proximate" record by hand, then flip the bit.
    let ia = alice();
    let ib = bob();
    let prox = alice_presence::ProximityProof::prove(
        &VivaldiCoord::new(0.0, 0.0),
        &VivaldiCoord::new(100.0, 0.0),
        1.0,
    );
    assert!(!prox.is_proximate);
    let event = PresenceEvent::new(1, 2, 5);
    let ca = Challenge::from_seed([1; 32]);
    let cb = Challenge::from_seed([2; 32]);
    let t = encounter_transcript(&event, &prox, &ia.public_key(), &ib.public_key(), &ca, &cb);
    let mut r = CrossingRecord::new(
        event,
        ChallengeProof::prove(&ia, ca, &t),
        ChallengeProof::prove(&ib, cb, &t),
        prox,
    );
    assert_eq!(verify_record(&r), VerifyResult::NotProximate);
    r.proximity.is_proximate = true;
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn tampering_counterpart_challenge_fails() {
    // Both challenges are in the transcript, so even the challenge the *other*
    // party answered is protected by my signature.
    let mut r = honest_record(1, 1000);
    r.proof_b.challenge = Challenge::from_seed([0xEE; 32]);
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

#[test]
fn only_the_verified_flag_is_outside_the_signature() {
    // Setting `verified` on a record the protocol left unverified does not
    // break signatures (it is a post-verification summary) — and it does not
    // make an invalid record valid either.
    let mut r = honest_record(1, 1000);
    r.proof_a.signature[0] ^= 1;
    r.event.set_verified();
    assert_eq!(verify_record(&r), VerifyResult::SignatureInvalidA);
}

// ── 5. Through the wire format ─────────────────────────────────────────

#[test]
fn tampering_serialized_bytes_fails_after_deserialize() {
    let r = honest_record(1, 1000);
    let mut bytes = serialize_crossing(&r);
    let clean = deserialize_crossing(&bytes).unwrap();
    assert_eq!(verify_record(&clean), VerifyResult::Valid);

    // Flip one bit inside the timestamp (offset 4 + 10).
    bytes[4 + 10] ^= 0x01;
    let dirty = deserialize_crossing(&bytes).unwrap();
    assert_eq!(verify_record(&dirty), VerifyResult::SignatureInvalidA);
}

#[test]
fn deserialized_record_is_not_trusted_until_verified() {
    // A record assembled from arbitrary bytes deserializes fine (the format
    // has no way to know) and is rejected by verification.
    let mut bytes = vec![0u8; alice_presence::serialize::CROSSING_RECORD_SIZE];
    bytes[..4].copy_from_slice(b"ACRS");
    let r = deserialize_crossing(&bytes).unwrap();
    assert_ne!(verify_record(&r), VerifyResult::Valid);
}

// ── 6. Key space sanity ────────────────────────────────────────────────

#[test]
fn identity_is_a_full_ed25519_key_not_u64() {
    let id = alice();
    assert_eq!(id.public_key().len(), 32);
    let r = honest_record(1, 1000);
    assert_eq!(r.proof_a.signature.len(), 64);
    // Two nearby seeds give unrelated keys (no small-integer secret space).
    let k1 = Identity::from_seed([0; 32]).public_key();
    let mut seed2 = [0u8; 32];
    seed2[0] = 1;
    let k2 = Identity::from_seed(seed2).public_key();
    let differing = k1.iter().zip(k2.iter()).filter(|(a, b)| a != b).count();
    assert!(differing > 16, "keys share too many bytes: {differing}");
}
