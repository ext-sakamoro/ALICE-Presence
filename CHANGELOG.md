# Changelog

All notable changes to ALICE-Presence will be documented in this file.

## [0.2.0] - 2026-09-16

### Security

The 0.1.x "ZKP-style" identity layer did not authenticate anything: `ZkProof::verify_structure` only checked that fields were non-zero, `ZkProof::verified` was a `pub bool` written by the prover and read back by the verifier, commitments and content hashes used FNV-1a (non-cryptographic, invertible) over a `u64` secret. Any party could construct a record that passed `verify_record` without knowing a secret. This release replaces that design.

### Changed (breaking)

- `identity`: `IdentityCommitment` / `ZkProof` removed. New `Identity` (Ed25519 signing key, `generate` / `from_seed`, `Debug` prints the public key only), `Challenge` (32-byte verifier nonce, `random` / `from_seed`), `ChallengeProof { public_key, challenge, signature }` with `prove` / `verify` / `verify_with_key` (`verify_strict`, domain-separated message `ALICE-Presence/v2/cp || challenge || transcript`), `ProofError`, `PublicKey`.
- `protocol`: `PartyInfo` now borrows an `&Identity` instead of carrying a `u64` secret; `execute_presence_protocol` takes `&ExchangeChallenges` (one challenge per direction, drawn by the verifying side); `PresenceConfig::challenge_bits` removed. Both parties sign the same `encounter_transcript` (event with the verified bit cleared, proximity payload, both public keys, both challenges); `event.verified` is set only after each side verified the other's proof.
- `event`: `CrossingRecord::is_fully_verified` removed (it read the prover-written flag). Added `encounter_transcript`, `CrossingRecord::transcript` / `compute_content_hash`, `ProximityProof::canonical_bytes` / `content_hash_matches`, `PresenceEvent::FLAG_VERIFIED` / `to_bytes_unverified`. `CrossingStatus::Verified` is no longer produced by `status()` (Initiated → Mutual → Recorded).
- `verification`: `verify_record` checks both signatures over the record's transcript first, then proximity, then identifier hashes. `VerifyResult::ZkpNotVerified` replaced by `SignatureInvalidA` / `SignatureInvalidB` / `KeyMismatch`. New `verify_record_with_keys` pins the expected public keys.
- `serialize`: proofs are 128 bytes each; `CROSSING_RECORD_SIZE` 121 → 327. Magic bytes unchanged.
- Shared hash: `fnv1a` → `hash64` (first 8 bytes of BLAKE3). `session_id`, `coord_hash_*`, group `content_hash`, replay nonces are identifiers only and documented as such.
- Dependencies: `ed25519-dalek 2`, `blake3 1`, `rand_core 0.6` (`getrandom`).
- Crate description / keywords / docs no longer claim ZKP or zero-knowledge; README gains a "Security model" section.

### Added

- `tests/adversarial.rs` — 20 attacker-perspective tests (forged signatures, key substitution, impersonation under another party id, proof splicing across encounters, replay under a fresh challenge, post-signing tampering of every transcript field, serialized bit flips, deserialized-but-unverified records).

## [0.1.0] - 2026-02-23

### Added
- `vivaldi` — Vivaldi network coordinate system (2D + height)
- `identity` — identity commitments and zero-knowledge proof structures
- `event` — proximity events, crossing records, presence proofs
- `protocol` — end-to-end presence protocol with distance check + ZKP verification
- `session` — session FSM (Idle → Discovered → Exchanging → Verified → Closed)
- `group` — multi-party group proximity detection and batch proofs
- `spatial` — KD-tree spatial index with range query support
- FNV-1a shared hash primitive
- 89 unit tests + 1 doc-test
