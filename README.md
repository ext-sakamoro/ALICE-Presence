# alice-presence

Phase synchronization of presence — proof of encounter via Ed25519 challenge-response, Vivaldi coordinates, and minimal P2P sync.

Replaces business cards with a protocol in which two parties sign the same encounter transcript, each answering a challenge the *other* side drew, and ship the result as an 18-byte P2P sync event plus a verifiable crossing record.

## Features

- Vivaldi network coordinates for proximity estimation
- Ed25519 identities (`ed25519-dalek`) with verifier-issued 32-byte challenges — no self-reported "verified" flag anywhere
- Both parties sign one transcript (ids, timestamp, proximity payload, both public keys, both challenges) → tampering, replay and proof splicing are caught by signature verification
- 18-byte presence events compatible with ALICE-Sync
- Verifier-side `verify_record` / `verify_record_with_keys` (pin the counterpart's public key learned out of band)
- BLAKE3-derived 64-bit identifiers for records / coordinates / sessions (identifiers only, never authentication)

## Security model

What a `VerifyResult::Valid` record proves:

- Each party holds the private key behind the public key in its `ChallengeProof`, and both signed the *same* transcript. Changing any signed field after the fact (timestamp, party ids, distance, coordinate hashes, the proximate bit, either key, either challenge) invalidates at least one signature.
- A proof cannot be lifted out of one record and reused in another: the transcript and the verifier-issued challenge differ.

What it does **not** prove:

- It is **not zero-knowledge**. Both public keys are stored in the record.
- Proximity is a mutual *attestation* of self-reported Vivaldi coordinates, not distance bounding. A party can lie about where it is.
- `content_hash`, `coord_hash_*`, `session_id`, replay nonces and group proofs are unsigned identifiers. Group proofs in particular are not evidence.
- Binding a public key to a real person or device is out of scope; use `verify_record_with_keys` with keys you trust for another reason.
- Challenges must be drawn by the verifier with a CSPRNG (`ExchangeChallenges::random`). The `from_seed` constructors exist for deterministic tests only.

The 0.1.x design (FNV-1a "commitment", `u64` secrets, prover-written `verified: bool`) provided none of the above and is gone; see `CHANGELOG.md`.

## Quick start

```rust
use alice_presence::{
    execute_presence_protocol, verify_record, ExchangeChallenges, Identity, PartyInfo,
    PresenceConfig, VerifyResult, VivaldiCoord,
};

let id_a = Identity::generate(&mut rand_core::OsRng);
let id_b = Identity::generate(&mut rand_core::OsRng);
let a = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), &id_a, 1);
let b = PartyInfo::new(VivaldiCoord::new(1.0, 1.0), &id_b, 2);
let challenges = ExchangeChallenges::random(&mut rand_core::OsRng);

let record = execute_presence_protocol(&a, &b, &challenges, 1000, &PresenceConfig::default()).unwrap();
assert_eq!(verify_record(&record), VerifyResult::Valid);
```

## Example

```
cargo run --example presence_demo
```

- Case 1: Alice ↔ Bob (Vivaldi distance 5.0 ≤ threshold 10.0) — full CrossingRecord, `verify_record` / pinned-key verification, and a tampered copy rejected with `SignatureInvalidA`
- Case 2: Alice ↔ Charlie (distance ≈113) — proximity fails, no record produced
- Case 3: 3-party group (Alice, Bob, Dora) — max pairwise 6.0, GroupProximityProof with `all_proximate=true`
- Case 4: adding a distant Charlie to the group — `all_proximate` collapses to false while the group proof still emits with `max_distance` breach

## Tests

147 unit tests + 20 adversarial tests + 2 doctests.

`tests/adversarial.rs` is the part that matters for the crypto: every test plays an attacker with everything except the private keys (forged signatures, key substitution, impersonation under someone else's party id, splicing a proof from an old encounter, replay under a new challenge, post-signing edits of every transcript field, bit flips in the serialized form) and asserts the record is rejected.

```
cargo test
```
