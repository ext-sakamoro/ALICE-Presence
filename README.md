# alice-presence

Phase synchronization of presence — cryptographic proof of encounter via ZKP, Vivaldi coordinates, and minimal P2P sync.

Replaces business cards with a cryptographic protocol that proves two entities met, using zero-knowledge proofs and minimal 18-byte P2P sync events.

## Features

- Vivaldi network coordinates for proximity estimation
- Zero-knowledge identity proofs (FNV-1a commitment scheme)
- 18-byte presence events compatible with ALICE-Sync
- Full crossing records with mutual verification

## Example

```
cargo run --example presence_demo
```

- Case 1: Alice ↔ Bob (Vivaldi distance 5.0 ≤ threshold 10.0) — full CrossingRecord with mutual ZKP verification and 18-byte wire event
- Case 2: Alice ↔ Charlie (distance ≈113) — proximity fails, no record produced
- Case 3: 3-party group (Alice, Bob, Dora) — max pairwise 6.0, GroupProximityProof with `all_proximate=true`
- Case 4: adding a distant Charlie to the group — `all_proximate` collapses to false while the group proof still emits with `max_distance` breach

## Tests

35 tests covering coordinates, commitments, proofs, events, records, protocol execution, and edge cases.

```
cargo test
```
