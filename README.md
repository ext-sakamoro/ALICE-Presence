# alice-presence

Phase synchronization of presence — cryptographic proof of encounter via ZKP, Vivaldi coordinates, and minimal P2P sync.

Replaces business cards with a cryptographic protocol that proves two entities met, using zero-knowledge proofs and minimal 18-byte P2P sync events.

## Features

- Vivaldi network coordinates for proximity estimation
- Zero-knowledge identity proofs (FNV-1a commitment scheme)
- 18-byte presence events compatible with ALICE-Sync
- Full crossing records with mutual verification

## Tests

35 tests covering coordinates, commitments, proofs, events, records, protocol execution, and edge cases.

```
cargo test
```
