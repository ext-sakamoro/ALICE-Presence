# Changelog

All notable changes to ALICE-Presence will be documented in this file.

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
