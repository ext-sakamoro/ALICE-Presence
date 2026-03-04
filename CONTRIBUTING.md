# Contributing to ALICE-Presence

## Prerequisites

- Rust 1.70+ (stable)
- `clippy`, `rustfmt` コンポーネント (`rustup component add clippy rustfmt`)

## Code Style

- `cargo fmt` 準拠（CI で `--check` 実行）
- `cargo clippy --lib --tests -- -W clippy::all -W clippy::pedantic` 警告ゼロ
- パブリック関数には `#[must_use]` を付与
- `Result` 返却関数には `# Errors` docセクション必須
- コード内コメント: 日本語

## Build

```bash
cargo build
```

## Test

```bash
cargo test
```

## Lint

```bash
cargo clippy -- -W clippy::all
cargo fmt -- --check
cargo doc --no-deps 2>&1 | grep warning
```

## Design Constraints

- **Zero external dependencies**: all crypto primitives (FNV-1a, ZKP structures) are self-contained.
- **Session FSM**: state transitions are enforced at compile time — invalid transitions return `false`.
- **Vivaldi coordinates**: 2D + height model for network-aware proximity estimation.
- **KD-tree**: spatial index enables O(log n) range queries for nearby peers.
- **Deterministic proofs**: presence proofs are reproducible from the same inputs.
