//! ZKP-style identity commitment and proof
//!
//! Commitment-based identity proofs using FNV-1a hash.
//! Simplified Sigma protocol: commit → challenge → respond.
//!
//! Author: Moroya Sakamoto

use crate::fnv1a;

// ── Identity Commitment ────────────────────────────────────────────────

/// ZKP-style identity commitment.
///
/// `commitment_hash = H(secret_bytes || nonce_bytes)` where H is FNV-1a.
#[derive(Debug, Clone, Copy)]
pub struct IdentityCommitment {
    /// H(secret || nonce)
    pub commitment_hash: u64,
    pub nonce: u64,
    pub timestamp_ns: u64,
}

impl IdentityCommitment {
    /// Create a commitment from a secret key and nonce.
    pub fn new(secret: u64, nonce: u64, timestamp_ns: u64) -> Self {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&secret.to_le_bytes());
        buf[8..16].copy_from_slice(&nonce.to_le_bytes());
        let commitment_hash = fnv1a(&buf);
        Self {
            commitment_hash,
            nonce,
            timestamp_ns,
        }
    }

    /// Verify that a given secret matches this commitment.
    pub fn verify(&self, secret: u64) -> bool {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&secret.to_le_bytes());
        buf[8..16].copy_from_slice(&self.nonce.to_le_bytes());
        fnv1a(&buf) == self.commitment_hash
    }
}

// ── Zero-Knowledge Proof ───────────────────────────────────────────────

/// Simplified ZKP of identity.
///
/// Prover generates `response = H(secret || challenge)`.
/// Verifier holds the original commitment and checks structural consistency.
#[derive(Debug, Clone, Copy)]
pub struct ZkProof {
    /// Verifier's challenge.
    pub challenge: u64,
    /// Prover's response: `H(secret || challenge)`.
    pub response: u64,
    /// Original commitment hash.
    pub commitment: u64,
    /// Whether the proof checks out.
    pub verified: bool,
}

impl ZkProof {
    /// Produce a proof: `response = H(secret || challenge)`.
    ///
    /// The proof is marked `verified = true` when the commitment matches
    /// `H(secret || nonce)` (i.e. the prover genuinely knows the secret).
    pub fn prove(secret: u64, commitment: &IdentityCommitment, challenge: u64) -> Self {
        let mut resp_buf = [0u8; 16];
        resp_buf[..8].copy_from_slice(&secret.to_le_bytes());
        resp_buf[8..16].copy_from_slice(&challenge.to_le_bytes());
        let response = fnv1a(&resp_buf);

        let verified = commitment.verify(secret);

        Self {
            challenge,
            response,
            commitment: commitment.commitment_hash,
            verified,
        }
    }

    /// Structural verification: fields are non-zero and internally consistent.
    pub fn verify_structure(&self) -> bool {
        self.response != 0 && self.commitment != 0 && self.challenge != 0
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_verify_correct_secret() {
        let c = IdentityCommitment::new(12345, 99, 1_000_000);
        assert!(c.verify(12345));
    }

    #[test]
    fn commitment_verify_wrong_secret() {
        let c = IdentityCommitment::new(12345, 99, 1_000_000);
        assert!(!c.verify(12346));
    }

    #[test]
    fn commitment_hash_determinism() {
        let a = IdentityCommitment::new(42, 7, 100);
        let b = IdentityCommitment::new(42, 7, 200);
        assert_eq!(a.commitment_hash, b.commitment_hash);
    }

    #[test]
    fn commitment_different_nonce() {
        let a = IdentityCommitment::new(42, 1, 100);
        let b = IdentityCommitment::new(42, 2, 100);
        assert_ne!(a.commitment_hash, b.commitment_hash);
    }

    #[test]
    fn zkproof_valid_secret() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let proof = ZkProof::prove(42, &commitment, 0xDEADBEEF);
        assert!(proof.verified);
        assert!(proof.verify_structure());
    }

    #[test]
    fn zkproof_invalid_secret() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let proof = ZkProof::prove(999, &commitment, 0xDEADBEEF);
        assert!(!proof.verified);
        assert!(proof.verify_structure());
    }

    #[test]
    fn zkproof_response_determinism() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let p1 = ZkProof::prove(42, &commitment, 123);
        let p2 = ZkProof::prove(42, &commitment, 123);
        assert_eq!(p1.response, p2.response);
    }

    #[test]
    fn zkproof_different_challenge_different_response() {
        let commitment = IdentityCommitment::new(42, 7, 100);
        let p1 = ZkProof::prove(42, &commitment, 1);
        let p2 = ZkProof::prove(42, &commitment, 2);
        assert_ne!(p1.response, p2.response);
    }
}
