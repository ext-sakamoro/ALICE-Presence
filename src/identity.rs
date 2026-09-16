//! Ed25519 identities, verifier challenges and challenge-response proofs
//!
//! The 0.1 design ("ZKP-style" FNV-1a commitment with a self-reported
//! `verified: bool`) proved nothing: the verifier only read a flag the prover
//! wrote. This module replaces it with a plain, well-understood construction:
//!
//! - an identity is an Ed25519 key pair ([`Identity`]),
//! - the **verifier** draws a random [`Challenge`],
//! - the prover signs `DOMAIN || challenge || transcript` ([`ChallengeProof::prove`]),
//! - the verifier checks the signature against the public key **and against
//!   the challenge it issued itself** ([`ChallengeProof::verify`]).
//!
//! There is no field a prover can set to make a proof "verified". Nothing here
//! is zero-knowledge: the public key travels with the proof.
//!
//! Author: Moroya Sakamoto

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

/// Domain separator prepended to every signed message so a presence proof can
/// never be confused with a signature made by the same key for another
/// protocol.
pub const SIGNING_DOMAIN: &[u8; 20] = b"ALICE-Presence/v2/cp";

/// Raw Ed25519 public key (32 bytes).
pub type PublicKey = [u8; 32];

// ── Identity ───────────────────────────────────────────────────────────

/// Long-term identity: an Ed25519 signing key.
///
/// Keep this on the owning device. Only [`Identity::public_key`] is shared.
/// `Debug` prints the public key only.
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from a cryptographic RNG.
    ///
    /// ```
    /// let id = alice_presence::Identity::generate(&mut rand_core::OsRng);
    /// assert_ne!(id.public_key(), [0u8; 32]);
    /// ```
    #[must_use]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            signing_key: SigningKey::generate(rng),
        }
    }

    /// Deterministic identity from a 32-byte seed (tests, key derivation).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Public key to share with counterparts / verifiers.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &Hex(&self.public_key()))
            .finish_non_exhaustive()
    }
}

// ── Challenge ──────────────────────────────────────────────────────────

/// 32-byte nonce drawn by the **verifier**.
///
/// The prover must answer exactly this value; a proof carrying any other
/// challenge is rejected by [`ChallengeProof::verify`], which is what stops a
/// recorded proof from being replayed into a new exchange.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Challenge(pub [u8; 32]);

impl Challenge {
    /// Draw a fresh challenge from a cryptographic RNG.
    #[must_use]
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Deterministic challenge (tests only — a predictable challenge gives an
    /// attacker time to precompute a response).
    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Challenge").field(&Hex(&self.0)).finish()
    }
}

// ── Errors ─────────────────────────────────────────────────────────────

/// Why a [`ChallengeProof`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The proof answers a different challenge than the verifier issued.
    ChallengeMismatch,
    /// The public key bytes do not decode to a valid Ed25519 point.
    InvalidPublicKey,
    /// The signature does not verify under the public key for this transcript.
    InvalidSignature,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChallengeMismatch => f.write_str("proof answers a different challenge"),
            Self::InvalidPublicKey => f.write_str("public key is not a valid Ed25519 key"),
            Self::InvalidSignature => f.write_str("signature does not verify"),
        }
    }
}

impl std::error::Error for ProofError {}

// ── Challenge-response proof ───────────────────────────────────────────

/// Proof that the holder of `public_key` answered `challenge` for a given
/// transcript.
///
/// All fields are readable (a verifier needs them) but none is trusted: the
/// only way to make [`verify`](Self::verify) succeed is to hold the private key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChallengeProof {
    /// Prover's Ed25519 public key.
    pub public_key: PublicKey,
    /// The challenge the prover answered (must equal the verifier's own).
    pub challenge: Challenge,
    /// Ed25519 signature over `SIGNING_DOMAIN || challenge || transcript`.
    pub signature: [u8; 64],
}

impl ChallengeProof {
    /// Wire size: 32 + 32 + 64.
    pub const SIZE: usize = 128;

    fn message(challenge: &Challenge, transcript: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + transcript.len());
        msg.extend_from_slice(SIGNING_DOMAIN);
        msg.extend_from_slice(&challenge.0);
        msg.extend_from_slice(transcript);
        msg
    }

    /// Sign `challenge` and `transcript` with `identity`.
    ///
    /// `transcript` is whatever the exchange must be bound to (party ids,
    /// timestamp, proximity payload, counterpart key, …); see
    /// [`crate::protocol`] for the canonical layout.
    #[must_use]
    pub fn prove(identity: &Identity, challenge: Challenge, transcript: &[u8]) -> Self {
        let signature = identity.sign(&Self::message(&challenge, transcript));
        Self {
            public_key: identity.public_key(),
            challenge,
            signature: signature.to_bytes(),
        }
    }

    /// Verifier-side check.
    ///
    /// `expected_challenge` is the value the verifier issued — it is compared
    /// first, so a proof for any other challenge (a replay) fails before the
    /// signature is even looked at. Uses `verify_strict` (rejects malleable /
    /// small-order keys).
    ///
    /// # Errors
    ///
    /// [`ProofError`] describing the first failed check.
    pub fn verify(
        &self,
        expected_challenge: &Challenge,
        transcript: &[u8],
    ) -> Result<(), ProofError> {
        if self.challenge != *expected_challenge {
            return Err(ProofError::ChallengeMismatch);
        }
        let key =
            VerifyingKey::from_bytes(&self.public_key).map_err(|_| ProofError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&Self::message(&self.challenge, transcript), &signature)
            .map_err(|_| ProofError::InvalidSignature)
    }

    /// `verify` with the additional requirement that the key inside the proof
    /// is the one the verifier expected (learned out of band).
    ///
    /// # Errors
    ///
    /// [`ProofError::InvalidPublicKey`] if the key differs, else as [`verify`](Self::verify).
    pub fn verify_with_key(
        &self,
        expected_key: &PublicKey,
        expected_challenge: &Challenge,
        transcript: &[u8],
    ) -> Result<(), ProofError> {
        if self.public_key != *expected_key {
            return Err(ProofError::InvalidPublicKey);
        }
        self.verify(expected_challenge, transcript)
    }

    /// Serialize to exactly [`Self::SIZE`] bytes: `public_key || challenge || signature`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.public_key);
        out[32..64].copy_from_slice(&self.challenge.0);
        out[64..].copy_from_slice(&self.signature);
        out
    }

    /// Deserialize from exactly [`Self::SIZE`] bytes. No validation is done
    /// here — call [`verify`](Self::verify).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut public_key = [0u8; 32];
        let mut challenge = [0u8; 32];
        let mut signature = [0u8; 64];
        public_key.copy_from_slice(&bytes[..32]);
        challenge.copy_from_slice(&bytes[32..64]);
        signature.copy_from_slice(&bytes[64..]);
        Self {
            public_key,
            challenge: Challenge(challenge),
            signature,
        }
    }
}

impl fmt::Debug for ChallengeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeProof")
            .field("public_key", &Hex(&self.public_key))
            .field("challenge", &self.challenge)
            .field("signature", &Hex(&self.signature))
            .finish()
    }
}

/// Lower-case hex formatter for byte arrays in `Debug` output.
struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Identity {
        Identity::from_seed([n; 32])
    }

    #[test]
    fn identity_from_seed_is_deterministic() {
        assert_eq!(id(1).public_key(), id(1).public_key());
        assert_ne!(id(1).public_key(), id(2).public_key());
    }

    #[test]
    fn identity_generate_differs_per_call() {
        let a = Identity::generate(&mut rand_core::OsRng);
        let b = Identity::generate(&mut rand_core::OsRng);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn identity_debug_hides_secret() {
        let s = format!("{:?}", id(3));
        assert!(s.contains("public_key"));
        assert!(!s.contains("signing_key"));
        assert!(!s.contains("SigningKey"));
    }

    #[test]
    fn challenge_random_differs() {
        let a = Challenge::random(&mut rand_core::OsRng);
        let b = Challenge::random(&mut rand_core::OsRng);
        assert_ne!(a, b);
    }

    #[test]
    fn prove_then_verify_ok() {
        let me = id(1);
        let ch = Challenge::from_seed([9; 32]);
        let proof = ChallengeProof::prove(&me, ch, b"transcript");
        assert_eq!(proof.verify(&ch, b"transcript"), Ok(()));
        assert_eq!(
            proof.verify_with_key(&me.public_key(), &ch, b"transcript"),
            Ok(())
        );
    }

    #[test]
    fn verify_rejects_other_challenge() {
        let me = id(1);
        let issued = Challenge::from_seed([9; 32]);
        let other = Challenge::from_seed([8; 32]);
        let proof = ChallengeProof::prove(&me, other, b"t");
        assert_eq!(
            proof.verify(&issued, b"t"),
            Err(ProofError::ChallengeMismatch)
        );
    }

    #[test]
    fn verify_rejects_other_transcript() {
        let me = id(1);
        let ch = Challenge::from_seed([9; 32]);
        let proof = ChallengeProof::prove(&me, ch, b"t1");
        assert_eq!(proof.verify(&ch, b"t2"), Err(ProofError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_other_key() {
        let me = id(1);
        let ch = Challenge::from_seed([9; 32]);
        let mut proof = ChallengeProof::prove(&me, ch, b"t");
        proof.public_key = id(2).public_key();
        assert_eq!(proof.verify(&ch, b"t"), Err(ProofError::InvalidSignature));
        assert_eq!(
            ChallengeProof::prove(&me, ch, b"t").verify_with_key(&id(2).public_key(), &ch, b"t"),
            Err(ProofError::InvalidPublicKey)
        );
    }

    #[test]
    fn verify_rejects_garbage_key() {
        let ch = Challenge::from_seed([9; 32]);
        // y = 2 is not on the curve → decompression fails.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        let proof = ChallengeProof {
            public_key: not_a_point,
            challenge: ch,
            signature: [0; 64],
        };
        assert_eq!(proof.verify(&ch, b"t"), Err(ProofError::InvalidPublicKey));
        // Bytes that do decode (identity / small-order points) still cannot
        // verify a signature.
        for pk in [[0u8; 32], [0xffu8; 32]] {
            let proof = ChallengeProof {
                public_key: pk,
                challenge: ch,
                signature: [0; 64],
            };
            assert!(proof.verify(&ch, b"t").is_err());
        }
    }

    #[test]
    fn proof_bytes_roundtrip() {
        let me = id(5);
        let ch = Challenge::from_seed([4; 32]);
        let proof = ChallengeProof::prove(&me, ch, b"abc");
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), ChallengeProof::SIZE);
        let back = ChallengeProof::from_bytes(&bytes);
        assert_eq!(back, proof);
        assert_eq!(back.verify(&ch, b"abc"), Ok(()));
    }

    #[test]
    fn domain_separation_changes_signature() {
        // A signature made by the same key over the bare message must not verify
        // as a presence proof.
        let me = id(1);
        let ch = Challenge::from_seed([1; 32]);
        let bare = me.sign(&[&ch.0[..], b"t"].concat());
        let proof = ChallengeProof {
            public_key: me.public_key(),
            challenge: ch,
            signature: bare.to_bytes(),
        };
        assert_eq!(proof.verify(&ch, b"t"), Err(ProofError::InvalidSignature));
    }

    #[test]
    fn proof_error_display() {
        assert_eq!(
            ProofError::ChallengeMismatch.to_string(),
            "proof answers a different challenge"
        );
        assert_eq!(
            ProofError::InvalidPublicKey.to_string(),
            "public key is not a valid Ed25519 key"
        );
        assert_eq!(
            ProofError::InvalidSignature.to_string(),
            "signature does not verify"
        );
    }
}
