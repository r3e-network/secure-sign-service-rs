// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # ECDSA Digital Signature Implementation
//!
//! This module provides ECDSA (Elliptic Curve Digital Signature Algorithm) functionality
//! specifically optimized for the NEO blockchain. It implements digital signatures using
//! the secp256r1 (P-256) elliptic curve.
//!
//! ## ECDSA Overview
//!
//! ECDSA provides:
//! - **Authentication**: Proves the signer owns the private key
//! - **Non-repudiation**: Signatures cannot be forged or denied
//! - **Integrity**: Detects any tampering with the signed message
//! - **Efficiency**: Compact signatures (64 bytes) with strong security
//!
//! ## NEO Blockchain Requirements
//!
//! - **Curve**: secp256r1 (NIST P-256) as mandated by NEO protocol
//! - **Hash Function**: SHA-256 for message preprocessing
//! - **Signature Format**: 64-byte concatenation of r || s values
//! - **Deterministic Nonces**: RFC 6979 for reproducible signatures
//!
//! ## Security Properties
//!
//! - **Cryptographic Strength**: ~128-bit security level
//! - **Side-Channel Resistance**: Constant-time operations where possible
//! - **Malleability Protection**: Canonical signature validation
//! - **Memory Safety**: Automatic cleanup of sensitive intermediate values

use alloc::string::{String, ToString};

use p256::ecdsa::{
    signature::{Signer, Verifier as P256Verifier},
    Signature, SigningKey, VerifyingKey,
};

use crate::{bytes::ToArray, secp256r1};

/// Size of an ECDSA signature in bytes (r + s components)
///
/// ECDSA signatures consist of two 32-byte integers:
/// - r: First component of the signature
/// - s: Second component of the signature
///   Total: 64 bytes for secp256r1 curve
pub const ECC256_SIGN_SIZE: usize = 32 * 2;

/// Trait for digital signature generation
///
/// This trait abstracts the signing operation, allowing different
/// types to implement signature generation in a consistent way.
pub trait Sign {
    /// The signature type produced by this signer
    type Sign;
    /// Error type for signing operations
    type Error;

    /// Generate a digital signature for the given message
    ///
    /// # Arguments
    /// * `message` - The data to be signed (typically a hash)
    ///
    /// # Returns
    /// * `Ok(Self::Sign)` - Successfully generated signature
    /// * `Err(Self::Error)` - Signing operation failed
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Self::Sign, Self::Error>;
}

/// Trait for digital signature verification
///
/// This trait abstracts the verification operation, allowing different
/// types to implement signature validation in a consistent way.
pub trait Verify {
    /// The signature type accepted by this verifier
    type Sign;
    /// Error type for verification operations
    type Error;

    /// Verify a digital signature against the given message
    ///
    /// # Arguments
    /// * `message` - The original data that was signed
    /// * `sign` - The signature to verify
    ///
    /// # Returns
    /// * `Ok(())` - Signature is valid
    /// * `Err(Self::Error)` - Signature is invalid or verification failed
    fn verify<T: AsRef<[u8]>>(&self, message: T, sign: &Self::Sign) -> Result<(), Self::Error>;
}

/// Errors that can occur during ECDSA signature generation
#[derive(Debug, Clone, thiserror::Error)]
pub enum SignError {
    #[error("ecdsa: invalid private key")]
    InvalidPrivateKey,

    #[error("ecdsa: sign error: {0}")]
    SignError(String),
}

/// ECDSA signature generation implementation for secp256r1 private keys
///
/// This implementation provides secure ECDSA signature generation with:
/// - **Deterministic nonces**: Uses RFC 6979 for reproducible signatures
/// - **Side-channel protection**: Leverages p256 crate's secure implementation
/// - **Memory safety**: Automatic cleanup of intermediate values
/// - **NEO compatibility**: Produces signatures in NEO-expected format
impl Sign for secp256r1::PrivateKey {
    type Sign = [u8; ECC256_SIGN_SIZE];
    type Error = SignError;

    /// Generate an ECDSA signature for the provided message
    ///
    /// This method implements the complete ECDSA signing process:
    ///
    /// ## Signing Process
    /// 1. **Key Conversion**: Convert internal private key to p256 format
    /// 2. **Nonce Generation**: Use RFC 6979 deterministic nonce generation
    /// 3. **Signature Computation**: Calculate r and s signature components
    /// 4. **Format Conversion**: Return signature as 64-byte array
    ///
    /// ## Security Features
    /// - **Deterministic Nonces**: RFC 6979 prevents nonce reuse attacks
    /// - **Constant-time Operations**: Side-channel attack resistance
    /// - **Canonical Signatures**: Ensures signature uniqueness
    /// - **Memory Protection**: Intermediate values automatically cleared
    ///
    /// # Arguments
    /// * `message` - Data to sign (typically SHA-256 hash of transaction data)
    ///
    /// # Returns
    /// * `Ok([u8; 64])` - 64-byte ECDSA signature (r || s in big-endian)
    /// * `Err(SignError)` - Private key invalid or signing operation failed
    ///
    /// # NEO Blockchain Usage
    /// ```text
    /// message = SHA-256(transaction_data || network_magic)
    /// signature = private_key.sign(message)
    /// // signature is used in transaction witnesses
    /// ```
    ///
    /// # Security Notes
    /// - Message should be pre-hashed with SHA-256 for security
    /// - Same message always produces the same signature (deterministic)
    /// - Never reuse private keys across different elliptic curves
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Self::Sign, Self::Error> {
        // Convert internal private key to p256 signing key format
        let sk: SigningKey = p256::SecretKey::from_slice(self.as_be_bytes())
            .map(|key| key.into())
            .map_err(|_| SignError::InvalidPrivateKey)?;

        // Generate ECDSA signature using RFC 6979 deterministic nonces
        // This ensures the same message always produces the same signature
        // while maintaining cryptographic security
        let signature: Signature = sk
            .try_sign(message.as_ref())
            .map_err(|err| SignError::SignError(err.to_string()))?;

        // Convert signature to NEO-compatible format: 64-byte array (r || s)
        let buf = signature.to_bytes(); // Components in big-endian format
        Ok(buf.as_slice().to_array())
    }
}

/// Errors that can occur during ECDSA signature verification
#[derive(Debug, Clone, thiserror::Error)]
pub enum VerifyError {
    #[error("ecdsa: invalid public key")]
    InvalidPublicKey,

    #[error("ecdsa: invalid sign")]
    InvalidSign,
}

/// ECDSA signature verification implementation for secp256r1 public keys
///
/// This implementation provides secure ECDSA signature verification with:
/// - **Format validation**: Ensures signature components are valid
/// - **Point validation**: Verifies public key is on the curve
/// - **Malleability protection**: Prevents signature malleability attacks
/// - **Constant-time verification**: Side-channel attack resistance
impl Verify for secp256r1::PublicKey {
    type Sign = [u8; ECC256_SIGN_SIZE];
    type Error = VerifyError;

    /// Verify an ECDSA signature against the provided message
    ///
    /// This method implements the complete ECDSA verification process:
    ///
    /// ## Verification Process
    /// 1. **Signature Parsing**: Decode 64-byte signature into r and s components
    /// 2. **Public Key Validation**: Ensure public key is valid curve point
    /// 3. **Mathematical Verification**: Perform ECDSA verification equation
    /// 4. **Result Validation**: Confirm signature authenticity
    ///
    /// ## Security Features
    /// - **Point Validation**: Ensures public key is on secp256r1 curve
    /// - **Signature Validation**: Checks r and s are in valid ranges
    /// - **Malleability Protection**: Rejects non-canonical signatures
    /// - **Constant-time Operations**: Side-channel attack resistance
    ///
    /// # Arguments
    /// * `message` - Original data that was signed
    /// * `sign` - 64-byte ECDSA signature to verify
    ///
    /// # Returns
    /// * `Ok(())` - Signature is mathematically valid and authentic
    /// * `Err(VerifyError)` - Signature is invalid, malformed, or forged
    ///
    /// # NEO Blockchain Usage
    /// ```text
    /// message = SHA-256(transaction_data || network_magic)
    /// is_valid = public_key.verify(message, signature)
    /// // Used to validate transaction witnesses
    /// ```
    ///
    /// # Security Notes
    /// - Message must be the same data that was originally signed
    /// - Signature malleability is automatically prevented
    /// - Invalid public keys are rejected during verification
    /// - Verification failure may indicate tampering or forgery
    #[inline]
    fn verify<T: AsRef<[u8]>>(&self, message: T, sign: &Self::Sign) -> Result<(), Self::Error> {
        // Parse the 64-byte signature into ECDSA signature format
        // This validates that r and s components are in correct ranges
        let sign = Signature::try_from(sign.as_ref()).map_err(|_| VerifyError::InvalidSign)?;

        // Convert public key to verification format and validate curve membership
        // Uses uncompressed format (65 bytes) for compatibility with p256 crate
        VerifyingKey::from_sec1_bytes(&self.to_uncompressed())
            .map_err(|_| VerifyError::InvalidPublicKey)?
            // Perform the ECDSA verification equation
            // Verifies: r ≡ (u₁G + u₂Q)ₓ (mod n) where Q is the public key
            .verify(message.as_ref(), &sign)
            .map_err(|_| VerifyError::InvalidSign)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    #[cfg(feature = "std")]
    use std::time::Instant;

    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        random::EnvCryptRandom,
        secp256r1::{Keypair, PrivateKey},
    };

    /// Test basic ECDSA signature generation and verification
    ///
    /// This tests the fundamental sign-verify cycle with known data.
    #[test]
    fn test_ecdsa_sign_verify_basic() {
        // Generate a test keypair
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        // Test message (typically would be a hash)
        let message = b"test message for ECDSA signing";

        // Sign the message
        let signature = private_key.sign(message).expect("Signing should succeed");

        // Verify the signature
        public_key
            .verify(message, &signature)
            .expect("Verification should succeed");
    }

    /// Test ECDSA with different message lengths
    ///
    /// Verifies that ECDSA works with various input sizes,
    /// though typically it's used with fixed-size hashes.
    #[test]
    fn test_ecdsa_various_message_lengths() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        // Test different message lengths
        let test_cases = [
            b"".to_vec(),      // Empty message
            b"a".to_vec(),     // Single byte
            b"short".to_vec(), // Short message
            vec![0u8; 32],     // 32 bytes (common hash size)
            vec![0u8; 64],     // 64 bytes
            vec![0u8; 256],    // Longer message
        ];

        for (i, message) in test_cases.iter().enumerate() {
            let signature = private_key
                .sign(message)
                .unwrap_or_else(|_| panic!("Signing test case {i} should succeed"));

            public_key
                .verify(message, &signature)
                .unwrap_or_else(|_| panic!("Verification test case {i} should succeed"));
        }
    }

    /// Test that different messages produce different signatures
    ///
    /// This is important for signature uniqueness and security.
    #[test]
    fn test_signature_uniqueness() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();

        let message1 = b"first message";
        let message2 = b"second message";
        let message3 = b"first message "; // Note the extra space

        let sig1 = private_key
            .sign(message1)
            .expect("First signature should succeed");
        let sig2 = private_key
            .sign(message2)
            .expect("Second signature should succeed");
        let sig3 = private_key
            .sign(message3)
            .expect("Third signature should succeed");

        // Different messages should produce different signatures
        assert_ne!(
            sig1, sig2,
            "Different messages should have different signatures"
        );
        assert_ne!(
            sig1, sig3,
            "Even slightly different messages should have different signatures"
        );
        assert_ne!(sig2, sig3, "All signatures should be unique");
    }

    /// Test signature verification failure with wrong message
    ///
    /// Verifies that signatures fail verification when the message is modified.
    #[test]
    fn test_verification_wrong_message() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        let original_message = b"original message";
        let modified_message = b"modified message";

        // Sign the original message
        let signature = private_key
            .sign(original_message)
            .expect("Signing should succeed");

        // Verification should succeed with original message
        public_key
            .verify(original_message, &signature)
            .expect("Original verification should succeed");

        // Verification should fail with modified message
        assert!(
            public_key.verify(modified_message, &signature).is_err(),
            "Verification should fail with modified message"
        );
    }

    /// Test signature verification failure with wrong public key
    ///
    /// Verifies that signatures fail verification with a different public key.
    #[test]
    fn test_verification_wrong_public_key() {
        let keypair1 =
            Keypair::gen(&mut EnvCryptRandom).expect("First keypair generation should succeed");
        let keypair2 =
            Keypair::gen(&mut EnvCryptRandom).expect("Second keypair generation should succeed");

        let message = b"test message";

        // Sign with first private key
        let signature = keypair1
            .private_key()
            .sign(message)
            .expect("Signing should succeed");

        // Verification should succeed with matching public key
        keypair1
            .public_key()
            .verify(message, &signature)
            .expect("Correct verification should succeed");

        // Verification should fail with different public key
        assert!(
            keypair2.public_key().verify(message, &signature).is_err(),
            "Verification should fail with wrong public key"
        );
    }

    /// Test signature verification with corrupted signature
    ///
    /// Verifies that corrupted signatures are rejected.
    #[test]
    fn test_verification_corrupted_signature() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        let message = b"test message";
        let mut signature = private_key.sign(message).expect("Signing should succeed");

        // Verify original signature works
        public_key
            .verify(message, &signature)
            .expect("Original signature should verify");

        // Corrupt the signature by flipping a bit
        signature[0] ^= 0x01;

        // Verification should fail with corrupted signature
        assert!(
            public_key.verify(message, &signature).is_err(),
            "Verification should fail with corrupted signature"
        );
    }

    /// Test deterministic signatures (RFC 6979)
    ///
    /// ECDSA should produce the same signature for the same message and key.
    #[test]
    fn test_deterministic_signatures() {
        // Use a fixed private key for deterministic testing
        let private_key_bytes = [1u8; 32];
        let private_key = PrivateKey::new(Zeroizing::new(private_key_bytes));

        let message = b"deterministic test message";

        // Generate multiple signatures of the same message
        let sig1 = private_key
            .sign(message)
            .expect("First signature should succeed");
        let sig2 = private_key
            .sign(message)
            .expect("Second signature should succeed");
        let sig3 = private_key
            .sign(message)
            .expect("Third signature should succeed");

        // All signatures should be identical (RFC 6979 deterministic)
        assert_eq!(sig1, sig2, "Deterministic signatures should be identical");
        assert_eq!(sig2, sig3, "Deterministic signatures should be identical");
    }

    /// Test signature with zero message
    ///
    /// Edge case testing with a zero-filled message.
    #[test]
    fn test_signature_zero_message() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        let zero_message = [0u8; 32];

        let signature = private_key
            .sign(zero_message)
            .expect("Zero message signing should succeed");
        public_key
            .verify(zero_message, &signature)
            .expect("Zero message verification should succeed");
    }

    /// Test signature with max value message
    ///
    /// Edge case testing with a max-value message.
    #[test]
    fn test_signature_max_message() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        let max_message = [0xFFu8; 32];

        let signature = private_key
            .sign(max_message)
            .expect("Max message signing should succeed");
        public_key
            .verify(max_message, &signature)
            .expect("Max message verification should succeed");
    }

    /// Test invalid signature format detection
    ///
    /// Verifies that malformed signatures are properly rejected.
    #[test]
    fn test_invalid_signature_format() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let public_key = keypair.public_key();

        let message = b"test message";

        // Test various invalid signature formats
        let invalid_signatures = [
            [0u8; 64], // All zeros
            [0xFFu8; 64], // All max values
                       // Note: p256 crate handles most invalid signature detection internally
        ];

        for (i, invalid_sig) in invalid_signatures.iter().enumerate() {
            assert!(
                public_key.verify(message, invalid_sig).is_err(),
                "Invalid signature {i} should be rejected",
            );
        }
    }

    /// Test performance of signature operations
    ///
    /// Ensures that signing and verification perform adequately.
    #[test]
    #[cfg(feature = "std")]
    fn test_signature_performance() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();
        let public_key = keypair.public_key();

        let message = b"performance test message";

        // Measure signing performance
        let start_sign = Instant::now();
        let mut signatures = Vec::new();

        for _ in 0..100 {
            let signature = private_key.sign(message).expect("Signing should succeed");
            signatures.push(signature);
        }

        let sign_duration = start_sign.elapsed();

        // Measure verification performance
        let start_verify = Instant::now();

        for signature in &signatures {
            public_key
                .verify(message, signature)
                .expect("Verification should succeed");
        }

        let verify_duration = start_verify.elapsed();

        // Performance assertions (more lenient for variable CI environments)
        // Allow more time than originally set to account for CI variability
        assert!(
            sign_duration.as_millis() < 3000,
            "100 signatures took too long: {}ms (max: 3000ms)",
            sign_duration.as_millis()
        );
        assert!(
            verify_duration.as_millis() < 2000,
            "100 verifications took too long: {}ms (max: 2000ms)",
            verify_duration.as_millis()
        );

        #[cfg(feature = "std")]
        println!(
            "Performance: 100 signatures in {}ms, 100 verifications in {}ms",
            sign_duration.as_millis(),
            verify_duration.as_millis()
        );
    }

    /// Test error propagation from underlying library
    ///
    /// Ensures that cryptographic errors are properly handled.
    #[test]
    fn test_error_propagation() {
        // Test with an invalid private key (all zeros)
        let zero_key = PrivateKey::new(Zeroizing::new([0u8; 32]));
        let message = b"test message";

        // This should fail because zero is not a valid private key
        assert!(
            zero_key.sign(message).is_err(),
            "Zero private key should fail signing"
        );
    }

    /// Test signature format consistency
    ///
    /// Verifies that signature format matches expected 64-byte structure.
    #[test]
    fn test_signature_format() {
        let keypair = Keypair::gen(&mut EnvCryptRandom).expect("Keypair generation should succeed");
        let private_key = keypair.private_key();

        let message = b"format test message";
        let signature = private_key.sign(message).expect("Signing should succeed");

        // Signature should be exactly 64 bytes (32 bytes r + 32 bytes s)
        assert_eq!(
            signature.len(),
            ECC256_SIGN_SIZE,
            "Signature should be 64 bytes"
        );
        assert_eq!(signature.len(), 64, "Signature should be 64 bytes");

        // The signature should not be all zeros (extremely unlikely)
        assert_ne!(signature, [0u8; 64], "Signature should not be all zeros");
    }
}
