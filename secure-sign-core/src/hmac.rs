// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # HMAC-SHA256 Key Derivation
//!
//! This module provides HMAC-SHA256 functionality for cryptographic key derivation
//! and strengthening operations. HMAC (Hash-based Message Authentication Code)
//! is used throughout the secure sign service to derive strong encryption keys
//! from shared secrets.
//!
//! ## HMAC-SHA256 Overview
//!
//! HMAC provides:
//! - **Key Derivation**: Transform raw shared secrets into strong encryption keys
//! - **Authentication**: Verify data integrity and authenticity
//! - **Pseudorandomness**: Generate cryptographically strong derived keys
//! - **Security Amplification**: Strengthen potentially weak input material
//!
//! ## Usage in Secure Sign Service
//!
//! HMAC-SHA256 is primarily used in the Diffie-Hellman key exchange:
//! ```text
//! shared_secret = ECDH(private_key, public_key)
//! encryption_key = HMAC-SHA256(salt, shared_secret)
//! ```
//!
//! This strengthens the raw ECDH output against potential cryptographic weaknesses
//! and provides a uniform 256-bit key suitable for AES-256-GCM encryption.
//!
//! ## Security Properties
//!
//! - **Collision Resistance**: Based on SHA-256's collision resistance
//! - **Pseudorandomness**: Output indistinguishable from random
//! - **Key Independence**: Different keys produce independent outputs
//! - **Constant-time**: Resistance to timing attacks

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Trait providing HMAC-SHA256 key derivation functionality
///
/// This trait allows any byte slice to be used as an HMAC key for
/// deriving cryptographically strong keys from input data.
pub trait HmacSha256 {
    /// Compute HMAC-SHA256 using this value as the key
    ///
    /// # Arguments
    /// * `data` - Input data to be authenticated and processed
    ///
    /// # Returns
    /// 32-byte HMAC-SHA256 output suitable for use as an encryption key
    fn hmac_sha256(&self, data: &[u8]) -> [u8; 32];
}

/// HMAC-SHA256 implementation for byte slices
///
/// This implementation allows any byte slice to serve as an HMAC key,
/// making it convenient to derive encryption keys from various sources
/// such as ECDH shared secrets, passphrases, or salt values.
impl HmacSha256 for [u8] {
    /// Compute HMAC-SHA256 with this byte slice as the key
    ///
    /// This method implements the complete HMAC-SHA256 computation:
    ///
    /// ## HMAC Process
    /// 1. **Key Preparation**: Process the key according to HMAC specification
    /// 2. **Inner Hash**: Compute SHA-256(key ⊕ ipad || data)
    /// 3. **Outer Hash**: Compute SHA-256(key ⊕ opad || inner_hash)
    /// 4. **Output**: Return 32-byte result
    ///
    /// ## Security Features
    /// - **Variable Key Length**: Accepts keys of any length (automatically padded/hashed)
    /// - **Collision Resistance**: Inherits SHA-256's collision resistance properties
    /// - **Pseudorandomness**: Output is computationally indistinguishable from random
    /// - **Authentication**: Provides strong authentication of the input data
    ///
    /// # Arguments
    /// * `data` - Input data to authenticate and derive key material from
    ///
    /// # Returns
    /// 32-byte HMAC-SHA256 result suitable for use as:
    /// - AES-256 encryption keys
    /// - Additional key derivation input
    /// - Message authentication codes
    /// - Cryptographic commitments
    ///
    /// # Usage in Key Exchange
    /// ```rust
    /// use secure_sign_core::hmac::HmacSha256;
    ///
    /// // Simulate ECDH shared secret (32 bytes)
    /// let shared_secret = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ///                      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ///                      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    ///                      0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22];
    ///
    /// // Empty salt as used in the Diffie-Hellman protocol
    /// let salt: [u8; 0] = [];
    /// let encryption_key = salt.hmac_sha256(&shared_secret);
    ///
    /// // encryption_key is now suitable for AES-256-GCM
    /// assert_eq!(encryption_key.len(), 32);
    /// ```
    ///
    /// # Security Notes
    /// - The key (self) can be of any length - HMAC handles key sizing internally
    /// - Output is always exactly 32 bytes (256 bits)
    /// - Same key + data always produces the same output (deterministic)
    /// - Computationally infeasible to reverse-engineer the input from output
    #[inline]
    fn hmac_sha256(&self, data: &[u8]) -> [u8; 32] {
        // Initialize HMAC with this byte slice as the key
        // The hmac crate handles key length normalization automatically:
        // - Keys longer than 64 bytes are hashed to 32 bytes
        // - Keys shorter than 64 bytes are zero-padded
        let mut hmac = Hmac::<Sha256>::new_from_slice(self).expect("Any key length should be OK");

        // Process the input data through the HMAC computation
        hmac.update(data);

        // Finalize the HMAC computation and extract the 32-byte result
        hmac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use std::time::Instant;

    use super::*;

    /// Test HMAC-SHA256 with known test vectors
    ///
    /// Uses RFC 4231 test vectors to verify correct HMAC implementation.
    #[test]
    fn test_hmac_sha256_rfc4231_vectors() {
        // Test Case 1: Basic functionality test
        let key1 = [0x0b; 20]; // 20 bytes of 0x0b
        let data1 = b"Hi There";
        let expected1 =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .expect("hex decode should work");

        let result1 = key1.hmac_sha256(data1);
        assert_eq!(result1.to_vec(), expected1, "RFC 4231 Test Case 1 failed");

        // Test Case 2: Test with data longer than key
        let key2 = b"Jefe";
        let data2 = b"what do ya want for nothing?";
        let expected2 =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .expect("hex decode should work");

        let result2 = key2.hmac_sha256(data2);
        assert_eq!(result2.to_vec(), expected2, "RFC 4231 Test Case 2 failed");

        // Test Case 3: Test with 50-byte key
        let key3 = [0xaa; 20];
        let data3 = [0xdd; 50];
        let expected3 =
            hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
                .expect("hex decode should work");

        let result3 = key3.hmac_sha256(&data3);
        assert_eq!(result3.to_vec(), expected3, "RFC 4231 Test Case 3 failed");
    }

    /// Test HMAC with empty key
    ///
    /// Verifies that HMAC handles empty keys correctly.
    #[test]
    fn test_hmac_empty_key() {
        let empty_key: [u8; 0] = [];
        let data = b"test data with empty key";

        // Should not panic and should produce consistent output
        let result1 = empty_key.hmac_sha256(data);
        let result2 = empty_key.hmac_sha256(data);

        assert_eq!(result1, result2, "Empty key HMAC should be deterministic");
        assert_ne!(result1, [0u8; 32], "Empty key HMAC should not be all zeros");
    }

    /// Test HMAC with empty data
    ///
    /// Verifies that HMAC handles empty data correctly.
    #[test]
    fn test_hmac_empty_data() {
        let key = b"test key for empty data";
        let empty_data: [u8; 0] = [];

        // Should not panic and should produce consistent output
        let result1 = key.hmac_sha256(&empty_data);
        let result2 = key.hmac_sha256(&empty_data);

        assert_eq!(result1, result2, "Empty data HMAC should be deterministic");
        assert_ne!(
            result1, [0u8; 32],
            "Empty data HMAC should not be all zeros"
        );
    }

    /// Test HMAC with both empty key and data
    ///
    /// Edge case with both inputs empty.
    #[test]
    fn test_hmac_both_empty() {
        let empty_key: [u8; 0] = [];
        let empty_data: [u8; 0] = [];

        let result = empty_key.hmac_sha256(&empty_data);

        // Should be deterministic
        let result2 = empty_key.hmac_sha256(&empty_data);
        assert_eq!(
            result, result2,
            "Empty key/data HMAC should be deterministic"
        );
    }

    /// Test HMAC with very long key (> block size)
    ///
    /// Tests behavior when key is longer than SHA-256 block size (64 bytes).
    #[test]
    fn test_hmac_long_key() {
        // Key longer than SHA-256 block size (64 bytes)
        let long_key = [0x42u8; 128];
        let data = b"test data for long key";

        let result = long_key.hmac_sha256(data);

        // Should produce valid output
        assert_ne!(result, [0u8; 32], "Long key HMAC should not be all zeros");

        // Should be deterministic
        let result2 = long_key.hmac_sha256(data);
        assert_eq!(result, result2, "Long key HMAC should be deterministic");
    }

    /// Test HMAC with exact block size key
    ///
    /// Tests with key exactly equal to SHA-256 block size (64 bytes).
    #[test]
    fn test_hmac_block_size_key() {
        let block_size_key = [0x33u8; 64]; // Exactly 64 bytes
        let data = b"test data for block size key";

        let result = block_size_key.hmac_sha256(data);

        assert_ne!(
            result, [0u8; 32],
            "Block size key HMAC should not be all zeros"
        );

        // Test determinism
        let result2 = block_size_key.hmac_sha256(data);
        assert_eq!(
            result, result2,
            "Block size key HMAC should be deterministic"
        );
    }

    /// Test HMAC key derivation consistency
    ///
    /// Verifies that the same key and data always produce the same result.
    #[test]
    fn test_hmac_deterministic() {
        let key = b"deterministic test key";
        let data = b"deterministic test data";

        // Multiple computations should yield identical results
        let results: Vec<[u8; 32]> = (0..10).map(|_| key.hmac_sha256(data)).collect();

        // All results should be identical
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                *result, results[0],
                "HMAC result {i} should match first result",
            );
        }
    }

    /// Test HMAC with different key lengths
    ///
    /// Verifies HMAC works correctly with various key sizes.
    #[test]
    fn test_hmac_various_key_lengths() {
        let data = b"test data for various key lengths";

        let test_cases = [
            vec![0x01; 1],   // 1 byte key
            vec![0x02; 16],  // 16 byte key (common)
            vec![0x03; 32],  // 32 byte key (common for derived keys)
            vec![0x04; 48],  // 48 byte key
            vec![0x05; 63],  // Just under block size
            vec![0x06; 64],  // Exactly block size
            vec![0x07; 65],  // Just over block size
            vec![0x08; 128], // Much larger than block size
        ];

        for (i, key) in test_cases.iter().enumerate() {
            let result = key.hmac_sha256(data);

            assert_ne!(
                result, [0u8; 32],
                "Key length test case {i} should not be all zeros",
            );

            // Test determinism for each key length
            let result2 = key.hmac_sha256(data);
            assert_eq!(
                result, result2,
                "Key length test case {i} should be deterministic",
            );
        }
    }

    /// Test HMAC avalanche effect
    ///
    /// Verifies that small changes in input produce large changes in output.
    #[test]
    fn test_hmac_avalanche_effect() {
        let base_key = b"base key for avalanche test";
        let base_data = b"base data for avalanche test";

        let base_result = base_key.hmac_sha256(base_data);

        // Test key changes
        let mut modified_key = base_key.to_vec();
        modified_key[0] ^= 0x01; // Flip one bit
        let key_result = modified_key.hmac_sha256(base_data);

        // Results should be completely different
        assert_ne!(
            base_result, key_result,
            "Key modification should cause significant output change"
        );

        // Test data changes
        let mut modified_data = base_data.to_vec();
        modified_data[0] ^= 0x01; // Flip one bit
        let data_result = base_key.hmac_sha256(&modified_data);

        assert_ne!(
            base_result, data_result,
            "Data modification should cause significant output change"
        );

        // Count differing bits to ensure good avalanche
        let base_bits = bytes_to_bits(&base_result);
        let key_bits = bytes_to_bits(&key_result);
        let data_bits = bytes_to_bits(&data_result);

        let key_diff_count = base_bits
            .iter()
            .zip(key_bits.iter())
            .filter(|(a, b)| a != b)
            .count();
        let data_diff_count = base_bits
            .iter()
            .zip(data_bits.iter())
            .filter(|(a, b)| a != b)
            .count();

        // Good avalanche should change roughly half the bits
        assert!(
            key_diff_count > 64,
            "Key change should affect many bits (got {key_diff_count})",
        );
        assert!(
            data_diff_count > 64,
            "Data change should affect many bits (got {data_diff_count})",
        );
    }

    /// Test HMAC as used in Diffie-Hellman key derivation
    ///
    /// Simulates the actual usage pattern in the secure sign service.
    #[test]
    fn test_hmac_diffie_hellman_usage() {
        // Simulate ECDH shared secret (32 bytes of random-looking data)
        let shared_secret = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x99, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22,
        ];

        // Empty salt as used in the actual implementation
        let salt: [u8; 0] = [];

        // Derive encryption key using HMAC
        let encryption_key = salt.hmac_sha256(&shared_secret);

        // Verify it produces a valid-looking key
        assert_ne!(
            encryption_key, [0u8; 32],
            "Derived key should not be all zeros"
        );
        assert_ne!(
            encryption_key, shared_secret,
            "Derived key should differ from input"
        );

        // Verify determinism
        let encryption_key2 = salt.hmac_sha256(&shared_secret);
        assert_eq!(
            encryption_key, encryption_key2,
            "Key derivation should be deterministic"
        );
    }

    /// Test HMAC performance
    ///
    /// Ensures HMAC operations perform adequately for frequent use.
    #[test]
    fn test_hmac_performance() {
        let key = b"performance test key";
        let data = b"performance test data";

        let start = Instant::now();

        // Perform many HMAC operations
        for _ in 0..1000 {
            let _ = key.hmac_sha256(data);
        }

        let duration = start.elapsed();

        // Should complete quickly (< 100ms on reasonable hardware)
        assert!(
            duration.as_millis() < 100,
            "1000 HMAC operations took too long: {}ms",
            duration.as_millis()
        );
    }

    /// Helper function to convert bytes to bits for avalanche testing
    fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        bits
    }
}
