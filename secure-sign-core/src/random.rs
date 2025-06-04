// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Cryptographic Random Number Generation
//!
//! This module provides cryptographically secure random number generation capabilities
//! essential for all cryptographic operations in the Secure Sign Service. Proper randomness
//! is critical for:
//!
//! - **Private Key Generation**: Creating unpredictable secp256r1 private keys
//! - **Nonce Generation**: ECDSA signature nonces and AES-GCM nonces
//! - **Key Exchange**: Ephemeral keypairs for Diffie-Hellman protocol
//! - **Salt Generation**: Random salts for key derivation functions
//!
//! ## Security Requirements
//!
//! Cryptographic randomness must be:
//! - **Unpredictable**: Computationally infeasible to predict future values
//! - **Unbiased**: Uniform distribution across the output space
//! - **Non-reproducible**: Different values on each call (except for testing)
//! - **Properly seeded**: Sufficient entropy from the operating system
//!
//! ## Implementation
//!
//! This module uses the `getrandom` crate which provides access to the operating
//! system's cryptographically secure random number generator:
//! - **Linux/Android**: `/dev/urandom` syscall
//! - **macOS/iOS**: `SecRandomCopyBytes` framework
//! - **Windows**: `RtlGenRandom` API
//! - **SGX Enclaves**: Intel RDRAND/RDSEED instructions

/// Trait for cryptographically secure random number generation
///
/// This trait abstracts the random number generation interface, allowing
/// different implementations for various environments (standard OS, SGX enclaves, etc.)
/// while maintaining a consistent API for cryptographic operations.
pub trait CryptRandom {
    /// Error type for random number generation failures
    ///
    /// This should capture platform-specific errors that may occur during
    /// random number generation, such as insufficient entropy or hardware failures.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Fill a buffer with cryptographically secure random bytes
    ///
    /// This method must provide cryptographically secure randomness suitable
    /// for all security-critical operations including key generation.
    ///
    /// # Arguments
    /// * `buf` - Mutable byte slice to fill with random data
    ///
    /// # Returns
    /// * `Ok(())` - Buffer successfully filled with secure random bytes
    /// * `Err(Self::Error)` - Random generation failed (entropy exhaustion, hardware failure, etc.)
    ///
    /// # Security Requirements
    /// - Must be cryptographically secure (not just pseudorandom)
    /// - Must have sufficient entropy for cryptographic use
    /// - Must be resistant to prediction attacks
    /// - Should fail securely if entropy is insufficient
    ///
    /// # Usage Example
    /// ```rust
    /// use secure_sign_core::random::{CryptRandom, EnvCryptRandom};
    ///
    /// let mut rng = EnvCryptRandom;
    /// let mut key_material = [0u8; 32];
    /// rng.try_fill_bytes(&mut key_material).expect("Should generate random bytes");
    ///
    /// // key_material now contains 32 cryptographically secure random bytes
    /// assert_ne!(key_material, [0u8; 32]); // Very unlikely to be all zeros
    /// ```
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// Environment-based cryptographic random number generator
///
/// This implementation uses the operating system's cryptographically secure
/// random number generator via the `getrandom` crate. It automatically selects
/// the most appropriate source of randomness for the current platform.
///
/// ## Platform-Specific Sources
///
/// - **Linux**: Uses `getrandom()` syscall or `/dev/urandom`
/// - **macOS**: Uses `arc4random_buf()` or Security framework
/// - **Windows**: Uses `BCryptGenRandom()` or `RtlGenRandom()`
/// - **SGX**: May use RDRAND instruction when available
///
/// ## Security Properties
///
/// - **Forward Secrecy**: Internal state is updated continuously
/// - **Backtracking Resistance**: Previous outputs cannot be computed from current state
/// - **Prediction Resistance**: Future outputs cannot be predicted
/// - **Proper Seeding**: Automatically seeded from high-entropy sources
pub struct EnvCryptRandom;

impl CryptRandom for EnvCryptRandom {
    /// Error type from the `getrandom` crate
    ///
    /// This captures platform-specific random generation errors such as:
    /// - Insufficient entropy in the random pool
    /// - Hardware random number generator failures
    /// - System call interruptions or permissions issues
    type Error = getrandom::Error;

    /// Generate cryptographically secure random bytes using OS facilities
    ///
    /// This implementation calls `getrandom::fill()` which provides access to
    /// the operating system's cryptographically secure random number generator.
    /// The implementation automatically handles platform differences and provides
    /// the strongest available randomness source.
    ///
    /// # Security Guarantees
    ///
    /// - **Cryptographic Quality**: Output is suitable for key generation
    /// - **Proper Entropy**: Sufficient entropy for cryptographic security
    /// - **Platform Optimized**: Uses best available source on each platform
    /// - **Error Handling**: Fails safely if randomness is unavailable
    ///
    /// # Performance Notes
    ///
    /// - Generally very fast (hardware-accelerated on modern CPUs)
    /// - May block briefly on first call if entropy pool is not ready
    /// - Scales well with request size
    /// - No significant performance difference between small and large requests
    ///
    /// # Error Conditions
    ///
    /// This method may fail in rare circumstances:
    /// - System entropy pool exhaustion (very rare on modern systems)
    /// - Hardware random number generator failures
    /// - Permission restrictions in sandboxed environments
    /// - Early boot scenarios with insufficient entropy
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(buf)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec::Vec};
    #[cfg(feature = "std")]
    use std::collections::HashSet;
    #[cfg(feature = "std")]
    use std::time::Instant;

    #[cfg(not(feature = "std"))]
    use hashbrown::HashSet;

    use super::*;

    /// Test basic random number generation functionality
    ///
    /// Verifies that the random number generator can fill buffers
    /// of various sizes with data that appears random.
    #[test]
    fn test_env_crypt_random_basic() {
        let mut rng = EnvCryptRandom;

        // Test small buffer
        let mut small_buf = [0u8; 8];
        rng.try_fill_bytes(&mut small_buf)
            .expect("Should fill small buffer");

        // Very unlikely that 8 bytes would all be zero if properly random
        assert_ne!(small_buf, [0u8; 8], "Buffer should not be all zeros");

        // Test medium buffer
        let mut medium_buf = [0u8; 64];
        rng.try_fill_bytes(&mut medium_buf)
            .expect("Should fill medium buffer");
        assert_ne!(medium_buf, [0u8; 64], "Buffer should not be all zeros");

        // Test large buffer (common for key generation)
        let mut large_buf = [0u8; 1024];
        rng.try_fill_bytes(&mut large_buf)
            .expect("Should fill large buffer");
        assert_ne!(large_buf, [0u8; 1024], "Buffer should not be all zeros");
    }

    /// Test that random output is not predictable
    ///
    /// Verifies that successive calls produce different output,
    /// which is critical for cryptographic security.
    #[test]
    fn test_random_uniqueness() {
        let mut rng = EnvCryptRandom;

        // Generate multiple buffers and ensure they're different
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        let mut buf3 = [0u8; 32];

        rng.try_fill_bytes(&mut buf1)
            .expect("First generation should succeed");
        rng.try_fill_bytes(&mut buf2)
            .expect("Second generation should succeed");
        rng.try_fill_bytes(&mut buf3)
            .expect("Third generation should succeed");

        // It's astronomically unlikely for three 32-byte random buffers to be identical
        assert_ne!(buf1, buf2, "First and second buffers should be different");
        assert_ne!(buf2, buf3, "Second and third buffers should be different");
        assert_ne!(buf1, buf3, "First and third buffers should be different");
    }

    /// Test edge case: empty buffer
    ///
    /// Verifies that the RNG handles zero-length requests gracefully.
    #[test]
    fn test_empty_buffer() {
        let mut rng = EnvCryptRandom;
        let mut empty_buf: [u8; 0] = [];

        // Should succeed even with empty buffer
        rng.try_fill_bytes(&mut empty_buf)
            .expect("Empty buffer should be handled gracefully");
    }

    /// Test edge case: single byte
    ///
    /// Verifies that single-byte generation works correctly.
    #[test]
    fn test_single_byte() {
        let mut rng = EnvCryptRandom;
        let mut byte_buf = [0u8; 1];

        rng.try_fill_bytes(&mut byte_buf)
            .expect("Single byte generation should work");

        // Generate multiple single bytes to ensure variation
        let mut values = Vec::new();
        for _ in 0..100 {
            let mut buf = [0u8; 1];
            rng.try_fill_bytes(&mut buf)
                .expect("Single byte generation should work");
            values.push(buf[0]);
        }

        // We should see some variation in 100 random bytes
        // (This test could theoretically fail with very low probability)
        let unique_values: HashSet<_> = values.into_iter().collect();
        assert!(
            unique_values.len() > 1,
            "Should see variation in random bytes"
        );
    }

    /// Test that random data has reasonable statistical properties
    ///
    /// This is a basic sanity check - not a full randomness test suite,
    /// but helps catch obvious problems.
    #[test]
    fn test_basic_statistical_properties() {
        let mut rng = EnvCryptRandom;
        let mut buf = [0u8; 1000];

        rng.try_fill_bytes(&mut buf)
            .expect("Should generate random data");

        // Count zeros and ones in all bits
        let mut zero_bits = 0;
        let mut one_bits = 0;

        for byte in buf.iter() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 0 {
                    zero_bits += 1;
                } else {
                    one_bits += 1;
                }
            }
        }

        let total_bits = zero_bits + one_bits;
        assert_eq!(total_bits, 8000, "Should have counted all bits");

        // For good random data, we expect roughly equal numbers of 0s and 1s
        // Allow for some deviation (within 10% of expected)
        let expected = total_bits / 2;
        let tolerance = total_bits / 10;

        assert!(
            zero_bits > expected - tolerance && zero_bits < expected + tolerance,
            "Zero bits ({}) should be roughly half of total ({})",
            zero_bits,
            expected
        );
        assert!(
            one_bits > expected - tolerance && one_bits < expected + tolerance,
            "One bits ({}) should be roughly half of total ({})",
            one_bits,
            expected
        );
    }

    /// Test reproducibility properties
    ///
    /// Verifies that the RNG behaves correctly regarding reproducibility.
    /// For cryptographic RNG, we want non-reproducible output.
    #[test]
    fn test_non_reproducibility() {
        // Create two separate RNG instances
        let mut rng1 = EnvCryptRandom;
        let mut rng2 = EnvCryptRandom;

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.try_fill_bytes(&mut buf1)
            .expect("First RNG should work");
        rng2.try_fill_bytes(&mut buf2)
            .expect("Second RNG should work");

        // Different RNG instances should produce different output
        // (This could theoretically fail with very low probability)
        assert_ne!(
            buf1, buf2,
            "Different RNG instances should produce different output"
        );
    }

    /// Performance test for random generation
    ///
    /// Verifies that random generation performs adequately for
    /// cryptographic operations like key generation.
    #[test]
    fn test_performance_baseline() {
        let mut rng = EnvCryptRandom;

        let start = Instant::now();

        // Generate the equivalent of 100 private keys (32 bytes each)
        for _ in 0..100 {
            let mut buf = [0u8; 32];
            rng.try_fill_bytes(&mut buf)
                .expect("Random generation should succeed");
        }

        let duration = start.elapsed();

        // This should complete very quickly (< 100ms on any reasonable system)
        assert!(
            duration.as_millis() < 100,
            "Random generation too slow: {}ms for 100 keys",
            duration.as_millis()
        );
    }

    /// Test trait object usage
    ///
    /// Verifies that the CryptRandom trait can be used as a trait object,
    /// which is important for dependency injection and testing.
    #[test]
    fn test_trait_object_usage() {
        let mut rng: Box<dyn CryptRandom<Error = getrandom::Error>> = Box::new(EnvCryptRandom);

        let mut buf = [0u8; 16];
        rng.try_fill_bytes(&mut buf)
            .expect("Trait object should work");

        assert_ne!(buf, [0u8; 16], "Trait object should generate random data");
    }
}
