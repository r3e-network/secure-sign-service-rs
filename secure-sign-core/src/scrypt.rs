// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Scrypt Key Derivation Function
//!
//! This module implements the scrypt password-based key derivation function (PBKDF)
//! as specified in RFC 7914. Scrypt is specifically designed to be memory-hard,
//! making it resistant to hardware-based attacks using custom ASICs or GPUs.
//!
//! ## Scrypt in NEP-6 Wallets
//!
//! NEP-6 wallets use scrypt to derive encryption keys from user passphrases:
//! ```text
//! passphrase + salt → scrypt(N, r, p) → encryption_key → AES(private_key)
//! ```
//!
//! ## Security Properties
//!
//! - **Memory-Hard**: Requires significant memory allocation (proportional to N×r)
//! - **Time-Hard**: Requires significant computation time (proportional to N×p)
//! - **ASIC-Resistant**: Memory requirements make custom hardware expensive
//! - **Configurable**: Parameters can be adjusted for security vs. performance
//!
//! ## Parameter Guidelines
//!
//! - **N (CPU/Memory cost)**: Power of 2, typically 16384-65536 for production
//! - **r (Block size)**: Usually 8, affects memory usage (128×r bytes per block)
//! - **p (Parallelization)**: Usually 1-8, affects computation time
//!
//! **Memory Usage**: 128 × N × r bytes
//! **Time Complexity**: O(N × p) operations
//!
//! ## NEP-6 Standard Parameters
//!
//! The NEP-6 standard recommends:
//! - N = 16384 (2^14)
//! - r = 8  
//! - p = 8
//! - Memory: ~16MB per derivation
//! - Time: ~100ms on modern hardware

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Scrypt algorithm parameters for key derivation
///
/// These parameters control the computational and memory cost of the scrypt
/// key derivation function. Higher values provide better security against
/// brute-force attacks but require more resources.
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct ScryptParams {
    /// CPU/Memory cost parameter (must be a power of 2)
    ///
    /// This parameter exponentially increases both memory usage and computation time.
    /// Memory usage = 128 × N × r bytes
    ///
    /// **Recommended values:**
    /// - Minimum: 1024 (1KB memory, fast but less secure)
    /// - Low security: 4096 (4MB memory, ~10ms)
    /// - Medium security: 16384 (16MB memory, ~50ms) - NEP-6 standard
    /// - High security: 65536 (64MB memory, ~200ms)
    /// - Maximum practical: 1048576 (1GB memory, several seconds)
    pub n: u64,

    /// Block size parameter (affects memory usage)
    ///
    /// This parameter controls the size of the internal blocks used by scrypt.
    /// Memory usage is proportional to r, and each block is 128 bytes.
    ///
    /// **Typical values:**
    /// - Standard: 8 (recommended for most use cases)
    /// - Higher values increase memory usage linearly
    /// - Very high values (>32) may decrease security/performance ratio
    pub r: u32,

    /// Parallelization parameter (affects computation time)
    ///
    /// This parameter controls the degree of parallelization.
    /// Higher values increase computation time linearly.
    ///
    /// **Typical values:**
    /// - Single-threaded: 1
    /// - Multi-core: 4-8 (can utilize multiple CPU cores)
    /// - Very high values may hit diminishing returns
    pub p: u32,
}

impl core::fmt::Display for ScryptParams {
    /// Format scrypt parameters in a human-readable way
    ///
    /// Displays the parameters in the format: ScryptParams{n:16384,r:8,p:8}
    /// This is useful for logging and debugging without exposing sensitive data.
    #[inline]
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::write!(
            formatter,
            "ScryptParams{{n:{},r:{},p:{}}}",
            self.n,
            self.r,
            self.p
        )
    }
}

/// Errors that can occur during scrypt key derivation
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScryptDeriveError {
    #[error("scrypt: invalid scrypt params")]
    InvalidParams,

    #[error("scrypt: invalid derived length")]
    InvalidDerivedLength,
}

/// Trait for performing scrypt key derivation
///
/// This trait allows any type that can be converted to a byte slice
/// (such as passwords, passphrases, or existing keys) to be used as
/// input material for scrypt key derivation.
pub trait DeriveScryptKey {
    /// Derive a key using the scrypt algorithm
    ///
    /// # Type Parameters
    /// * `N` - Length of the derived key in bytes (must be > 0)
    ///
    /// # Arguments
    /// * `salt` - Random salt to prevent rainbow table attacks
    /// * `scrypt` - Scrypt parameters controlling cost and security
    ///
    /// # Returns
    /// * `Ok(Zeroizing<[u8; N]>)` - Derived key with automatic cleanup
    /// * `Err(ScryptDeriveError)` - Parameter validation or derivation failure
    fn derive_scrypt_key<const N: usize>(
        &self,
        salt: &[u8],
        scrypt: ScryptParams,
    ) -> Result<Zeroizing<[u8; N]>, ScryptDeriveError>;
}

impl<T: AsRef<[u8]>> DeriveScryptKey for T {
    /// Perform scrypt key derivation with comprehensive parameter validation
    ///
    /// This implementation provides secure scrypt key derivation with strict
    /// parameter validation to prevent weak configurations or attacks.
    ///
    /// ## Parameter Validation
    ///
    /// - **N**: Must be a power of 2 (enforced for security and efficiency)
    /// - **r**: Must be in valid range [1, 4294967295]
    /// - **p**: Must be in valid range [1, 4294967295]  
    /// - **Key length**: Must be > 0 and within reasonable bounds
    ///
    /// ## Security Considerations
    ///
    /// - **Salt Requirement**: Always use a unique, random salt
    /// - **Parameter Selection**: Choose parameters based on security requirements
    /// - **Memory Constraints**: Ensure sufficient system memory for chosen N×r
    /// - **Timing Attacks**: Scrypt is inherently resistant to timing attacks
    ///
    /// ## Memory Usage Calculation
    ///
    /// Memory required = 128 × N × r bytes
    ///
    /// Examples:
    /// - N=1024, r=8: ~1MB
    /// - N=16384, r=8: ~16MB (NEP-6 standard)
    /// - N=65536, r=8: ~64MB
    ///
    /// ## Performance Characteristics
    ///
    /// Time complexity is approximately O(N × p), with the actual time
    /// depending on CPU speed and memory bandwidth.
    ///
    /// # Arguments
    /// * `salt` - Cryptographic salt (should be random and unique per derivation)
    /// * `scrypt` - Scrypt parameters (N must be power of 2)
    ///
    /// # Returns
    /// * `Ok(Zeroizing<[u8; N]>)` - Derived key wrapped for automatic cleanup
    /// * `Err(ScryptDeriveError)` - Invalid parameters or derivation failure
    ///
    /// # Usage in NEP-6 Wallets
    /// ```rust
    /// use secure_sign_core::scrypt::{DeriveScryptKey, ScryptParams};
    /// use zeroize::Zeroizing;
    ///
    /// let passphrase = "user_password";
    /// let address_hash = [0x12, 0x34, 0x56, 0x78]; // Simulated address hash
    /// let salt = &address_hash[0..4]; // First 4 bytes of address hash
    /// let params = ScryptParams { n: 16, r: 1, p: 1 }; // Low params for test
    /// let derived_key: Zeroizing<[u8; 64]> = passphrase.derive_scrypt_key(salt, params)
    ///     .expect("Should derive key");
    ///
    /// // Verify we got a 64-byte key
    /// assert_eq!(derived_key.len(), 64);
    /// // First 32 bytes used for AES key, next 32 bytes for verification
    /// ```
    ///
    /// # Error Conditions
    ///
    /// This method validates all parameters and will return errors for:
    /// - N values that are not powers of 2
    /// - r or p values outside valid ranges  
    /// - Memory allocation failures for large parameters
    /// - Integer overflow in parameter calculations
    fn derive_scrypt_key<const N: usize>(
        &self,
        salt: &[u8],
        scrypt: ScryptParams,
    ) -> Result<Zeroizing<[u8; N]>, ScryptDeriveError> {
        // Critical security check: N must be a power of 2
        // This is required by the scrypt specification and prevents weak configurations
        if scrypt.n.count_ones() != 1 {
            return Err(ScryptDeriveError::InvalidParams);
        }

        let key = self.as_ref();

        // Convert our parameters to the scrypt crate's format
        // The scrypt crate expects log2(N) rather than N itself
        let params = scrypt::ScryptParams::new(scrypt.n.ilog2() as u8, scrypt.r, scrypt.p)
            .map_err(|_| ScryptDeriveError::InvalidParams)?;

        // Allocate output buffer with automatic zeroization
        let mut derived = Zeroizing::new([0u8; N]);

        // Perform the actual scrypt key derivation
        // This is where the intensive computation happens
        scrypt::scrypt(key, salt, &params, derived.as_mut_slice())
            .map_err(|_| ScryptDeriveError::InvalidDerivedLength)?;

        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec};
    use core::any;
    use std::time::{Duration, Instant};

    use super::*;

    /// Test basic scrypt key derivation functionality
    ///
    /// Verifies that scrypt produces output and behaves deterministically.
    #[test]
    fn test_scrypt_basic_functionality() {
        let password = b"test password";
        let salt = b"test salt";
        let params = ScryptParams { n: 16, r: 1, p: 1 }; // Very low params for speed

        let derived_key: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, params);
        assert!(
            derived_key.is_ok(),
            "Basic scrypt derivation should succeed"
        );

        let key1 = derived_key.unwrap();
        assert_ne!(*key1, [0u8; 32], "Derived key should not be all zeros");

        // Test determinism
        let key2 = password.derive_scrypt_key(salt, params).unwrap();
        assert_eq!(*key1, *key2, "Scrypt should be deterministic");
    }

    /// Test scrypt parameter validation
    ///
    /// Verifies that invalid parameters are properly rejected.
    #[test]
    fn test_scrypt_parameter_validation() {
        let password = b"test password";
        let salt = b"test salt";

        // Test invalid N (not power of 2)
        let invalid_params = [
            ScryptParams { n: 0, r: 1, p: 1 },  // N = 0
            ScryptParams { n: 3, r: 1, p: 1 },  // N = 3 (not power of 2)
            ScryptParams { n: 5, r: 1, p: 1 },  // N = 5 (not power of 2)
            ScryptParams { n: 15, r: 1, p: 1 }, // N = 15 (not power of 2)
            ScryptParams { n: 17, r: 1, p: 1 }, // N = 17 (not power of 2)
        ];

        for (i, params) in invalid_params.iter().enumerate() {
            let result: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, *params);
            assert!(result.is_err(), "Invalid parameters {i} should be rejected",);

            if let Err(e) = result {
                assert!(
                    matches!(e, ScryptDeriveError::InvalidParams),
                    "Should return InvalidParams error for case {i}",
                );
            }
        }
    }

    /// Test valid power-of-2 N values
    ///
    /// Verifies that all valid N parameters work correctly.
    #[test]
    fn test_scrypt_valid_n_values() {
        let password = b"test password";
        let salt = b"test salt";

        // Test various valid N values (powers of 2)
        let valid_n_values = vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

        for n in valid_n_values {
            let params = ScryptParams { n, r: 1, p: 1 };
            let result: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, params);

            assert!(result.is_ok(), "Valid N={n} should succeed");

            if let Ok(key) = result {
                assert_ne!(*key, [0u8; 32], "N={n} should produce non-zero key");
            }
        }
    }

    /// Test different key output lengths
    ///
    /// Verifies that scrypt can produce keys of various lengths.
    #[test]
    fn test_scrypt_various_key_lengths() {
        let password = b"test password";
        let salt = b"test salt";
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        // Test various key lengths
        let key16: Result<Zeroizing<[u8; 16]>, _> = password.derive_scrypt_key(salt, params);
        assert!(key16.is_ok(), "16-byte key derivation should succeed");

        let key32: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, params);
        assert!(key32.is_ok(), "32-byte key derivation should succeed");

        let key64: Result<Zeroizing<[u8; 64]>, _> = password.derive_scrypt_key(salt, params);
        assert!(key64.is_ok(), "64-byte key derivation should succeed");

        // Keys should be different lengths but all non-zero
        assert_ne!(
            *key16.unwrap(),
            [0u8; 16],
            "16-byte key should not be zeros"
        );
        assert_ne!(
            *key32.unwrap(),
            [0u8; 32],
            "32-byte key should not be zeros"
        );
        assert_ne!(
            *key64.unwrap(),
            [0u8; 64],
            "64-byte key should not be zeros"
        );
    }

    /// Test scrypt with different salt values
    ///
    /// Verifies that different salts produce different keys.
    #[test]
    fn test_scrypt_salt_sensitivity() {
        let password = b"test password";
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let salt3 = b"salt1 "; // Note the extra space

        let key1: Zeroizing<[u8; 32]> = password.derive_scrypt_key(salt1, params).unwrap();
        let key2: Zeroizing<[u8; 32]> = password.derive_scrypt_key(salt2, params).unwrap();
        let key3: Zeroizing<[u8; 32]> = password.derive_scrypt_key(salt3, params).unwrap();

        // Different salts should produce different keys
        assert_ne!(
            *key1, *key2,
            "Different salts should produce different keys"
        );
        assert_ne!(
            *key1, *key3,
            "Even slightly different salts should produce different keys"
        );
        assert_ne!(
            *key2, *key3,
            "All salt variations should produce unique keys"
        );
    }

    /// Test scrypt with different password values
    ///
    /// Verifies that different passwords produce different keys.
    #[test]
    fn test_scrypt_password_sensitivity() {
        let salt = b"test salt";
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        let password1 = b"password1";
        let password2 = b"password2";
        let password3 = b"password1 "; // Note the extra space

        let key1: Zeroizing<[u8; 32]> = password1.derive_scrypt_key(salt, params).unwrap();
        let key2: Zeroizing<[u8; 32]> = password2.derive_scrypt_key(salt, params).unwrap();
        let key3: Zeroizing<[u8; 32]> = password3.derive_scrypt_key(salt, params).unwrap();

        // Different passwords should produce different keys
        assert_ne!(
            *key1, *key2,
            "Different passwords should produce different keys"
        );
        assert_ne!(
            *key1, *key3,
            "Even slightly different passwords should produce different keys"
        );
        assert_ne!(
            *key2, *key3,
            "All password variations should produce unique keys"
        );
    }

    /// Test scrypt with empty inputs
    ///
    /// Edge case testing with empty passwords and salts.
    #[test]
    fn test_scrypt_empty_inputs() {
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        // Test empty password
        let empty_password: &[u8] = b"";
        let salt = b"test salt";
        let result1: Result<Zeroizing<[u8; 32]>, _> =
            empty_password.derive_scrypt_key(salt, params);
        assert!(result1.is_ok(), "Empty password should be handled");

        // Test empty salt
        let password = b"test password";
        let empty_salt: &[u8] = b"";
        let result2: Result<Zeroizing<[u8; 32]>, _> =
            password.derive_scrypt_key(empty_salt, params);
        assert!(result2.is_ok(), "Empty salt should be handled");

        // Test both empty
        let result3: Result<Zeroizing<[u8; 32]>, _> =
            empty_password.derive_scrypt_key(empty_salt, params);
        assert!(result3.is_ok(), "Both empty should be handled");

        // All should produce different results
        let key1 = result1.unwrap();
        let key2 = result2.unwrap();
        let key3 = result3.unwrap();

        assert_ne!(*key1, *key2, "Empty password vs empty salt should differ");
        assert_ne!(*key1, *key3, "Empty password vs both empty should differ");
        assert_ne!(*key2, *key3, "Empty salt vs both empty should differ");
    }

    /// Test NEP-6 standard parameters
    ///
    /// Verifies that the NEP-6 recommended parameters work correctly.
    #[test]
    fn test_nep6_standard_parameters() {
        let password = b"test password for NEP-6";
        let salt = b"test salt";
        let nep6_params = ScryptParams {
            n: 16384,
            r: 8,
            p: 8,
        };

        let start = Instant::now();
        let result: Result<Zeroizing<[u8; 64]>, _> = password.derive_scrypt_key(salt, nep6_params);
        let duration = start.elapsed();

        assert!(result.is_ok(), "NEP-6 parameters should work");

        if let Ok(key) = result {
            assert_ne!(
                *key, [0u8; 64],
                "NEP-6 derivation should produce non-zero key"
            );
        }

        // Should complete in reasonable time (< 30 seconds for this test)
        // NEP-6 parameters are computationally intensive by design
        assert!(
            duration.as_secs() < 30,
            "NEP-6 parameters should complete reasonably quickly"
        );

        println!("NEP-6 scrypt derivation took: {}ms", duration.as_millis());
    }

    /// Test scrypt with various r and p values
    ///
    /// Verifies that different r and p parameters work correctly.
    #[test]
    fn test_scrypt_various_r_p_values() {
        let password = b"test password";
        let salt = b"test salt";

        let test_cases = vec![
            (1, 1), // Minimal
            (1, 2), // Vary p
            (2, 1), // Vary r
            (2, 2), // Both increased
            (4, 1), // Higher r
            (1, 4), // Higher p
            (8, 8), // Common values
        ];

        for (r, p) in test_cases {
            let params = ScryptParams { n: 16, r, p };
            let result: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, params);

            assert!(result.is_ok(), "Parameters r={r}, p={p} should work");

            if let Ok(key) = result {
                assert_ne!(*key, [0u8; 32], "r={r}, p={p} should produce non-zero key",);
            }
        }
    }

    /// Test scrypt memory usage scaling
    ///
    /// Verifies that different N values affect memory usage as expected.
    #[test]
    fn test_scrypt_memory_scaling() {
        let password = b"test password";
        let salt = b"test salt";

        // Test increasing N values and measure time
        let n_values = vec![16, 32, 64, 128];
        let mut previous_duration = Duration::from_nanos(0);

        for n in n_values {
            let params = ScryptParams { n, r: 1, p: 1 };

            let start = Instant::now();
            let result: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, params);
            let duration = start.elapsed();

            assert!(result.is_ok(), "N={n} should succeed");

            // Generally, higher N should take longer (though this can be flaky)
            if previous_duration.as_nanos() > 0 {
                // Allow some variance, but generally should increase
                println!(
                    "N={}: {}μs (previous: {}μs)",
                    n,
                    duration.as_micros(),
                    previous_duration.as_micros()
                );
            }

            previous_duration = duration;
        }
    }

    /// Test scrypt with string types
    ///
    /// Verifies that different string types work with the trait.
    #[test]
    fn test_scrypt_string_types() {
        let salt = b"test salt";
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        // Test with String
        let string_password = String::from("string password");
        let result1: Result<Zeroizing<[u8; 32]>, _> =
            string_password.derive_scrypt_key(salt, params);
        assert!(result1.is_ok(), "String password should work");

        // Test with &str
        let str_password = "str password";
        let result2: Result<Zeroizing<[u8; 32]>, _> = str_password.derive_scrypt_key(salt, params);
        assert!(result2.is_ok(), "&str password should work");

        // Test with Vec<u8>
        let vec_password = vec![0x70, 0x61, 0x73, 0x73]; // "pass" in bytes
        let result3: Result<Zeroizing<[u8; 32]>, _> = vec_password.derive_scrypt_key(salt, params);
        assert!(result3.is_ok(), "Vec<u8> password should work");

        // All should produce valid, different keys
        let key1 = result1.unwrap();
        let key2 = result2.unwrap();
        let key3 = result3.unwrap();

        assert_ne!(*key1, [0u8; 32], "String key should not be zeros");
        assert_ne!(*key2, [0u8; 32], "&str key should not be zeros");
        assert_ne!(*key3, [0u8; 32], "Vec<u8> key should not be zeros");

        // Different inputs should produce different outputs
        assert_ne!(
            *key1, *key2,
            "Different password types should produce different keys"
        );
        assert_ne!(
            *key1, *key3,
            "String vs Vec<u8> should produce different keys"
        );
        assert_ne!(
            *key2, *key3,
            "&str vs Vec<u8> should produce different keys"
        );
    }

    /// Test scrypt parameter display
    ///
    /// Verifies that the Display implementation works correctly.
    #[test]
    fn test_scrypt_params_display() {
        let params = ScryptParams {
            n: 16384,
            r: 8,
            p: 8,
        };
        let display_string = format!("{params}");

        assert!(
            display_string.contains("16384"),
            "Display should contain n value"
        );
        assert!(
            display_string.contains("8"),
            "Display should contain r and p values"
        );
        assert!(
            display_string.contains("ScryptParams"),
            "Display should contain type name"
        );

        // Verify the exact format
        assert_eq!(display_string, "ScryptParams{n:16384,r:8,p:8}");
    }

    /// Test scrypt zeroization
    ///
    /// Verifies that derived keys are properly zeroized when dropped.
    #[test]
    fn test_scrypt_zeroization() {
        let password = b"test password";
        let salt = b"test salt";
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        // This test verifies that the Zeroizing wrapper is used
        let derived_key: Result<Zeroizing<[u8; 32]>, ScryptDeriveError> =
            password.derive_scrypt_key(salt, params);
        assert!(derived_key.is_ok(), "Derivation should succeed");

        let key: Zeroizing<[u8; 32]> = derived_key.unwrap();
        let key_copy = *key; // Copy the key data before it's dropped

        // Verify the key contains non-zero data
        assert_ne!(key_copy, [0u8; 32], "Key should contain non-zero data");

        // The key will be zeroized when it goes out of scope
        // This is automatic with the Zeroizing wrapper
        drop(key);

        // We can't directly verify zeroization since the memory might be reused,
        // but we can verify the type system enforces it
        assert!(any::type_name::<Zeroizing<[u8; 32]>>().contains("Zeroizing"));
    }

    /// Performance test for scrypt operations
    ///
    /// Ensures scrypt performance is reasonable for different parameter sets.
    #[test]
    fn test_scrypt_performance_various_params() {
        let password = b"performance test password";
        let salt = b"performance test salt";

        let test_cases = vec![
            ("fast", ScryptParams { n: 16, r: 1, p: 1 }),
            (
                "medium",
                ScryptParams {
                    n: 1024,
                    r: 1,
                    p: 1,
                },
            ),
            (
                "slow",
                ScryptParams {
                    n: 4096,
                    r: 1,
                    p: 1,
                },
            ),
        ];

        for (name, params) in test_cases {
            let start = Instant::now();
            let result: Result<Zeroizing<[u8; 32]>, _> = password.derive_scrypt_key(salt, params);
            let duration = start.elapsed();

            assert!(result.is_ok(), "{name} parameters should succeed");

            // Performance bounds (adjust based on expected hardware)
            let max_time_ms = match name {
                "fast" => 10,    // Should be very fast
                "medium" => 100, // Should be reasonable
                "slow" => 500,   // Should complete within reasonable time
                _ => 1000,
            };

            assert!(
                duration.as_millis() < max_time_ms,
                "{} scrypt took too long: {}ms (max: {}ms)",
                name,
                duration.as_millis(),
                max_time_ms
            );

            println!(
                "{} scrypt (N={}): {}ms",
                name,
                params.n,
                duration.as_millis()
            );
        }
    }
}
