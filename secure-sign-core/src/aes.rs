// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};

pub const AES256_KEY_SIZE: usize = 32;
// pub const AES128_KEY_SIZE: usize = 16;

const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, thiserror::Error)]
pub enum AesEcbError {
    #[error("aes-ecb: invalid data length")]
    InvalidDataLength,
}

pub trait Aes256EcbCipher {
    fn aes256_ecb_encrypt_aligned(&self, buf: &mut [u8]) -> Result<(), AesEcbError>;

    fn aes256_ecb_decrypt_aligned(&self, buf: &mut [u8]) -> Result<(), AesEcbError>;
}

impl Aes256EcbCipher for [u8] {
    fn aes256_ecb_encrypt_aligned(&self, data: &mut [u8]) -> Result<(), AesEcbError> {
        let cipher = Aes256::new_from_slice(self).expect("aes256 key length is 32-bytes");
        if data.len() % AES_BLOCK_SIZE != 0 {
            return Err(AesEcbError::InvalidDataLength);
        }

        data.chunks_mut(AES_BLOCK_SIZE)
            .map(GenericArray::from_mut_slice)
            .for_each(|block| cipher.encrypt_block(block));
        Ok(())
    }

    fn aes256_ecb_decrypt_aligned(&self, data: &mut [u8]) -> Result<(), AesEcbError> {
        let cipher = Aes256::new_from_slice(self).expect("aes256 key length is 32-bytes");
        if data.len() % AES_BLOCK_SIZE != 0 {
            return Err(AesEcbError::InvalidDataLength);
        }

        data.chunks_mut(AES_BLOCK_SIZE)
            .map(GenericArray::from_mut_slice)
            .for_each(|block| cipher.decrypt_block(block));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Test AES-256 ECB encryption and decryption basic functionality
    ///
    /// Verifies that encryption and decryption work correctly with aligned data.
    #[test]
    fn test_aes256_ecb_basic_encrypt_decrypt() {
        // 32-byte key for AES-256
        let key = [0x42u8; AES256_KEY_SIZE];

        // 16-byte block of data
        let original_data = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];

        let mut data = original_data;

        // Encrypt the data
        let result = key.aes256_ecb_encrypt_aligned(&mut data);
        assert!(result.is_ok(), "Encryption should succeed");

        // Data should be changed after encryption
        assert_ne!(
            data, original_data,
            "Encrypted data should be different from original"
        );

        // Decrypt the data
        let result = key.aes256_ecb_decrypt_aligned(&mut data);
        assert!(result.is_ok(), "Decryption should succeed");

        // Data should be restored to original
        assert_eq!(data, original_data, "Decrypted data should match original");
    }

    /// Test AES-256 ECB with zero key and data
    ///
    /// Verifies that zero inputs work correctly.
    #[test]
    fn test_aes256_ecb_zero_key_data() {
        let zero_key = [0u8; AES256_KEY_SIZE];
        let mut zero_data = [0u8; AES_BLOCK_SIZE];
        let original_zero_data = zero_data;

        // Encrypt zero data with zero key
        let result = zero_key.aes256_ecb_encrypt_aligned(&mut zero_data);
        assert!(result.is_ok(), "Zero key encryption should succeed");

        // Even zero data should change when encrypted (unless it's the specific AES zero block)
        // We can't predict the exact result, but it should be deterministic
        let encrypted_zero = zero_data;

        // Decrypt back
        let result = zero_key.aes256_ecb_decrypt_aligned(&mut zero_data);
        assert!(result.is_ok(), "Zero key decryption should succeed");
        assert_eq!(zero_data, original_zero_data, "Should decrypt back to zero");
    }

    /// Test AES-256 ECB with maximum values
    ///
    /// Verifies that maximum values work correctly.
    #[test]
    fn test_aes256_ecb_max_values() {
        let max_key = [0xffu8; AES256_KEY_SIZE];
        let mut max_data = [0xffu8; AES_BLOCK_SIZE];
        let original_max_data = max_data;

        // Encrypt maximum values
        let result = max_key.aes256_ecb_encrypt_aligned(&mut max_data);
        assert!(result.is_ok(), "Max value encryption should succeed");
        assert_ne!(
            max_data, original_max_data,
            "Encrypted max data should be different"
        );

        // Decrypt back
        let result = max_key.aes256_ecb_decrypt_aligned(&mut max_data);
        assert!(result.is_ok(), "Max value decryption should succeed");
        assert_eq!(
            max_data, original_max_data,
            "Should decrypt back to max values"
        );
    }

    /// Test AES-256 ECB with multiple blocks
    ///
    /// Verifies that multiple blocks are processed correctly.
    #[test]
    fn test_aes256_ecb_multiple_blocks() {
        let key = [0x5au8; AES256_KEY_SIZE];

        // Create 3 blocks of data (48 bytes)
        let mut data = Vec::with_capacity(AES_BLOCK_SIZE * 3);
        data.extend_from_slice(&[0x01; AES_BLOCK_SIZE]);
        data.extend_from_slice(&[0x02; AES_BLOCK_SIZE]);
        data.extend_from_slice(&[0x03; AES_BLOCK_SIZE]);

        let original_data = data.clone();

        // Encrypt all blocks
        let result = key.aes256_ecb_encrypt_aligned(&mut data);
        assert!(result.is_ok(), "Multi-block encryption should succeed");
        assert_ne!(
            data, original_data,
            "Encrypted multi-block data should be different"
        );

        // Each block should be encrypted differently (ECB mode)
        assert_ne!(
            &data[0..16],
            &data[16..32],
            "Different blocks should encrypt differently"
        );
        assert_ne!(
            &data[16..32],
            &data[32..48],
            "Different blocks should encrypt differently"
        );

        // Decrypt all blocks
        let result = key.aes256_ecb_decrypt_aligned(&mut data);
        assert!(result.is_ok(), "Multi-block decryption should succeed");
        assert_eq!(
            data, original_data,
            "Should decrypt back to original multi-block data"
        );
    }

    /// Test AES-256 ECB error cases
    ///
    /// Verifies that invalid data lengths are rejected.
    #[test]
    fn test_aes256_ecb_error_cases() {
        let key = [0x3cu8; AES256_KEY_SIZE];

        // Test with unaligned data lengths
        let test_cases = vec![
            1,  // Too short
            8,  // Half block
            15, // Almost a block
            17, // Block + 1
            24, // Block + half block
            31, // Almost 2 blocks
            33, // 2 blocks + 1
        ];

        for invalid_len in test_cases {
            let mut invalid_data = vec![0x42u8; invalid_len];

            // Encryption should fail
            let result = key.aes256_ecb_encrypt_aligned(&mut invalid_data);
            assert!(
                result.is_err(),
                "Encryption should fail for length {invalid_len}"
            );
            assert!(
                matches!(result.unwrap_err(), AesEcbError::InvalidDataLength),
                "Should return InvalidDataLength error for length {invalid_len}"
            );

            // Decryption should also fail
            let result = key.aes256_ecb_decrypt_aligned(&mut invalid_data);
            assert!(
                result.is_err(),
                "Decryption should fail for length {invalid_len}"
            );
            assert!(
                matches!(result.unwrap_err(), AesEcbError::InvalidDataLength),
                "Should return InvalidDataLength error for length {invalid_len}"
            );
        }
    }

    /// Test AES-256 ECB with valid aligned lengths
    ///
    /// Verifies that all multiples of 16 bytes work correctly.
    #[test]
    fn test_aes256_ecb_valid_lengths() {
        let key = [0x7bu8; AES256_KEY_SIZE];

        // Test various valid lengths (multiples of 16)
        let valid_lengths = vec![16, 32, 48, 64, 80, 96, 112, 128, 160, 256];

        for len in valid_lengths {
            let mut data = vec![0x99u8; len];
            let original_data = data.clone();

            // Encryption should succeed
            let result = key.aes256_ecb_encrypt_aligned(&mut data);
            assert!(result.is_ok(), "Encryption should succeed for length {len}");
            assert_ne!(
                data, original_data,
                "Data should change after encryption for length {len}"
            );

            // Decryption should succeed and restore original
            let result = key.aes256_ecb_decrypt_aligned(&mut data);
            assert!(result.is_ok(), "Decryption should succeed for length {len}");
            assert_eq!(
                data, original_data,
                "Should decrypt to original for length {len}"
            );
        }
    }

    /// Test AES-256 ECB determinism
    ///
    /// Verifies that encryption/decryption is deterministic.
    #[test]
    fn test_aes256_ecb_determinism() {
        let key = [0x9au8; AES256_KEY_SIZE];
        let original_data = [
            0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];

        // Encrypt the same data multiple times
        let mut data1 = original_data;
        let mut data2 = original_data;
        let mut data3 = original_data;

        key.aes256_ecb_encrypt_aligned(&mut data1).unwrap();
        key.aes256_ecb_encrypt_aligned(&mut data2).unwrap();
        key.aes256_ecb_encrypt_aligned(&mut data3).unwrap();

        // All encrypted results should be identical
        assert_eq!(data1, data2, "Encryption should be deterministic");
        assert_eq!(data2, data3, "Encryption should be deterministic");

        // Decrypt all and verify they return to original
        key.aes256_ecb_decrypt_aligned(&mut data1).unwrap();
        key.aes256_ecb_decrypt_aligned(&mut data2).unwrap();
        key.aes256_ecb_decrypt_aligned(&mut data3).unwrap();

        assert_eq!(data1, original_data, "Decryption should be deterministic");
        assert_eq!(data2, original_data, "Decryption should be deterministic");
        assert_eq!(data3, original_data, "Decryption should be deterministic");
    }

    /// Test AES-256 ECB with different key patterns
    ///
    /// Verifies that different keys produce different ciphertexts.
    #[test]
    fn test_aes256_ecb_different_keys() {
        let data = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];

        // Create different keys
        let key1 = [0x01u8; AES256_KEY_SIZE];
        let key2 = [0x02u8; AES256_KEY_SIZE];
        let key3 = [0xffu8; AES256_KEY_SIZE];

        let mut data1 = data;
        let mut data2 = data;
        let mut data3 = data;

        // Encrypt with different keys
        key1.aes256_ecb_encrypt_aligned(&mut data1).unwrap();
        key2.aes256_ecb_encrypt_aligned(&mut data2).unwrap();
        key3.aes256_ecb_encrypt_aligned(&mut data3).unwrap();

        // Different keys should produce different ciphertexts
        assert_ne!(
            data1, data2,
            "Different keys should produce different ciphertexts"
        );
        assert_ne!(
            data2, data3,
            "Different keys should produce different ciphertexts"
        );
        assert_ne!(
            data1, data3,
            "Different keys should produce different ciphertexts"
        );

        // But each should decrypt correctly with its own key
        key1.aes256_ecb_decrypt_aligned(&mut data1).unwrap();
        key2.aes256_ecb_decrypt_aligned(&mut data2).unwrap();
        key3.aes256_ecb_decrypt_aligned(&mut data3).unwrap();

        assert_eq!(data1, data, "Key1 should decrypt correctly");
        assert_eq!(data2, data, "Key2 should decrypt correctly");
        assert_eq!(data3, data, "Key3 should decrypt correctly");
    }

    /// Test AES-256 ECB trait implementation on different slice types
    ///
    /// Verifies that the trait works with various slice types.
    #[test]
    fn test_aes256_ecb_trait_slice_types() {
        let key_array = [0x6du8; AES256_KEY_SIZE];
        let key_vec = vec![0x6du8; AES256_KEY_SIZE];
        let mut data = [
            0x87, 0x65, 0x43, 0x21, 0xfe, 0xdc, 0xba, 0x98, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let original_data = data;

        // Test with array slice
        let result = key_array.as_slice().aes256_ecb_encrypt_aligned(&mut data);
        assert!(result.is_ok(), "Array slice should work for encryption");

        let result = key_array.as_slice().aes256_ecb_decrypt_aligned(&mut data);
        assert!(result.is_ok(), "Array slice should work for decryption");
        assert_eq!(data, original_data, "Array slice round-trip should work");

        // Test with Vec slice
        let result = key_vec.as_slice().aes256_ecb_encrypt_aligned(&mut data);
        assert!(result.is_ok(), "Vec slice should work for encryption");

        let result = key_vec.as_slice().aes256_ecb_decrypt_aligned(&mut data);
        assert!(result.is_ok(), "Vec slice should work for decryption");
        assert_eq!(data, original_data, "Vec slice round-trip should work");
    }

    /// Test AES-256 ECB error display
    ///
    /// Verifies that error messages are meaningful.
    #[test]
    fn test_aes_ecb_error_display() {
        let error = AesEcbError::InvalidDataLength;
        let error_msg = format!("{error}");
        assert!(
            error_msg.contains("invalid data length"),
            "Error should describe invalid data length"
        );

        // Test Debug implementation
        let debug_msg = format!("{error:?}");
        assert!(
            debug_msg.contains("InvalidDataLength"),
            "Debug should show error variant"
        );
    }

    /// Test AES-256 ECB constants
    ///
    /// Verifies that constants have expected values.
    #[test]
    fn test_aes_constants() {
        assert_eq!(AES256_KEY_SIZE, 32, "AES-256 key should be 32 bytes");
        assert_eq!(AES_BLOCK_SIZE, 16, "AES block size should be 16 bytes");
    }

    /// Test AES-256 ECB with real-world patterns
    ///
    /// Tests patterns that might appear in real cryptographic usage.
    #[test]
    fn test_aes256_ecb_realistic_patterns() {
        // Simulate NEP-6 wallet encryption pattern
        let password_derived_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x7e, 0x2b, 0xa5, 0x3f, 0xd5, 0x7a, 0x9b, 0x12, 0x84, 0x6f, 0x3a, 0x8c,
            0x9d, 0x4e, 0x5f, 0x6a,
        ];

        // Simulate private key data (32 bytes, needs padding to 48 for 3 blocks)
        let mut private_key_data = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00, // Padding to make it 48 bytes (3 AES blocks)
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x20, // Length in last byte
        ];

        let original_key_data = private_key_data.clone();

        // Encrypt the private key
        let result = password_derived_key.aes256_ecb_encrypt_aligned(&mut private_key_data);
        assert!(result.is_ok(), "Wallet encryption should succeed");
        assert_ne!(
            private_key_data, original_key_data,
            "Encrypted key should be different"
        );

        // Decrypt the private key
        let result = password_derived_key.aes256_ecb_decrypt_aligned(&mut private_key_data);
        assert!(result.is_ok(), "Wallet decryption should succeed");
        assert_eq!(
            private_key_data, original_key_data,
            "Decrypted key should match original"
        );
    }
}
