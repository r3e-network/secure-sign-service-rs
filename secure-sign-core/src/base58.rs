// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::{string::String, vec::Vec};

use ::base58::{FromBase58, FromBase58Error, ToBase58};

use crate::hash::Sha256;

pub trait ToBase58Check {
    fn to_base58_check(&self) -> String;
}

impl<T: AsRef<[u8]>> ToBase58Check for T {
    fn to_base58_check(&self) -> String {
        let mut buf = Vec::with_capacity(1 + self.as_ref().len() + 1 + 4);
        buf.extend(self.as_ref());

        let check = buf.sha256().sha256();
        buf.extend(&check[..4]);
        buf.to_base58()
    }
}

pub trait FromBase58Check: Sized {
    type Error;

    fn from_base58_check<T: AsRef<str>>(src: T) -> Result<Self, Self::Error>;
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum FromBase58CheckError {
    #[error("base58check: invalid character '{0}'")]
    InvalidChar(char),

    #[error("base58check: invalid length")]
    InvalidLength,

    #[error("base58check: invalid checksum")]
    InvalidChecksum,
}

impl FromBase58Check for Vec<u8> {
    type Error = FromBase58CheckError;

    fn from_base58_check<T: AsRef<str>>(src: T) -> Result<Vec<u8>, Self::Error> {
        const MIN_SIZE: usize = 5;
        const START_AT: usize = 0;

        let decoded = src.as_ref().from_base58().map_err(|err| match err {
            FromBase58Error::InvalidBase58Character(ch, _) => Self::Error::InvalidChar(ch),
            FromBase58Error::InvalidBase58Length => Self::Error::InvalidLength,
        })?;

        let s = decoded.as_slice();
        if s.len() < MIN_SIZE {
            return Err(Self::Error::InvalidLength);
        }

        let sha = (&s[..s.len() - 4]).sha256().sha256();
        if sha[..4] != s[s.len() - 4..] {
            return Err(Self::Error::InvalidChecksum);
        }

        Ok(s[START_AT..s.len() - 4].into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    /// Test Base58Check encoding and decoding round-trip
    ///
    /// Verifies that data can be encoded and decoded back to original.
    #[test]
    fn test_base58check_round_trip() {
        let test_data = b"Hello, Base58Check!";

        // Encode to Base58Check
        let encoded = test_data.to_base58_check();
        assert!(!encoded.is_empty(), "Encoded string should not be empty");

        // Decode back
        let decoded = Vec::<u8>::from_base58_check(&encoded).expect("Should decode successfully");
        assert_eq!(
            decoded,
            test_data.to_vec(),
            "Decoded data should match original"
        );
    }

    /// Test Base58Check with empty data
    ///
    /// Verifies that empty data encoding creates valid output, but decoding has minimum length requirements.
    #[test]
    fn test_base58check_empty_data() {
        let empty_data: &[u8] = &[];

        // Encode empty data
        let encoded = empty_data.to_base58_check();
        assert!(
            !encoded.is_empty(),
            "Even empty data should produce a checksum"
        );

        // However, decoding has a minimum length requirement (5 bytes including checksum)
        // Empty data + checksum = 4 bytes, which is less than minimum, so decoding will fail
        let decode_result = Vec::<u8>::from_base58_check(&encoded);
        assert!(
            decode_result.is_err(),
            "Empty data decoding should fail due to minimum length"
        );
        assert!(
            matches!(
                decode_result.unwrap_err(),
                FromBase58CheckError::InvalidLength
            ),
            "Should be InvalidLength error"
        );
    }

    /// Test Base58Check with single byte
    ///
    /// Verifies that single byte data works correctly.
    #[test]
    fn test_base58check_single_byte() {
        let single_byte = [0x42u8];

        let encoded = single_byte.to_base58_check();
        let decoded = Vec::<u8>::from_base58_check(&encoded).expect("Should decode single byte");
        assert_eq!(
            decoded,
            single_byte.to_vec(),
            "Single byte should round-trip"
        );
    }

    /// Test Base58Check with various data types
    ///
    /// Verifies that the trait works with different AsRef<[u8]> types.
    #[test]
    fn test_base58check_different_types() {
        let test_data = b"Test data";

        // Test with &[u8]
        let encoded1 = test_data.to_base58_check();

        // Test with Vec<u8>
        let vec_data = test_data.to_vec();
        let encoded2 = vec_data.to_base58_check();

        // Test with String bytes
        let string_data = "Test data";
        let encoded3 = string_data.as_bytes().to_base58_check();

        // All should produce the same encoding
        assert_eq!(
            encoded1, encoded2,
            "Vec and slice should encode identically"
        );
        assert_eq!(encoded2, encoded3, "String bytes should encode identically");

        // All should decode to the same data
        let decoded1 = Vec::<u8>::from_base58_check(&encoded1).unwrap();
        let decoded2 = Vec::<u8>::from_base58_check(&encoded2).unwrap();
        let decoded3 = Vec::<u8>::from_base58_check(&encoded3).unwrap();

        assert_eq!(decoded1, decoded2, "Should decode to same data");
        assert_eq!(decoded2, decoded3, "Should decode to same data");
        assert_eq!(decoded1, test_data.to_vec(), "Should match original");
    }

    /// Test Base58Check with binary data
    ///
    /// Verifies that binary data (not just text) works correctly.
    #[test]
    fn test_base58check_binary_data() {
        let binary_data = [0x00, 0x01, 0x7f, 0x80, 0xff, 0xaa, 0x55, 0x33];

        let encoded = binary_data.to_base58_check();
        let decoded = Vec::<u8>::from_base58_check(&encoded).expect("Should decode binary data");

        assert_eq!(
            decoded,
            binary_data.to_vec(),
            "Binary data should round-trip correctly"
        );
    }

    /// Test Base58Check with crypto-related data sizes
    ///
    /// Tests sizes commonly used in cryptographic contexts.
    #[test]
    fn test_base58check_crypto_sizes() {
        // Test 20-byte hash (RIPEMD160/Address)
        let hash_20 = [0x42u8; 20];
        let encoded_20 = hash_20.to_base58_check();
        let decoded_20 = Vec::<u8>::from_base58_check(&encoded_20).unwrap();
        assert_eq!(
            decoded_20,
            hash_20.to_vec(),
            "20-byte hash should round-trip"
        );

        // Test 32-byte hash (SHA-256)
        let hash_32 = [0x7au8; 32];
        let encoded_32 = hash_32.to_base58_check();
        let decoded_32 = Vec::<u8>::from_base58_check(&encoded_32).unwrap();
        assert_eq!(
            decoded_32,
            hash_32.to_vec(),
            "32-byte hash should round-trip"
        );

        // Test 33-byte compressed public key
        let pubkey_33 = [0x03u8; 33];
        let encoded_33 = pubkey_33.to_base58_check();
        let decoded_33 = Vec::<u8>::from_base58_check(&encoded_33).unwrap();
        assert_eq!(
            decoded_33,
            pubkey_33.to_vec(),
            "33-byte pubkey should round-trip"
        );
    }

    /// Test Base58Check determinism
    ///
    /// Verifies that encoding is deterministic and consistent.
    #[test]
    fn test_base58check_determinism() {
        let test_data = b"Determinism test data";

        // Encode multiple times
        let encoded1 = test_data.to_base58_check();
        let encoded2 = test_data.to_base58_check();
        let encoded3 = test_data.to_base58_check();

        // All encodings should be identical
        assert_eq!(encoded1, encoded2, "Encoding should be deterministic");
        assert_eq!(encoded2, encoded3, "Encoding should be deterministic");

        // Decoding should also be deterministic
        let decoded1 = Vec::<u8>::from_base58_check(&encoded1).unwrap();
        let decoded2 = Vec::<u8>::from_base58_check(&encoded2).unwrap();
        let decoded3 = Vec::<u8>::from_base58_check(&encoded3).unwrap();

        assert_eq!(decoded1, decoded2, "Decoding should be deterministic");
        assert_eq!(decoded2, decoded3, "Decoding should be deterministic");
    }

    /// Test Base58Check with invalid characters
    ///
    /// Verifies that invalid Base58 characters are rejected.
    #[test]
    fn test_base58check_invalid_chars() {
        // Base58 excludes 0, O, I, l to avoid confusion
        let invalid_strings = vec![
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0", // Contains '0'
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzO", // Contains 'O'
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzI", // Contains 'I'
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzl", // Contains 'l'
            "InvalidChar!",                                                // Contains '!'
            "Has Space",                                                   // Contains space
            "Has+Plus",                                                    // Contains '+'
            "Has/Slash",                                                   // Contains '/'
        ];

        for invalid_str in invalid_strings {
            let result = Vec::<u8>::from_base58_check(invalid_str);
            assert!(
                result.is_err(),
                "Should reject invalid character in: {invalid_str}"
            );

            if let Err(err) = result {
                assert!(
                    matches!(err, FromBase58CheckError::InvalidChar(_)),
                    "Should be InvalidChar error for: {invalid_str}"
                );
            }
        }
    }

    /// Test Base58Check with invalid length
    ///
    /// Verifies that too-short strings are rejected.
    #[test]
    fn test_base58check_invalid_length() {
        // Strings that are too short (less than minimum required for checksum)
        let short_strings = vec![
            "",     // Empty
            "1",    // 1 character
            "11",   // 2 characters
            "111",  // 3 characters
            "1111", // 4 characters (minimum is 5 for checksum)
        ];

        for short_str in short_strings {
            let result = Vec::<u8>::from_base58_check(short_str);
            assert!(
                result.is_err(),
                "Should reject too-short string: '{short_str}'"
            );

            if let Err(err) = result {
                assert!(
                    matches!(err, FromBase58CheckError::InvalidLength),
                    "Should be InvalidLength error for: '{short_str}'"
                );
            }
        }
    }

    /// Test Base58Check with invalid checksum
    ///
    /// Verifies that corrupted checksums are detected.
    #[test]
    fn test_base58check_invalid_checksum() {
        let original_data = b"Test checksum validation";
        let valid_encoded = original_data.to_base58_check();

        // Corrupt the checksum by changing the last character
        let mut corrupted = valid_encoded.clone();
        corrupted.pop(); // Remove last char
        corrupted.push('1'); // Add different char

        let result = Vec::<u8>::from_base58_check(&corrupted);
        assert!(result.is_err(), "Should reject corrupted checksum");

        if let Err(err) = result {
            assert!(
                matches!(err, FromBase58CheckError::InvalidChecksum),
                "Should be InvalidChecksum error"
            );
        }

        // Try corrupting different positions
        let chars: Vec<char> = valid_encoded.chars().collect();
        if chars.len() > 1 {
            for i in 0..chars.len() {
                let mut corrupted_chars = chars.clone();
                corrupted_chars[i] = if corrupted_chars[i] == '1' { '2' } else { '1' };
                let corrupted_str: String = corrupted_chars.into_iter().collect();

                let result = Vec::<u8>::from_base58_check(&corrupted_str);
                // This might be InvalidChar, InvalidLength, or InvalidChecksum depending on corruption
                assert!(
                    result.is_err(),
                    "Should reject corrupted string at position {i}"
                );
            }
        }
    }

    /// Test Base58Check error display
    ///
    /// Verifies that error messages are meaningful.
    #[test]
    fn test_base58check_error_display() {
        let invalid_char_error = FromBase58CheckError::InvalidChar('0');
        let error_msg = format!("{invalid_char_error}");
        assert!(
            error_msg.contains("invalid character '0'"),
            "Should describe invalid character"
        );

        let invalid_length_error = FromBase58CheckError::InvalidLength;
        let error_msg = format!("{invalid_length_error}");
        assert!(
            error_msg.contains("invalid length"),
            "Should describe invalid length"
        );

        let invalid_checksum_error = FromBase58CheckError::InvalidChecksum;
        let error_msg = format!("{invalid_checksum_error}");
        assert!(
            error_msg.contains("invalid checksum"),
            "Should describe invalid checksum"
        );

        // Test Debug implementation
        let debug_msg = format!("{invalid_char_error:?}");
        assert!(
            debug_msg.contains("InvalidChar"),
            "Debug should show error variant"
        );
    }

    /// Test Base58Check with real-world patterns
    ///
    /// Tests patterns that might appear in real blockchain usage.
    #[test]
    fn test_base58check_realistic_patterns() {
        // Simulate NEO address-like data (21 bytes: version + 20-byte hash)
        let address_data = [
            0x17, // Version byte
            0x62, 0xe8, 0x2d, 0x5e, 0x62, 0xa5, 0x4e, 0x3a, 0x95, 0x8b, 0xe2, 0x1d, 0xb4, 0x4d,
            0xf2, 0x3f, 0x8e, 0x7c, 0x9b, 0x4a,
        ];

        let encoded_address = address_data.to_base58_check();
        let decoded_address = Vec::<u8>::from_base58_check(&encoded_address).unwrap();
        assert_eq!(
            decoded_address,
            address_data.to_vec(),
            "Address should round-trip"
        );

        // Simulate private key export (32 bytes)
        let private_key = [
            0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x01, // WIF compression flag
        ];

        let encoded_key = private_key.to_base58_check();
        let decoded_key = Vec::<u8>::from_base58_check(&encoded_key).unwrap();
        assert_eq!(
            decoded_key,
            private_key.to_vec(),
            "Private key should round-trip"
        );
    }

    /// Test Base58Check trait bounds and generic usage
    ///
    /// Verifies that traits work correctly in generic contexts.
    #[test]
    fn test_base58check_generic_usage() {
        // Generic function using ToBase58Check
        fn encode_data<T: ToBase58Check>(data: T) -> String {
            data.to_base58_check()
        }

        // Generic function using FromBase58Check
        fn decode_data<T: FromBase58Check>(encoded: &str) -> Result<T, T::Error> {
            T::from_base58_check(encoded)
        }

        let test_data = b"Generic test";

        // Test encoding through generic function
        let encoded = encode_data(test_data);
        assert!(!encoded.is_empty(), "Generic encoding should work");

        // Test decoding through generic function
        let decoded: Vec<u8> = decode_data(&encoded).expect("Generic decoding should work");
        assert_eq!(
            decoded,
            test_data.to_vec(),
            "Generic round-trip should work"
        );
    }

    /// Test Base58Check with reasonably sized data
    ///
    /// Verifies that multi-byte data works correctly without hitting library limits.
    #[test]
    fn test_base58check_reasonably_sized_data() {
        // Create 64 bytes of data (reasonable size for base58)
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();

        let encoded = data.to_base58_check();
        let decoded =
            Vec::<u8>::from_base58_check(&encoded).expect("Should decode reasonably sized data");

        assert_eq!(decoded, data, "Data should round-trip correctly");
        assert!(
            encoded.len() > data.len(),
            "Encoded data should be longer than original"
        );

        // Test with a different pattern to ensure it's not just working for sequential data
        let pattern_data: Vec<u8> = (0..32).map(|i| (i * 7) as u8).collect();
        let encoded_pattern = pattern_data.to_base58_check();
        let decoded_pattern =
            Vec::<u8>::from_base58_check(&encoded_pattern).expect("Should decode pattern data");
        assert_eq!(
            decoded_pattern, pattern_data,
            "Pattern data should round-trip correctly"
        );
    }

    /// Test Base58Check checksum validation with edge cases
    ///
    /// Verifies that checksum validation works correctly in edge cases.
    #[test]
    fn test_base58check_checksum_edge_cases() {
        // Test with data that might produce tricky checksums
        // Note: minimum decoded length is 5 bytes (data + 4-byte checksum), so need at least 1 byte of data
        let edge_cases = vec![
            vec![0x00, 0x00, 0x00, 0x00, 0x00], // All zeros (5 bytes minimum)
            vec![0xff, 0xff, 0xff, 0xff, 0xff], // All ones (5 bytes minimum)
            vec![0x00, 0xff, 0x00, 0xff, 0x00], // Alternating pattern
            vec![0x01, 0x02, 0x03, 0x04, 0x05], // Sequential
            (0..64).collect::<Vec<u8>>(),       // Full range up to 64 bytes
        ];

        for edge_data in edge_cases {
            let encoded = edge_data.to_base58_check();
            let decoded =
                Vec::<u8>::from_base58_check(&encoded).expect("Edge case should round-trip");
            assert_eq!(decoded, edge_data, "Edge case data should match");
        }
    }
}
