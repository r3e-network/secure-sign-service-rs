// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};
use core::fmt::{Display, Formatter};

use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::bin::{BinEncoder, BinWriter};

pub const H160_SIZE: usize = 20;

/// little endian
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
#[repr(align(8))]
pub struct H160([u8; H160_SIZE]);

impl H160 {
    #[inline]
    pub fn from_le_bytes(src: [u8; H160_SIZE]) -> Self {
        H160(src)
    }

    #[inline]
    pub fn as_le_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; H160_SIZE]> for H160 {
    #[inline]
    fn as_ref(&self) -> &[u8; H160_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for H160 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for H160 {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        const TABLE: &[u8] = b"0123456789abcdef";
        let mut h = String::with_capacity(H160_SIZE * 2);
        self.0.iter().rev().for_each(|b| {
            h.push(TABLE[(b >> 4) as usize] as char);
            h.push(TABLE[(b & 0x0F) as usize] as char);
        });

        f.write_str("0x")?;
        f.write_str(&h)
    }
}

impl Default for H160 {
    #[inline]
    fn default() -> Self {
        Self([0u8; H160_SIZE])
    }
}

impl BinEncoder for H160 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.0);
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ToH160Error {
    #[error("to-h160: hex-encode H160's length must be 40(without '0x')")]
    InvalidLength,

    #[error("to-h160: invalid character '{0}'")]
    InvalidChar(char),
}

impl TryFrom<&str> for H160 {
    type Error = ToH160Error;

    /// value must be big-endian
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use hex::FromHexError as HexError;

        let value = value.trim_matches('"');
        let value = if value.starts_with("0x") || value.starts_with("0X") {
            &value[2..]
        } else {
            value
        };

        let mut buf = [0u8; H160_SIZE];
        hex::decode_to_slice(value, &mut buf).map_err(|err| match err {
            HexError::OddLength | HexError::InvalidStringLength => Self::Error::InvalidLength,
            HexError::InvalidHexCharacter { c, index: _ } => Self::Error::InvalidChar(c),
        })?;

        buf.reverse();
        Ok(Self(buf))
    }
}

impl Serialize for H160 {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for H160 {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        H160::try_from(value.as_str()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec::Vec};
    use core::hash::{Hash, Hasher};
    use core::mem;

    // Mock DefaultHasher for no-std environment
    #[derive(Default)]
    struct DefaultHasher(u64);

    impl DefaultHasher {
        fn new() -> Self {
            Self::default()
        }
    }

    impl Hasher for DefaultHasher {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            for &byte in bytes {
                self.0 = self.0.wrapping_mul(31).wrapping_add(byte as u64);
            }
        }
    }

    use super::*;

    /// Simple mock BinWriter for testing
    #[derive(Debug, Default)]
    struct SimpleBinWriter {
        buffer: Vec<u8>,
    }

    impl BinWriter for SimpleBinWriter {
        fn write_varint(&mut self, _value: u64) {
            // Simple implementation for testing
        }

        fn write<T: AsRef<[u8]>>(&mut self, value: T) {
            self.buffer.extend_from_slice(value.as_ref());
        }

        fn len(&self) -> usize {
            self.buffer.len()
        }
    }

    /// Test H160 constant values
    ///
    /// Verifies that the H160_SIZE constant is correct.
    #[test]
    fn test_h160_constants() {
        assert_eq!(H160_SIZE, 20, "H160_SIZE should be 20 bytes");
    }

    /// Test H160 creation from little-endian bytes
    ///
    /// Verifies that H160 can be created from a 20-byte array.
    #[test]
    fn test_h160_from_le_bytes() {
        let test_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];

        let h160 = H160::from_le_bytes(test_bytes);
        assert_eq!(
            h160.as_le_bytes(),
            &test_bytes,
            "Should preserve input bytes"
        );
    }

    /// Test H160 default implementation
    ///
    /// Verifies that default H160 is all zeros.
    #[test]
    fn test_h160_default() {
        let default_h160 = H160::default();
        let zero_bytes = [0u8; 20];

        assert_eq!(
            default_h160.as_le_bytes(),
            &zero_bytes,
            "Default should be all zeros"
        );
        let array_ref: &[u8; 20] = default_h160.as_ref();
        assert_eq!(*array_ref, zero_bytes, "AsRef should match default");
    }

    /// Test H160 as_le_bytes method
    ///
    /// Verifies that as_le_bytes returns the correct byte slice.
    #[test]
    fn test_h160_as_le_bytes() {
        let test_bytes = [0xaa; 20]; // All bytes set to 0xaa
        let h160 = H160::from_le_bytes(test_bytes);

        assert_eq!(
            h160.as_le_bytes(),
            &test_bytes,
            "as_le_bytes should return original bytes"
        );
        assert_eq!(h160.as_le_bytes().len(), 20, "Should return 20 bytes");
    }

    /// Test AsRef implementations
    ///
    /// Verifies that both AsRef<[u8; 20]> and AsRef<[u8]> work correctly.
    #[test]
    fn test_h160_as_ref() {
        let test_bytes = [0x42; 20];
        let h160 = H160::from_le_bytes(test_bytes);

        // Test AsRef<[u8; 20]>
        let array_ref: &[u8; 20] = h160.as_ref();
        assert_eq!(*array_ref, test_bytes, "AsRef<[u8; 20]> should work");

        // Test AsRef<[u8]>
        let slice_ref: &[u8] = h160.as_ref();
        assert_eq!(slice_ref, &test_bytes[..], "AsRef<[u8]> should work");
        assert_eq!(slice_ref.len(), 20, "Slice should have correct length");
    }

    /// Test H160 Display implementation
    ///
    /// Verifies that H160 displays as hex with proper formatting.
    #[test]
    fn test_h160_display() {
        // Test zero hash
        let zero_h160 = H160::default();
        let zero_str = format!("{zero_h160}");
        assert_eq!(
            zero_str, "0x0000000000000000000000000000000000000000",
            "Zero hash should display correctly"
        );

        // Test all-ones hash
        let ones_h160 = H160::from_le_bytes([0xff; 20]);
        let ones_str = format!("{ones_h160}");
        assert_eq!(
            ones_str, "0xffffffffffffffffffffffffffffffffffffffff",
            "All-ones hash should display correctly"
        );

        // Test specific pattern
        let test_bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c,
        ];
        let pattern_h160 = H160::from_le_bytes(test_bytes);
        let pattern_str = format!("{pattern_h160}");

        // Note: Display reverses bytes (big-endian display)
        assert_eq!(
            pattern_str, "0x3c2d1e0f1032547698badcfeefcdab8967452301",
            "Pattern should display in big-endian format"
        );

        // Verify it starts with 0x
        assert!(pattern_str.starts_with("0x"), "Should start with 0x prefix");
        assert_eq!(
            pattern_str.len(),
            42,
            "Should have correct length (2 + 40 hex chars)"
        );
    }

    /// Test H160 equality and comparison
    ///
    /// Verifies that equality works correctly for H160.
    #[test]
    fn test_h160_equality() {
        let bytes1 = [0x42; 20];
        let bytes2 = [0x42; 20];
        let bytes3 = [0x43; 20];

        let h160_1 = H160::from_le_bytes(bytes1);
        let h160_2 = H160::from_le_bytes(bytes2);
        let h160_3 = H160::from_le_bytes(bytes3);

        // Test equality
        assert_eq!(h160_1, h160_2, "Same bytes should be equal");
        assert_ne!(h160_1, h160_3, "Different bytes should not be equal");

        // Test self-equality
        assert_eq!(h160_1, h160_1, "Should be equal to itself");
    }

    /// Test H160 Clone and Copy traits
    ///
    /// Verifies that H160 can be copied and cloned correctly.
    #[test]
    fn test_h160_clone_copy() {
        let original_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd,
        ];

        let original = H160::from_le_bytes(original_bytes);

        // Test Copy trait
        let copied = original;
        assert_eq!(copied, original, "Copy should create identical instance");
        assert_eq!(
            copied.as_le_bytes(),
            original.as_le_bytes(),
            "Copied bytes should match"
        );

        // Test Clone trait
        let cloned = original;
        assert_eq!(cloned, original, "Clone should create identical instance");
        assert_eq!(
            cloned.as_le_bytes(),
            original.as_le_bytes(),
            "Cloned bytes should match"
        );
    }

    /// Test H160 Hash trait
    ///
    /// Verifies that H160 can be used as a hash map key.
    #[test]
    fn test_h160_hash() {
        let bytes1 = [0x01; 20];
        let bytes2 = [0x02; 20];

        let h160_1 = H160::from_le_bytes(bytes1);
        let h160_2 = H160::from_le_bytes(bytes2);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        let mut hasher3 = DefaultHasher::new();

        h160_1.hash(&mut hasher1);
        h160_2.hash(&mut hasher2);
        h160_1.hash(&mut hasher3);

        let hash1 = hasher1.finish();
        let hash2 = hasher2.finish();
        let hash3 = hasher3.finish();

        assert_ne!(hash1, hash2, "Different H160 should have different hashes");
        assert_eq!(hash1, hash3, "Same H160 should have same hash");
    }

    /// Test H160 Debug trait
    ///
    /// Verifies that Debug formatting works correctly.
    #[test]
    fn test_h160_debug() {
        let test_bytes = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x12, 0x34,
            0x56, 0x78, 0xab, 0xcd, 0xef, 0x01,
        ];

        let h160 = H160::from_le_bytes(test_bytes);
        let debug_str = format!("{h160:?}");

        // Debug should show the struct name and array contents
        assert!(debug_str.contains("H160"), "Debug should show struct name");
        assert!(
            debug_str.contains("222"),
            "Debug should show byte value for 0xde"
        );
        assert!(
            debug_str.contains("173"),
            "Debug should show byte value for 0xad"
        );
    }

    /// Test BinEncoder implementation
    ///
    /// Verifies that H160 can be binary encoded correctly.
    #[test]
    fn test_h160_bin_encoder() {
        let test_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];

        let h160 = H160::from_le_bytes(test_bytes);
        let mut writer = SimpleBinWriter::default();

        h160.encode_bin(&mut writer);

        assert_eq!(
            writer.buffer, test_bytes,
            "Binary encoding should preserve exact bytes"
        );
        assert_eq!(writer.buffer.len(), 20, "Should encode exactly 20 bytes");
    }

    /// Test H160 TryFrom<&str> implementation
    ///
    /// Verifies that H160 can be parsed from hex strings.
    #[test]
    fn test_h160_try_from_str() {
        // Test basic hex string parsing
        let hex_str = "0x1234567890abcdef1234567890abcdef12345678";
        let h160 = H160::try_from(hex_str).expect("Should parse valid hex");

        // Verify it produces expected bytes (note: hex is big-endian, stored little-endian)
        let expected_le = [
            0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd,
            0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
        ];
        let array_ref: &[u8; 20] = h160.as_ref();
        assert_eq!(
            *array_ref, expected_le,
            "Should convert big-endian hex to little-endian bytes"
        );

        // Test without 0x prefix
        let hex_str_no_prefix = "1234567890abcdef1234567890abcdef12345678";
        let h160_no_prefix =
            H160::try_from(hex_str_no_prefix).expect("Should parse hex without 0x");
        assert_eq!(
            h160, h160_no_prefix,
            "With and without 0x prefix should be equal"
        );

        // Test uppercase hex
        let hex_str_upper = "0X1234567890ABCDEF1234567890ABCDEF12345678";
        let h160_upper = H160::try_from(hex_str_upper).expect("Should parse uppercase hex");
        assert_eq!(
            h160, h160_upper,
            "Uppercase and lowercase hex should be equal"
        );

        // Test with quotes
        let hex_str_quoted = "\"0x1234567890abcdef1234567890abcdef12345678\"";
        let h160_quoted = H160::try_from(hex_str_quoted).expect("Should parse quoted hex");
        assert_eq!(h160, h160_quoted, "Quoted and unquoted hex should be equal");
    }

    /// Test H160 TryFrom<&str> error cases
    ///
    /// Verifies that invalid hex strings are properly rejected.
    #[test]
    fn test_h160_try_from_str_errors() {
        // Test invalid length (too short)
        let result = H160::try_from("0x123456");
        assert!(
            matches!(result, Err(ToH160Error::InvalidLength)),
            "Should reject too-short hex string"
        );

        // Test invalid length (too long)
        let result = H160::try_from("0x1234567890abcdef1234567890abcdef1234567890");
        assert!(
            matches!(result, Err(ToH160Error::InvalidLength)),
            "Should reject too-long hex string"
        );

        // Test odd length
        let result = H160::try_from("0x123456789");
        assert!(
            matches!(result, Err(ToH160Error::InvalidLength)),
            "Should reject odd-length hex string"
        );

        // Test invalid characters
        let result = H160::try_from("0x1234567890abcdef1234567890abcdef1234567g");
        assert!(
            matches!(result, Err(ToH160Error::InvalidChar('g'))),
            "Should reject invalid hex character"
        );

        // Test empty string
        let result = H160::try_from("");
        assert!(
            matches!(result, Err(ToH160Error::InvalidLength)),
            "Should reject empty string"
        );
    }

    /// Test H160 serialization and deserialization
    ///
    /// Verifies that H160 can be serialized to and from JSON.
    #[test]
    fn test_h160_serde() {
        let test_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        let h160 = H160::from_le_bytes(test_bytes);

        // Test serialization
        let serialized = serde_json::to_string(&h160).expect("Should serialize");

        // Should serialize as hex string
        assert!(serialized.contains("0x"), "Should serialize with 0x prefix");
        assert_eq!(
            serialized.len(),
            44,
            "Should serialize to correct length (quotes + 0x + 40 chars)"
        );

        // Test deserialization
        let deserialized: H160 = serde_json::from_str(&serialized).expect("Should deserialize");
        assert_eq!(
            h160, deserialized,
            "Deserialized value should match original"
        );

        // Test round-trip
        let serialized2 = serde_json::to_string(&deserialized).expect("Should serialize again");
        assert_eq!(serialized, serialized2, "Round-trip should be consistent");
    }

    /// Test ToH160Error display
    ///
    /// Verifies that error messages are meaningful.
    #[test]
    fn test_to_h160_error_display() {
        let invalid_length_error = ToH160Error::InvalidLength;
        let error_msg = format!("{invalid_length_error}");
        assert!(
            error_msg.contains("length must be 40"),
            "Should describe length requirement"
        );

        let invalid_char_error = ToH160Error::InvalidChar('z');
        let error_msg = format!("{invalid_char_error}");
        assert!(
            error_msg.contains("invalid character 'z'"),
            "Should describe invalid character"
        );
    }

    /// Test H160 memory layout and alignment
    ///
    /// Verifies that H160 has the expected memory characteristics.
    #[test]
    fn test_h160_memory_characteristics() {
        // Size should be 24 bytes due to 8-byte alignment
        assert_eq!(
            mem::size_of::<H160>(),
            24,
            "H160 should be 24 bytes due to alignment"
        );

        // Alignment should be 8 bytes as specified
        assert_eq!(
            mem::align_of::<H160>(),
            8,
            "H160 should have 8-byte alignment"
        );

        // Should have expected memory layout
        assert!(
            mem::size_of::<H160>() >= mem::size_of::<[u8; 20]>(),
            "H160 should be at least as large as the underlying array"
        );
    }

    /// Test H160 with boundary values
    ///
    /// Verifies behavior with min/max values.
    #[test]
    fn test_h160_boundary_values() {
        // Test minimum value (all zeros)
        let min_h160 = H160::from_le_bytes([0x00; 20]);
        assert_eq!(min_h160, H160::default(), "Min value should equal default");

        // Test maximum value (all 0xff)
        let max_h160 = H160::from_le_bytes([0xff; 20]);
        assert_ne!(
            max_h160,
            H160::default(),
            "Max value should not equal default"
        );

        // Test that they're different
        assert_ne!(min_h160, max_h160, "Min and max should be different");

        // Test display of boundary values
        let min_str = format!("{min_h160}");
        let max_str = format!("{max_h160}");
        assert_eq!(
            min_str.len(),
            max_str.len(),
            "Min and max should have same display length"
        );
    }

    /// Test H160 with realistic script hash values
    ///
    /// Tests with values that might actually appear as NEO script hashes.
    #[test]
    fn test_h160_realistic_values() {
        // Simulate a realistic NEO script hash (RIPEMD160 of SHA256)
        let script_hash_like = [
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65,
        ];

        let hash = H160::from_le_bytes(script_hash_like);

        // Should not be zero
        assert_ne!(hash, H160::default(), "Real hash should not be zero");

        // Should be deterministic
        let hash2 = H160::from_le_bytes(script_hash_like);
        assert_eq!(hash, hash2, "Same input should produce same hash");

        // Should format correctly
        let hex_str = format!("{hash}");
        assert!(hex_str.starts_with("0x"), "Should have hex prefix");
        assert_eq!(hex_str.len(), 42, "Should have correct hex length");

        // Should be parseable back
        let parsed = H160::try_from(hex_str.as_str()).expect("Should parse back");
        assert_eq!(hash, parsed, "Parsing display should round-trip");
    }

    /// Test H160 edge cases in display and parsing
    ///
    /// Tests edge cases that might cause issues.
    #[test]
    fn test_h160_edge_cases() {
        // Test single non-zero byte at different positions
        let mut bytes = [0u8; 20];

        // First byte
        bytes[0] = 0x01;
        let h1 = H160::from_le_bytes(bytes);
        let display1 = format!("{h1}");
        assert!(
            display1.ends_with("01"),
            "Should end with 01 when first byte is 0x01"
        );

        // Last byte
        bytes = [0u8; 20];
        bytes[19] = 0xff;
        let h2 = H160::from_le_bytes(bytes);
        let display2 = format!("{h2}");
        assert!(
            display2.starts_with("0xff"),
            "Should start with ff when last byte is 0xff"
        );

        // Mixed case - verify hex characters are lowercase
        bytes = [0xab; 20];
        let h3 = H160::from_le_bytes(bytes);
        let display3 = format!("{h3}");
        assert!(
            display3.contains("ab"),
            "Should use lowercase hex characters"
        );
        assert!(
            !display3.contains("AB"),
            "Should not use uppercase hex characters"
        );
    }
}
