// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::String;
use core::fmt::{Display, Formatter};

use crate::bin::{BinEncoder, BinWriter};

pub const H256_SIZE: usize = 32;

/// little endian
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct H256([u8; H256_SIZE]);

impl H256 {
    pub fn from_le_bytes(src: [u8; H256_SIZE]) -> Self {
        H256(src)
    }

    pub fn as_le_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; H256_SIZE]> for H256 {
    #[inline]
    fn as_ref(&self) -> &[u8; H256_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for H256 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for H256 {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        const TABLE: &[u8] = b"0123456789abcdef";
        let mut h = String::with_capacity(H256_SIZE * 2);
        self.0.iter().rev().for_each(|b| {
            h.push(TABLE[(b >> 4) as usize] as char);
            h.push(TABLE[(b & 0x0F) as usize] as char);
        });

        f.write_str("0x")?;
        f.write_str(&h)
    }
}

impl Default for H256 {
    #[inline]
    fn default() -> Self {
        Self([0u8; H256_SIZE])
    }
}

impl BinEncoder for H256 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.0);
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::ToString, vec::Vec};
    use core::hash::{Hash, Hasher};

    // Mock DefaultHasher for no-std environment
    struct DefaultHasher(u64);

    impl Default for DefaultHasher {
        fn default() -> Self {
            DefaultHasher(0)
        }
    }

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

    /// Mock BinWriter implementation for testing binary encoding
    #[derive(Debug, Default)]
    struct MockBinWriter {
        buffer: Vec<u8>,
    }

    impl BinWriter for MockBinWriter {
        fn write_varint(&mut self, value: u64) {
            let (size, buf): (u8, [u8; 9]) = crate::bin::to_varint_le(value);
            self.buffer.extend_from_slice(&buf[..size as usize]);
        }

        fn write<T: AsRef<[u8]>>(&mut self, value: T) {
            self.buffer.extend_from_slice(value.as_ref());
        }

        fn len(&self) -> usize {
            self.buffer.len()
        }
    }

    /// Test H256 constant values
    ///
    /// Verifies that the H256_SIZE constant is correct.
    #[test]
    fn test_h256_constants() {
        assert_eq!(H256_SIZE, 32, "H256_SIZE should be 32 bytes");
    }

    /// Test H256 creation from little-endian bytes
    ///
    /// Verifies that H256 can be created from a 32-byte array.
    #[test]
    fn test_h256_from_le_bytes() {
        let test_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let h256 = H256::from_le_bytes(test_bytes);
        assert_eq!(
            h256.as_le_bytes(),
            &test_bytes,
            "Should preserve input bytes"
        );
    }

    /// Test H256 default implementation
    ///
    /// Verifies that default H256 is all zeros.
    #[test]
    fn test_h256_default() {
        let default_h256 = H256::default();
        let zero_bytes = [0u8; 32];

        assert_eq!(
            default_h256.as_le_bytes(),
            &zero_bytes,
            "Default should be all zeros"
        );
        let array_ref: &[u8; 32] = default_h256.as_ref();
        assert_eq!(*array_ref, zero_bytes, "AsRef should match default");
    }

    /// Test H256 as_le_bytes method
    ///
    /// Verifies that as_le_bytes returns the correct byte slice.
    #[test]
    fn test_h256_as_le_bytes() {
        let test_bytes = [0xaa; 32]; // All bytes set to 0xaa
        let h256 = H256::from_le_bytes(test_bytes);

        assert_eq!(
            h256.as_le_bytes(),
            &test_bytes,
            "as_le_bytes should return original bytes"
        );
        assert_eq!(h256.as_le_bytes().len(), 32, "Should return 32 bytes");
    }

    /// Test AsRef implementations
    ///
    /// Verifies that both AsRef<[u8; 32]> and AsRef<[u8]> work correctly.
    #[test]
    fn test_h256_as_ref() {
        let test_bytes = [0x42; 32];
        let h256 = H256::from_le_bytes(test_bytes);

        // Test AsRef<[u8; 32]>
        let array_ref: &[u8; 32] = h256.as_ref();
        assert_eq!(*array_ref, test_bytes, "AsRef<[u8; 32]> should work");

        // Test AsRef<[u8]>
        let slice_ref: &[u8] = h256.as_ref();
        assert_eq!(slice_ref, &test_bytes[..], "AsRef<[u8]> should work");
        assert_eq!(slice_ref.len(), 32, "Slice should have correct length");
    }

    /// Test H256 Display implementation
    ///
    /// Verifies that H256 displays as hex with proper formatting.
    #[test]
    fn test_h256_display() {
        // Test zero hash
        let zero_h256 = H256::default();
        let zero_str = format!("{zero_h256}");
        assert_eq!(
            zero_str, "0x0000000000000000000000000000000000000000000000000000000000000000",
            "Zero hash should display correctly"
        );

        // Test all-ones hash
        let ones_h256 = H256::from_le_bytes([0xff; 32]);
        let ones_str = format!("{ones_h256}");
        assert_eq!(
            ones_str, "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "All-ones hash should display correctly"
        );

        // Test specific pattern
        let test_bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4,
            0xc3, 0xd2, 0xe1, 0xf0,
        ];
        let pattern_h256 = H256::from_le_bytes(test_bytes);
        let pattern_str = format!("{pattern_h256}");

        // Note: Display reverses bytes (big-endian display)
        assert_eq!(
            pattern_str, "0xf0e1d2c3b4a5968778695a4b3c2d1e0f1032547698badcfeefcdab8967452301",
            "Pattern should display in big-endian format"
        );

        // Verify it starts with 0x
        assert!(pattern_str.starts_with("0x"), "Should start with 0x prefix");
        assert_eq!(
            pattern_str.len(),
            66,
            "Should have correct length (2 + 64 hex chars)"
        );
    }

    /// Test H256 equality and comparison
    ///
    /// Verifies that equality works correctly for H256.
    #[test]
    fn test_h256_equality() {
        let bytes1 = [0x42; 32];
        let bytes2 = [0x42; 32];
        let bytes3 = [0x43; 32];

        let h256_1 = H256::from_le_bytes(bytes1);
        let h256_2 = H256::from_le_bytes(bytes2);
        let h256_3 = H256::from_le_bytes(bytes3);

        // Test equality
        assert_eq!(h256_1, h256_2, "Same bytes should be equal");
        assert_ne!(h256_1, h256_3, "Different bytes should not be equal");

        // Test self-equality
        assert_eq!(h256_1, h256_1, "Should be equal to itself");
    }

    /// Test H256 Clone and Copy traits
    ///
    /// Verifies that H256 can be copied and cloned correctly.
    #[test]
    fn test_h256_clone_copy() {
        let original_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x99, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22,
        ];

        let original = H256::from_le_bytes(original_bytes);

        // Test Copy trait
        let copied = original;
        assert_eq!(copied, original, "Copy should create identical instance");
        assert_eq!(
            copied.as_le_bytes(),
            original.as_le_bytes(),
            "Copied bytes should match"
        );

        // Test Clone trait
        let cloned = original.clone();
        assert_eq!(cloned, original, "Clone should create identical instance");
        assert_eq!(
            cloned.as_le_bytes(),
            original.as_le_bytes(),
            "Cloned bytes should match"
        );
    }

    /// Test H256 Hash trait
    ///
    /// Verifies that H256 can be used as a hash map key.
    #[test]
    fn test_h256_hash() {
        let bytes1 = [0x01; 32];
        let bytes2 = [0x02; 32];

        let h256_1 = H256::from_le_bytes(bytes1);
        let h256_2 = H256::from_le_bytes(bytes2);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        let mut hasher3 = DefaultHasher::new();

        h256_1.hash(&mut hasher1);
        h256_2.hash(&mut hasher2);
        h256_1.hash(&mut hasher3);

        let hash1 = hasher1.finish();
        let hash2 = hasher2.finish();
        let hash3 = hasher3.finish();

        assert_ne!(hash1, hash2, "Different H256 should have different hashes");
        assert_eq!(hash1, hash3, "Same H256 should have same hash");
    }

    /// Test H256 Debug trait
    ///
    /// Verifies that Debug formatting works correctly.
    #[test]
    fn test_h256_debug() {
        let test_bytes = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x12, 0x34,
            0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];

        let h256 = H256::from_le_bytes(test_bytes);
        let debug_str = format!("{h256:?}");

        // Debug should show the struct name and array contents
        assert!(debug_str.contains("H256"), "Debug should show struct name");
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
    /// Verifies that H256 can be binary encoded correctly.
    #[test]
    fn test_h256_bin_encoder() {
        let test_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let h256 = H256::from_le_bytes(test_bytes);
        let mut writer = MockBinWriter::default();

        h256.encode_bin(&mut writer);

        assert_eq!(
            writer.buffer, test_bytes,
            "Binary encoding should preserve exact bytes"
        );
        assert_eq!(writer.buffer.len(), 32, "Should encode exactly 32 bytes");
    }

    /// Test H256 with boundary values
    ///
    /// Verifies behavior with min/max values.
    #[test]
    fn test_h256_boundary_values() {
        // Test minimum value (all zeros)
        let min_h256 = H256::from_le_bytes([0x00; 32]);
        assert_eq!(min_h256, H256::default(), "Min value should equal default");

        // Test maximum value (all 0xff)
        let max_h256 = H256::from_le_bytes([0xff; 32]);
        assert_ne!(
            max_h256,
            H256::default(),
            "Max value should not equal default"
        );

        // Test that they're different
        assert_ne!(min_h256, max_h256, "Min and max should be different");
    }

    /// Test H256 with realistic hash values
    ///
    /// Tests with values that might actually appear as SHA-256 hashes.
    #[test]
    fn test_h256_realistic_values() {
        // Simulate a real Bitcoin genesis block hash
        let genesis_like = [
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let hash = H256::from_le_bytes(genesis_like);

        // Should not be zero
        assert_ne!(hash, H256::default(), "Real hash should not be zero");

        // Should be deterministic
        let hash2 = H256::from_le_bytes(genesis_like);
        assert_eq!(hash, hash2, "Same input should produce same hash");

        // Should format correctly
        let hex_str = format!("{hash}");
        assert!(hex_str.starts_with("0x"), "Should have hex prefix");
        assert_eq!(hex_str.len(), 66, "Should have correct hex length");
    }

    /// Test H256 memory layout and size
    ///
    /// Verifies that H256 has the expected memory characteristics.
    #[test]
    fn test_h256_memory_characteristics() {
        use core::mem;

        // Size should be exactly 32 bytes
        assert_eq!(mem::size_of::<H256>(), 32, "H256 should be 32 bytes");

        // Alignment should be reasonable
        assert!(
            mem::align_of::<H256>() <= 8,
            "H256 alignment should be reasonable"
        );

        // Should be a simple wrapper with no overhead
        assert_eq!(
            mem::size_of::<H256>(),
            mem::size_of::<[u8; 32]>(),
            "H256 should have no overhead vs raw array"
        );
    }

    /// Test H256 edge cases in display
    ///
    /// Tests edge cases in hex display formatting.
    #[test]
    fn test_h256_display_edge_cases() {
        // Test single non-zero byte at different positions
        let mut bytes = [0u8; 32];

        // First byte
        bytes[0] = 0x01;
        let h1 = H256::from_le_bytes(bytes);
        let display1 = format!("{h1}");
        assert!(
            display1.ends_with("01"),
            "Should end with 01 when first byte is 0x01"
        );

        // Last byte
        bytes = [0u8; 32];
        bytes[31] = 0xff;
        let h2 = H256::from_le_bytes(bytes);
        let display2 = format!("{h2}");
        assert!(
            display2.starts_with("0xff"),
            "Should start with ff when last byte is 0xff"
        );

        // Mixed case - verify hex characters are lowercase
        bytes = [0xab; 32];
        let h3 = H256::from_le_bytes(bytes);
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
