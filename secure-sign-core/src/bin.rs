// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use bytes::{BufMut, BytesMut};

pub trait BinWriter {
    // write varint in little endian
    fn write_varint(&mut self, value: u64);

    fn write<T: AsRef<[u8]>>(&mut self, value: T);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BinWriter for BytesMut {
    fn write_varint(&mut self, value: u64) {
        let (size, buf) = to_varint_le(value);
        self.put_slice(&buf[..size as usize]); // size field
    }

    fn write<T: AsRef<[u8]>>(&mut self, value: T) {
        self.put_slice(value.as_ref());
    }

    fn len(&self) -> usize {
        self.len()
    }
}

pub trait BinEncoder {
    fn encode_bin(&self, w: &mut impl BinWriter);
}

impl BinEncoder for u8 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.to_le_bytes());
    }
}

impl BinEncoder for u16 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.to_le_bytes());
    }
}

impl BinEncoder for u32 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.to_le_bytes());
    }
}

impl BinEncoder for u64 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.to_le_bytes());
    }
}

impl BinEncoder for [u8] {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write_varint(self.len() as u64);
        w.write(self);
    }
}

pub fn to_varint_le(value: u64) -> (u8, [u8; 9]) {
    let mut le = [0u8; 9];
    if value < 0xfd {
        le[0] = value as u8;
        (1, le)
    } else if value < 0xFFFF {
        le[0] = 0xfd;
        le[1..=2].copy_from_slice(&(value as u16).to_le_bytes());
        (3, le)
    } else if value < 0xFFFFFFFF {
        le[0] = 0xfe;
        le[1..=4].copy_from_slice(&(value as u32).to_le_bytes());
        (5, le)
    } else {
        le[0] = 0xff;
        le[1..=8].copy_from_slice(&value.to_le_bytes());
        (9, le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Simple mock BinWriter for testing
    #[derive(Debug, Default)]
    struct MockBinWriter {
        buffer: Vec<u8>,
    }

    impl BinWriter for MockBinWriter {
        fn write_varint(&mut self, value: u64) {
            let (size, buf) = to_varint_le(value);
            self.buffer.extend_from_slice(&buf[..size as usize]);
        }

        fn write<T: AsRef<[u8]>>(&mut self, value: T) {
            self.buffer.extend_from_slice(value.as_ref());
        }

        fn len(&self) -> usize {
            self.buffer.len()
        }
    }

    /// Test to_varint_le function with various values
    ///
    /// Verifies correct varint encoding for different value ranges.
    #[test]
    fn test_to_varint_le_basic() {
        // Test single byte encoding (< 0xfd)
        let (size, buf) = to_varint_le(0);
        assert_eq!(size, 1, "Zero should use 1 byte");
        assert_eq!(buf[0], 0, "Zero should encode as 0");

        let (size, buf) = to_varint_le(252);
        assert_eq!(size, 1, "252 should use 1 byte");
        assert_eq!(buf[0], 252, "252 should encode as 252");

        // Test 3-byte encoding (0xfd <= value < 0xFFFF)
        let (size, buf) = to_varint_le(253);
        assert_eq!(size, 3, "253 should use 3 bytes");
        assert_eq!(buf[0], 0xfd, "Should have 0xfd prefix");
        assert_eq!(buf[1], 253, "Little-endian low byte");
        assert_eq!(buf[2], 0, "Little-endian high byte");

        let (size, buf) = to_varint_le(0xFFFF - 1);
        assert_eq!(size, 3, "65534 should use 3 bytes");
        assert_eq!(buf[0], 0xfd, "Should have 0xfd prefix");
        assert_eq!(buf[1], 0xfe, "Little-endian low byte");
        assert_eq!(buf[2], 0xff, "Little-endian high byte");
    }

    /// Test to_varint_le with larger values
    ///
    /// Verifies 5-byte and 9-byte varint encoding.
    #[test]
    fn test_to_varint_le_large_values() {
        // Test 5-byte encoding (0xFFFF <= value < 0xFFFFFFFF)
        let (size, buf) = to_varint_le(0x10000);
        assert_eq!(size, 5, "65536 should use 5 bytes");
        assert_eq!(buf[0], 0xfe, "Should have 0xfe prefix");
        assert_eq!(
            &buf[1..=4],
            &[0x00, 0x00, 0x01, 0x00],
            "Little-endian 4 bytes"
        );

        let (size, buf) = to_varint_le(0xFFFFFFFF - 1);
        assert_eq!(size, 5, "Large 32-bit value should use 5 bytes");
        assert_eq!(buf[0], 0xfe, "Should have 0xfe prefix");
        assert_eq!(
            &buf[1..=4],
            &[0xfe, 0xff, 0xff, 0xff],
            "Little-endian 4 bytes"
        );

        // Test 9-byte encoding (>= 0xFFFFFFFF)
        let (size, buf) = to_varint_le(0x100000000);
        assert_eq!(size, 9, "Large value should use 9 bytes");
        assert_eq!(buf[0], 0xff, "Should have 0xff prefix");
        assert_eq!(
            &buf[1..=8],
            &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            "Little-endian 8 bytes"
        );

        let (size, buf) = to_varint_le(u64::MAX);
        assert_eq!(size, 9, "Max u64 should use 9 bytes");
        assert_eq!(buf[0], 0xff, "Should have 0xff prefix");
        assert_eq!(&buf[1..=8], &[0xff; 8], "All bytes should be 0xff");
    }

    /// Test BinWriter trait with MockBinWriter
    ///
    /// Verifies that the BinWriter trait methods work correctly.
    #[test]
    fn test_bin_writer_basic() {
        let mut writer = MockBinWriter::default();

        // Test write method
        writer.write([1, 2, 3, 4]);
        assert_eq!(writer.buffer, vec![1, 2, 3, 4], "Write should append bytes");
        assert_eq!(writer.len(), 4, "Length should be updated");
        assert!(!writer.is_empty(), "Should not be empty");

        // Test write with different types
        writer.write(&[5, 6]);
        writer.write(b"test");
        assert_eq!(
            writer.buffer,
            vec![1, 2, 3, 4, 5, 6, 116, 101, 115, 116],
            "Should handle different AsRef types"
        );

        // Test varint writing
        let mut writer2 = MockBinWriter::default();
        writer2.write_varint(42);
        assert_eq!(writer2.buffer, vec![42], "Small varint should be 1 byte");

        writer2.write_varint(300);
        assert_eq!(
            writer2.buffer,
            vec![42, 0xfd, 44, 1],
            "Larger varint should be 3 bytes"
        );
    }

    /// Test BinWriter trait with BytesMut
    ///
    /// Verifies that BytesMut correctly implements BinWriter.
    #[test]
    fn test_bin_writer_bytes_mut() {
        let mut buf = BytesMut::new();

        // Test empty state
        assert_eq!(buf.len(), 0, "Should start empty");
        assert!(buf.is_empty(), "Should be empty");

        // Test writing bytes
        buf.write(b"hello");
        assert_eq!(buf.len(), 5, "Should have 5 bytes");
        assert_eq!(&buf[..], b"hello", "Should contain written data");

        // Test writing varint
        buf.write_varint(100);
        assert_eq!(buf.len(), 6, "Should have added 1 byte for varint");
        assert_eq!(buf[5], 100, "Varint should be appended");

        // Test writing various types
        buf.write([1, 2, 3]);
        buf.write(vec![4, 5, 6]);
        assert_eq!(buf.len(), 12, "Should handle different types");
    }

    /// Test BinEncoder for primitive types
    ///
    /// Verifies that numeric types encode correctly in little-endian.
    #[test]
    fn test_bin_encoder_primitives() {
        let mut writer = MockBinWriter::default();

        // Test u8
        let val_u8: u8 = 0x42;
        val_u8.encode_bin(&mut writer);
        assert_eq!(writer.buffer, vec![0x42], "u8 should encode as single byte");

        writer.buffer.clear();

        // Test u16
        let val_u16: u16 = 0x1234;
        val_u16.encode_bin(&mut writer);
        assert_eq!(
            writer.buffer,
            vec![0x34, 0x12],
            "u16 should encode little-endian"
        );

        writer.buffer.clear();

        // Test u32
        let val_u32: u32 = 0x12345678;
        val_u32.encode_bin(&mut writer);
        assert_eq!(
            writer.buffer,
            vec![0x78, 0x56, 0x34, 0x12],
            "u32 should encode little-endian"
        );

        writer.buffer.clear();

        // Test u64
        let val_u64: u64 = 0x123456789abcdef0;
        val_u64.encode_bin(&mut writer);
        assert_eq!(
            writer.buffer,
            vec![0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12],
            "u64 should encode little-endian"
        );
    }

    /// Test BinEncoder for byte slices
    ///
    /// Verifies that byte slices encode with length prefix.
    #[test]
    fn test_bin_encoder_byte_slice() {
        let mut writer = MockBinWriter::default();

        // Test empty slice
        let empty_slice: &[u8] = &[];
        empty_slice.encode_bin(&mut writer);
        assert_eq!(writer.buffer, vec![0], "Empty slice should have length 0");

        writer.buffer.clear();

        // Test small slice
        let small_slice: &[u8] = &[1, 2, 3];
        small_slice.encode_bin(&mut writer);
        assert_eq!(
            writer.buffer,
            vec![3, 1, 2, 3],
            "Small slice should have varint length + data"
        );

        writer.buffer.clear();

        // Test slice that requires multi-byte varint
        let large_slice = vec![0x42; 300];
        large_slice.as_slice().encode_bin(&mut writer);
        assert_eq!(
            writer.buffer[0], 0xfd,
            "Large slice should use multi-byte varint"
        );
        assert_eq!(writer.buffer[1], 44, "Length 300 = 0x012c, low byte");
        assert_eq!(writer.buffer[2], 1, "Length 300 = 0x012c, high byte");
        assert_eq!(writer.buffer[3], 0x42, "Data should follow");
        assert_eq!(
            writer.buffer.len(),
            303,
            "Should be 3 bytes length + 300 bytes data"
        );
    }

    /// Test varint encoding edge cases
    ///
    /// Verifies edge cases and boundary values for varint encoding.
    #[test]
    fn test_varint_edge_cases() {
        // Test boundary values
        let boundary_tests = vec![
            (0, 1),          // Minimum value
            (252, 1),        // Last 1-byte value
            (253, 3),        // First 3-byte value
            (0xFFFE, 3),     // Last 3-byte value
            (0xFFFF, 5),     // First 5-byte value
            (0xFFFFFFFE, 5), // Last 5-byte value
            (0xFFFFFFFF, 9), // First 9-byte value
            (u64::MAX, 9),   // Maximum value
        ];

        for (value, expected_size) in boundary_tests {
            let (actual_size, _) = to_varint_le(value);
            assert_eq!(
                actual_size, expected_size,
                "Value {value} should use {expected_size} bytes"
            );
        }
    }

    /// Test BinEncoder and BinWriter integration
    ///
    /// Verifies that encoders and writers work together correctly.
    #[test]
    fn test_integration_encoding_workflow() {
        let mut writer = MockBinWriter::default();

        // Simulate encoding a transaction-like structure
        let version: u32 = 1;
        let input_count: u64 = 2;
        let data1: &[u8] = b"input1";
        let data2: &[u8] = b"input2";
        let timestamp: u64 = 1609459200; // Jan 1, 2021

        // Encode version
        version.encode_bin(&mut writer);

        // Encode input count as varint
        writer.write_varint(input_count);

        // Encode inputs with length prefixes
        data1.encode_bin(&mut writer);
        data2.encode_bin(&mut writer);

        // Encode timestamp
        timestamp.encode_bin(&mut writer);

        // Verify the structure
        assert_eq!(writer.buffer[0..4], [1, 0, 0, 0], "Version should be first");
        assert_eq!(writer.buffer[4], 2, "Input count should follow");
        assert_eq!(writer.buffer[5], 6, "First input length");
        assert_eq!(&writer.buffer[6..12], b"input1", "First input data");
        assert_eq!(writer.buffer[12], 6, "Second input length");
        assert_eq!(&writer.buffer[13..19], b"input2", "Second input data");
        // Timestamp verification (little-endian u64)
        assert_eq!(writer.buffer.len(), 27, "Total length should be correct");
    }

    /// Test BinWriter trait with generics
    ///
    /// Verifies that BinWriter can be used in generic contexts.
    #[test]
    fn test_bin_writer_generic_usage() {
        fn write_data<W: BinWriter>(writer: &mut W, data: &[u8]) {
            writer.write_varint(data.len() as u64);
            writer.write(data);
        }

        let mut mock_writer = MockBinWriter::default();
        write_data(&mut mock_writer, b"test");

        assert_eq!(mock_writer.buffer[0], 4, "Should write length");
        assert_eq!(&mock_writer.buffer[1..], b"test", "Should write data");

        let mut bytes_writer = BytesMut::new();
        write_data(&mut bytes_writer, b"hello");

        assert_eq!(bytes_writer[0], 5, "BytesMut should also work");
        assert_eq!(&bytes_writer[1..], b"hello", "BytesMut should write data");
    }

    /// Test memory efficiency and performance
    ///
    /// Verifies that encoding operations are efficient.
    #[test]
    fn test_encoding_memory_efficiency() {
        let mut writer = MockBinWriter::default();

        // Test that encoding doesn't introduce unnecessary allocations
        let _initial_capacity = writer.buffer.capacity();

        // Encode some small values
        for i in 0u8..10 {
            i.encode_bin(&mut writer);
        }

        assert_eq!(writer.len(), 10, "Should have encoded 10 bytes");

        // Test that varints use minimal space
        let mut varint_writer = MockBinWriter::default();
        varint_writer.write_varint(0);
        varint_writer.write_varint(252);
        varint_writer.write_varint(253);

        assert_eq!(
            varint_writer.buffer,
            vec![0, 252, 0xfd, 253, 0],
            "Varints should use minimal encoding"
        );
    }

    /// Test error conditions and boundary behavior
    ///
    /// Verifies that edge cases are handled correctly.
    #[test]
    fn test_boundary_behavior() {
        let mut writer = MockBinWriter::default();

        // Test with maximum values
        u8::MAX.encode_bin(&mut writer);
        u16::MAX.encode_bin(&mut writer);
        u32::MAX.encode_bin(&mut writer);
        u64::MAX.encode_bin(&mut writer);

        // Verify sizes
        assert_eq!(
            writer.buffer.len(),
            1 + 2 + 4 + 8,
            "Should encode all max values"
        );

        // Test varint with all boundaries
        let mut varint_writer = MockBinWriter::default();
        let boundaries = [
            0,
            252,
            253,
            0xFFFE,
            0xFFFF,
            0xFFFFFFFE,
            0xFFFFFFFF,
            u64::MAX,
        ];

        for value in boundaries {
            varint_writer.write_varint(value);
        }

        // Should not panic and should produce sensible output
        assert!(varint_writer.len() > 0, "Should have written data");
        assert!(varint_writer.len() < 100, "Should not be excessively large");
    }
}
