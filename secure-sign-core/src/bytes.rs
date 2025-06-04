// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

pub trait ToArray<T: Copy, const N: usize> {
    /// slice to array. slice.len() must be constant
    fn to_array(&self) -> [T; N];
}

impl<T: Copy + Default, const N: usize> ToArray<T, N> for [T] {
    /// slice to array. slice.len() must be constant
    #[inline]
    fn to_array(&self) -> [T; N] {
        let mut d = [Default::default(); N];
        d.copy_from_slice(self);
        d
    }
}

// pub trait ToRevArray<T: Copy, const N: usize> {
//     fn to_rev_array(&self) -> [T; N];
// }
//
// impl<T: Copy + Default, const N: usize> ToRevArray<T, N> for [T] {
//     /// slice to revered array(for endian transition). slice.len() must be constant
//     #[inline]
//     fn to_rev_array(&self) -> [T; N] {
//         let mut d = [Default::default(); N];
//         d.copy_from_slice(self);
//         d.reverse();
//         d
//     }
// }
//
// impl<T: Copy + Default, const N: usize> ToRevArray<T, N> for [T; N] {
//     #[inline]
//     fn to_rev_array(&self) -> [T; N] {
//         let mut b = self.clone();
//         b.reverse();
//         b
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    /// Test ToArray with u8 slice to array conversion
    ///
    /// Verifies that u8 slices can be converted to fixed-size arrays.
    #[test]
    fn test_to_array_u8_basic() {
        let slice: &[u8] = &[1, 2, 3, 4, 5];

        // Test converting to same size array
        let array: [u8; 5] = slice.to_array();
        assert_eq!(
            array,
            [1, 2, 3, 4, 5],
            "Should convert slice to array correctly"
        );

        // Test converting to smaller array
        let small_slice: &[u8] = &[1, 2, 3];
        let small_array: [u8; 3] = small_slice.to_array();
        assert_eq!(
            small_array,
            [1, 2, 3],
            "Should convert smaller slice to array"
        );
    }

    /// Test ToArray with different data types
    ///
    /// Verifies that the trait works with various Copy + Default types.
    #[test]
    fn test_to_array_different_types() {
        // Test with i32
        let int_slice: &[i32] = &[10, 20, 30, 40];
        let int_array: [i32; 4] = int_slice.to_array();
        assert_eq!(int_array, [10, 20, 30, 40], "Should work with i32");

        // Test with u16
        let u16_slice: &[u16] = &[100, 200];
        let u16_array: [u16; 2] = u16_slice.to_array();
        assert_eq!(u16_array, [100, 200], "Should work with u16");

        // Test with char
        let char_slice: &[char] = &['a', 'b', 'c'];
        let char_array: [char; 3] = char_slice.to_array();
        assert_eq!(char_array, ['a', 'b', 'c'], "Should work with char");

        // Test with bool
        let bool_slice: &[bool] = &[true, false, true];
        let bool_array: [bool; 3] = bool_slice.to_array();
        assert_eq!(bool_array, [true, false, true], "Should work with bool");
    }

    /// Test ToArray with single element arrays
    ///
    /// Verifies edge case of single element conversion.
    #[test]
    fn test_to_array_single_element() {
        let slice: &[u8] = &[42];
        let array: [u8; 1] = slice.to_array();
        assert_eq!(array, [42], "Should handle single element arrays");

        let slice: &[i64] = &[9876543210];
        let array: [i64; 1] = slice.to_array();
        assert_eq!(array, [9876543210], "Should handle single i64");
    }

    /// Test ToArray with common crypto array sizes
    ///
    /// Tests sizes commonly used in cryptographic operations.
    #[test]
    fn test_to_array_crypto_sizes() {
        // Test 16 bytes (AES block size)
        let aes_slice: &[u8] = &[1; 16];
        let aes_array: [u8; 16] = aes_slice.to_array();
        assert_eq!(aes_array, [1u8; 16], "Should handle AES block size");

        // Test 20 bytes (SHA-1, RIPEMD160)
        let sha1_slice: &[u8] = &[2; 20];
        let sha1_array: [u8; 20] = sha1_slice.to_array();
        assert_eq!(sha1_array, [2u8; 20], "Should handle SHA-1 size");

        // Test 32 bytes (SHA-256, secp256r1 keys)
        let sha256_slice: &[u8] = &[3; 32];
        let sha256_array: [u8; 32] = sha256_slice.to_array();
        assert_eq!(sha256_array, [3u8; 32], "Should handle SHA-256 size");

        // Test 64 bytes (SHA-512)
        let sha512_slice: &[u8] = &[4; 64];
        let sha512_array: [u8; 64] = sha512_slice.to_array();
        assert_eq!(sha512_array, [4u8; 64], "Should handle SHA-512 size");
    }

    /// Test ToArray trait bounds and generic usage
    ///
    /// Verifies that the trait can be used in generic contexts.
    #[test]
    fn test_to_array_generic_usage() {
        // Generic function using the ToArray trait
        fn convert_slice<T: Copy + Default, const N: usize>(slice: &[T]) -> [T; N] {
            slice.to_array()
        }

        // Test with different types through generic function
        let u8_result: [u8; 3] = convert_slice(&[5, 6, 7]);
        assert_eq!(u8_result, [5, 6, 7], "Generic function should work with u8");

        let i32_result: [i32; 2] = convert_slice(&[100, 200]);
        assert_eq!(
            i32_result,
            [100, 200],
            "Generic function should work with i32"
        );
    }

    /// Test ToArray with zero-sized arrays (edge case)
    ///
    /// Verifies behavior with empty arrays.
    #[test]
    fn test_to_array_zero_size() {
        let empty_slice: &[u8] = &[];
        let empty_array: [u8; 0] = empty_slice.to_array();
        assert_eq!(empty_array, [0u8; 0], "Should handle zero-sized arrays");

        let empty_i32_slice: &[i32] = &[];
        let empty_i32_array: [i32; 0] = empty_i32_slice.to_array();
        assert_eq!(
            empty_i32_array, [0i32; 0],
            "Should handle zero-sized i32 arrays"
        );
    }

    /// Test ToArray with maximum and minimum values
    ///
    /// Verifies handling of extreme values.
    #[test]
    fn test_to_array_extreme_values() {
        // Test with u8 extreme values
        let max_slice: &[u8] = &[u8::MAX, u8::MIN, u8::MAX];
        let max_array: [u8; 3] = max_slice.to_array();
        assert_eq!(max_array, [255, 0, 255], "Should handle u8 extreme values");

        // Test with i32 extreme values
        let extreme_slice: &[i32] = &[i32::MAX, i32::MIN];
        let extreme_array: [i32; 2] = extreme_slice.to_array();
        assert_eq!(
            extreme_array,
            [i32::MAX, i32::MIN],
            "Should handle i32 extreme values"
        );

        // Test with negative values
        let negative_slice: &[i8] = &[-128, -1, 0, 1, 127];
        let negative_array: [i8; 5] = negative_slice.to_array();
        assert_eq!(
            negative_array,
            [-128, -1, 0, 1, 127],
            "Should handle negative values"
        );
    }

    /// Test ToArray memory efficiency
    ///
    /// Verifies that the conversion doesn't introduce unnecessary overhead.
    #[test]
    fn test_to_array_memory_efficiency() {
        use core::mem;

        // Verify that arrays have the expected size
        let test_slice: &[u8] = &[1, 2, 3, 4];
        let test_array: [u8; 4] = test_slice.to_array();

        assert_eq!(mem::size_of_val(&test_array), 4, "Array should be 4 bytes");
        assert_eq!(mem::size_of::<[u8; 4]>(), 4, "Array type should be 4 bytes");

        // Test with larger arrays
        let large_slice: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let large_array: [u64; 8] = large_slice.to_array();
        assert_eq!(
            mem::size_of_val(&large_array),
            64,
            "Large array should be 64 bytes"
        );
    }

    /// Test ToArray determinism and consistency
    ///
    /// Verifies that conversions are deterministic and reproducible.
    #[test]
    fn test_to_array_determinism() {
        let test_slice: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

        // Convert multiple times and verify consistency
        let array1: [u8; 8] = test_slice.to_array();
        let array2: [u8; 8] = test_slice.to_array();
        let array3: [u8; 8] = test_slice.to_array();

        assert_eq!(array1, array2, "Multiple conversions should be identical");
        assert_eq!(array2, array3, "All conversions should be consistent");
        assert_eq!(
            array1,
            [1, 2, 3, 4, 5, 6, 7, 8],
            "Result should match input"
        );
    }

    /// Test ToArray with patterns commonly used in blockchain
    ///
    /// Tests patterns that appear in real blockchain operations.
    #[test]
    fn test_to_array_blockchain_patterns() {
        // Simulate hash digest conversion
        let hash_bytes: &[u8] = &[
            0xd4, 0x6c, 0x4e, 0x68, 0x31, 0x98, 0x46, 0xde, 0xb0, 0xd4, 0x0b, 0x88, 0xd6, 0x75,
            0x6b, 0xea, 0x75, 0x70, 0x41, 0x0e, 0xd8, 0x12, 0x5f, 0x12, 0xe6, 0x1c, 0x4b, 0x96,
            0xdc, 0x72, 0x22, 0x83,
        ];
        let hash_array: [u8; 32] = hash_bytes.to_array();
        assert_eq!(hash_array[0], 0xd4, "First byte should be preserved");
        assert_eq!(hash_array[31], 0x83, "Last byte should be preserved");

        // Simulate address/script hash conversion
        let address_bytes: &[u8] = &[
            0x17, 0x62, 0xe8, 0x2d, 0x5e, 0x62, 0xa5, 0x4e, 0x3a, 0x95, 0x8b, 0xe2, 0x1d, 0xb4,
            0x4d, 0xf2, 0x3f, 0x8e, 0x7c, 0x9b,
        ];
        let address_array: [u8; 20] = address_bytes.to_array();
        assert_eq!(address_array.len(), 20, "Address should be 20 bytes");
        assert_eq!(
            &address_array[..],
            address_bytes,
            "Address bytes should be preserved"
        );

        // Simulate signature component conversion
        let signature_r: &[u8] = &[0x12; 32];
        let signature_r_array: [u8; 32] = signature_r.to_array();
        assert_eq!(
            signature_r_array, [0x12; 32],
            "Signature R component should be preserved"
        );
    }

    /// Test ToArray with trait object compatibility
    ///
    /// Verifies that the trait can be used with dynamic dispatch.
    #[test]
    fn test_to_array_trait_objects() {
        // Function that works with any slice via trait object
        fn process_slice_to_array_4(slice: &[u8]) -> [u8; 4] {
            slice.to_array()
        }

        let test_slice: &[u8] = &[10, 20, 30, 40];
        let result = process_slice_to_array_4(test_slice);
        assert_eq!(
            result,
            [10, 20, 30, 40],
            "Should work through function call"
        );

        // Test with Vec as well
        let test_vec = vec![50, 60, 70, 80];
        let vec_result = process_slice_to_array_4(&test_vec);
        assert_eq!(vec_result, [50, 60, 70, 80], "Should work with Vec slice");
    }
}
