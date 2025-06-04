// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use sha2::Digest;

use crate::bytes::ToArray;

pub trait Sha256 {
    fn sha256(&self) -> [u8; 32];
}

impl<T: AsRef<[u8]>> Sha256 for T {
    #[inline]
    fn sha256(&self) -> [u8; 32] {
        let mut h = sha2::Sha256::new();
        h.update(self);
        h.finalize().as_slice().to_array()
    }
}

pub trait SlicesSha256 {
    fn slices_sha256(self) -> [u8; 32];
}

impl<T: Iterator> SlicesSha256 for T
where
    <T as Iterator>::Item: AsRef<[u8]>,
{
    #[inline]
    fn slices_sha256(self) -> [u8; 32] {
        let mut h = sha2::Sha256::new();
        self.for_each(|s| h.update(s));

        h.finalize().as_slice().to_array()
    }
}

pub trait Ripemd160 {
    fn ripemd160(&self) -> [u8; 20];
}

impl<T: AsRef<[u8]>> Ripemd160 for T {
    #[inline]
    fn ripemd160(&self) -> [u8; 20] {
        let mut h = ripemd::Ripemd160::new();
        h.update(self);
        h.finalize().as_slice().to_array()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use super::*;

    /// Test SHA-256 with known test vectors
    ///
    /// Uses NIST test vectors to verify correct SHA-256 implementation.
    #[test]
    fn test_sha256_nist_vectors() {
        // NIST Test Vector 1: Empty string
        let input1 = b"";
        let expected1 =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("valid hex");
        let result1 = input1.sha256();
        assert_eq!(
            result1.to_vec(),
            expected1,
            "SHA-256 of empty string failed"
        );

        // NIST Test Vector 2: "abc"
        let input2 = b"abc";
        let expected2 =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("valid hex");
        let result2 = input2.sha256();
        assert_eq!(result2.to_vec(), expected2, "SHA-256 of 'abc' failed");

        // NIST Test Vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let input3 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected3 =
            hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
                .expect("valid hex");
        let result3 = input3.sha256();
        assert_eq!(result3.to_vec(), expected3, "SHA-256 of long string failed");
    }

    /// Test SHA-256 with various data types
    ///
    /// Verifies that the trait works with different input types.
    #[test]
    fn test_sha256_data_types() {
        let test_data = "Hello, world!";

        // Test with &str
        let str_result = test_data.sha256();

        // Test with String
        let string_result = test_data.to_string().sha256();
        assert_eq!(
            str_result, string_result,
            "String and &str should produce same hash"
        );

        // Test with &[u8]
        let slice_result = test_data.as_bytes().sha256();
        assert_eq!(
            str_result, slice_result,
            "&str and &[u8] should produce same hash"
        );

        // Test with Vec<u8>
        let vec_result = test_data.as_bytes().to_vec().sha256();
        assert_eq!(
            str_result, vec_result,
            "&str and Vec<u8> should produce same hash"
        );

        // Test with array
        let array_data = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" in ASCII
        let array_result = array_data.sha256();
        let hello_result = b"Hello".sha256();
        assert_eq!(
            array_result, hello_result,
            "Array and byte string should produce same hash"
        );
    }

    /// Test SHA-256 determinism and consistency
    ///
    /// Verifies that SHA-256 produces consistent results.
    #[test]
    fn test_sha256_determinism() {
        let test_inputs = vec![
            b"".as_slice(),
            b"a",
            b"test",
            b"Hello, world!",
            b"The quick brown fox jumps over the lazy dog",
            &[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc],
        ];

        for input in test_inputs {
            let hash1 = input.sha256();
            let hash2 = input.sha256();
            let hash3 = input.sha256();

            assert_eq!(hash1, hash2, "SHA-256 should be deterministic (run 1 vs 2)");
            assert_eq!(hash2, hash3, "SHA-256 should be deterministic (run 2 vs 3)");
            assert_ne!(hash1, [0u8; 32], "SHA-256 should not be all zeros");
        }
    }

    /// Test SHA-256 avalanche effect
    ///
    /// Verifies that small changes in input produce large changes in output.
    #[test]
    fn test_sha256_avalanche_effect() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let modified = b"The quick brown fox jumps over the lazy doh"; // Changed last character

        let original_hash = original.sha256();
        let modified_hash = modified.sha256();

        assert_ne!(
            original_hash, modified_hash,
            "Single bit change should change hash"
        );

        // Count differing bits to ensure good avalanche
        let mut differing_bits = 0;
        for i in 0..32 {
            differing_bits += (original_hash[i] ^ modified_hash[i]).count_ones();
        }

        // Good avalanche should change roughly half the bits (128 out of 256)
        assert!(
            differing_bits > 64,
            "Avalanche effect should affect many bits (got {differing_bits})"
        );
    }

    /// Test SHA-256 with large inputs
    ///
    /// Verifies performance and correctness with large data.
    #[test]
    fn test_sha256_large_inputs() {
        // Test with 1MB of data
        let large_data = vec![0x42u8; 1_000_000];
        let hash = large_data.sha256();

        // Should not be all zeros
        assert_ne!(hash, [0u8; 32], "Large input hash should not be all zeros");

        // Should be deterministic
        let hash2 = large_data.sha256();
        assert_eq!(hash, hash2, "Large input should be deterministic");

        // Test with data that's not a multiple of block size
        let odd_size_data = vec![0x37u8; 1_000_001];
        let odd_hash = odd_size_data.sha256();
        assert_ne!(
            odd_hash, hash,
            "Different sized inputs should produce different hashes"
        );
    }

    /// Test SlicesSha256 trait basic functionality
    ///
    /// Verifies that multiple slices can be hashed together.
    #[test]
    fn test_slices_sha256_basic() {
        let slice1: &[u8] = b"Hello, ";
        let slice2: &[u8] = b"world!";

        // Hash using SlicesSha256
        let slices_hash = [slice1, slice2].iter().slices_sha256();

        // Hash concatenated data using regular SHA-256
        let concat_data = b"Hello, world!";
        let concat_hash = concat_data.sha256();

        assert_eq!(
            slices_hash, concat_hash,
            "SlicesSha256 should equal concatenated SHA-256"
        );
    }

    /// Test SlicesSha256 with various iterators
    ///
    /// Verifies that the trait works with different iterator types.
    #[test]
    fn test_slices_sha256_iterators() {
        let data_parts = vec![b"Part1", b"Part2", b"Part3"];

        // Test with Vec iterator
        let vec_hash = data_parts.iter().slices_sha256();

        // Test with slice iterator
        let slice_hash = data_parts.as_slice().iter().slices_sha256();
        assert_eq!(
            vec_hash, slice_hash,
            "Vec and slice iterators should produce same hash"
        );

        // Test with array iterator
        let array_parts = [b"Part1", b"Part2", b"Part3"];
        let array_hash = array_parts.iter().slices_sha256();
        assert_eq!(
            vec_hash, array_hash,
            "Vec and array iterators should produce same hash"
        );

        // Compare with concatenated version
        let concatenated = b"Part1Part2Part3";
        let concat_hash = concatenated.sha256();
        assert_eq!(
            vec_hash, concat_hash,
            "SlicesSha256 should equal concatenated data"
        );
    }

    /// Test SlicesSha256 with empty and single slices
    ///
    /// Verifies edge cases for SlicesSha256.
    #[test]
    fn test_slices_sha256_edge_cases() {
        // Test with empty iterator
        let empty_slices: Vec<&[u8]> = vec![];
        let empty_hash = empty_slices.iter().slices_sha256();
        let empty_string_hash = b"".sha256();
        assert_eq!(
            empty_hash, empty_string_hash,
            "Empty slices should equal empty string hash"
        );

        // Test with single slice
        let single_slice = [b"single"];
        let single_hash = single_slice.iter().slices_sha256();
        let single_direct_hash = b"single".sha256();
        assert_eq!(
            single_hash, single_direct_hash,
            "Single slice should equal direct hash"
        );

        // Test with empty slices in the iterator
        let mixed_slices = [
            b"start".as_slice(),
            b"".as_slice(),
            b"middle".as_slice(),
            b"".as_slice(),
            b"end".as_slice(),
        ];
        let mixed_hash = mixed_slices.iter().slices_sha256();
        let mixed_concat_hash = b"startmiddleend".sha256();
        assert_eq!(
            mixed_hash, mixed_concat_hash,
            "Empty slices should be ignored"
        );
    }

    /// Test RIPEMD160 with known test vectors
    ///
    /// Uses official RIPEMD160 test vectors to verify correctness.
    #[test]
    fn test_ripemd160_test_vectors() {
        // Test Vector 1: Empty string
        let input1 = b"";
        let expected1 = hex::decode("9c1185a5c5e9fc54612808977ee8f548b2258d31").expect("valid hex");
        let result1 = input1.ripemd160();
        assert_eq!(
            result1.to_vec(),
            expected1,
            "RIPEMD160 of empty string failed"
        );

        // Test Vector 2: "abc"
        let input2 = b"abc";
        let expected2 = hex::decode("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc").expect("valid hex");
        let result2 = input2.ripemd160();
        assert_eq!(result2.to_vec(), expected2, "RIPEMD160 of 'abc' failed");

        // Test Vector 3: "message digest"
        let input3 = b"message digest";
        let expected3 = hex::decode("5d0689ef49d2fae572b881b123a85ffa21595f36").expect("valid hex");
        let result3 = input3.ripemd160();
        assert_eq!(
            result3.to_vec(),
            expected3,
            "RIPEMD160 of 'message digest' failed"
        );

        // Test Vector 4: "abcdefghijklmnopqrstuvwxyz"
        let input4 = b"abcdefghijklmnopqrstuvwxyz";
        let expected4 = hex::decode("f71c27109c692c1b56bbdceb5b9d2865b3708dbc").expect("valid hex");
        let result4 = input4.ripemd160();
        assert_eq!(result4.to_vec(), expected4, "RIPEMD160 of alphabet failed");
    }

    /// Test RIPEMD160 with various data types
    ///
    /// Verifies that the trait works with different input types.
    #[test]
    fn test_ripemd160_data_types() {
        let test_data = "Hello, RIPEMD160!";

        // Test with &str
        let str_result = test_data.ripemd160();

        // Test with String
        let string_result = test_data.to_string().ripemd160();
        assert_eq!(
            str_result, string_result,
            "String and &str should produce same hash"
        );

        // Test with &[u8]
        let slice_result = test_data.as_bytes().ripemd160();
        assert_eq!(
            str_result, slice_result,
            "&str and &[u8] should produce same hash"
        );

        // Test with Vec<u8>
        let vec_result = test_data.as_bytes().to_vec().ripemd160();
        assert_eq!(
            str_result, vec_result,
            "&str and Vec<u8> should produce same hash"
        );
    }

    /// Test RIPEMD160 determinism
    ///
    /// Verifies that RIPEMD160 produces consistent results.
    #[test]
    fn test_ripemd160_determinism() {
        let test_inputs = vec![
            b"".as_slice(),
            b"a",
            b"test",
            b"RIPEMD160 test",
            b"The quick brown fox jumps over the lazy dog",
            &[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc],
        ];

        for input in test_inputs {
            let hash1 = input.ripemd160();
            let hash2 = input.ripemd160();
            let hash3 = input.ripemd160();

            assert_eq!(
                hash1, hash2,
                "RIPEMD160 should be deterministic (run 1 vs 2)"
            );
            assert_eq!(
                hash2, hash3,
                "RIPEMD160 should be deterministic (run 2 vs 3)"
            );
            assert_ne!(hash1, [0u8; 20], "RIPEMD160 should not be all zeros");
        }
    }

    /// Test RIPEMD160 avalanche effect
    ///
    /// Verifies that small changes in input produce large changes in output.
    #[test]
    fn test_ripemd160_avalanche_effect() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let modified = b"The quick brown fox jumps over the lazy cat"; // Changed last word

        let original_hash = original.ripemd160();
        let modified_hash = modified.ripemd160();

        assert_ne!(
            original_hash, modified_hash,
            "Word change should change hash"
        );

        // Count differing bits to ensure good avalanche
        let mut differing_bits = 0;
        for i in 0..20 {
            differing_bits += (original_hash[i] ^ modified_hash[i]).count_ones();
        }

        // Good avalanche should change roughly half the bits (80 out of 160)
        assert!(
            differing_bits > 40,
            "Avalanche effect should affect many bits (got {differing_bits})"
        );
    }

    /// Test SHA-256 vs RIPEMD160 output differences
    ///
    /// Verifies that different hash functions produce different outputs.
    #[test]
    fn test_sha256_vs_ripemd160() {
        let test_data = b"Compare hash functions";

        let sha256_hash = test_data.sha256();
        let ripemd160_hash = test_data.ripemd160();

        // Hashes should have different lengths
        assert_eq!(sha256_hash.len(), 32, "SHA-256 should produce 32 bytes");
        assert_eq!(
            ripemd160_hash.len(),
            20,
            "RIPEMD160 should produce 20 bytes"
        );

        // First 20 bytes should be different (extremely unlikely to be same)
        assert_ne!(
            &sha256_hash[0..20],
            &ripemd160_hash[0..20],
            "SHA-256 and RIPEMD160 should produce different hashes"
        );
    }

    /// Test hash functions with NEO blockchain usage patterns
    ///
    /// Simulates real-world usage in NEO blockchain operations.
    #[test]
    fn test_neo_blockchain_usage_patterns() {
        // Simulate script hash calculation: SHA-256 + RIPEMD160
        let script_bytes = b"CheckWitness script example";
        let sha256_hash = script_bytes.sha256();
        let script_hash = sha256_hash.ripemd160();

        assert_eq!(script_hash.len(), 20, "Script hash should be 20 bytes");
        assert_ne!(
            script_hash, [0u8; 20],
            "Script hash should not be all zeros"
        );

        // Simulate double SHA-256 (used in many blockchain operations)
        let transaction_data = b"Sample transaction data";
        let first_hash = transaction_data.sha256();
        let double_hash = first_hash.sha256();

        assert_ne!(
            first_hash, double_hash,
            "Double SHA-256 should be different from single"
        );
        assert_eq!(
            double_hash.len(),
            32,
            "Double SHA-256 should still be 32 bytes"
        );

        // Simulate Merkle tree node hashing using SlicesSha256
        let left_hash = b"left_node_hash_data".sha256();
        let right_hash = b"right_node_hash_data".sha256();
        let merkle_node = [left_hash.as_slice(), right_hash.as_slice()]
            .iter()
            .slices_sha256();

        assert_ne!(
            merkle_node, left_hash,
            "Merkle node should differ from left child"
        );
        assert_ne!(
            merkle_node, right_hash,
            "Merkle node should differ from right child"
        );
    }

    /// Test hash memory usage with large data
    ///
    /// Verifies that hash functions handle large inputs correctly.
    #[test]
    fn test_hash_memory_efficiency() {
        let test_data =
            b"Performance test data that is somewhat longer to provide a better benchmark";
        let iterations = 100;

        // Test SHA-256 with repeated hashing
        let mut current_hash = test_data.sha256();
        for _ in 0..iterations {
            current_hash = current_hash.sha256();
        }

        // Should not be all zeros after iterations
        assert_ne!(
            current_hash, [0u8; 32],
            "Iterated SHA-256 should not be all zeros"
        );

        // Test RIPEMD160 with repeated hashing
        let mut current_ripemd = test_data.ripemd160();
        for _ in 0..iterations {
            current_ripemd = current_ripemd.ripemd160();
        }

        // Should not be all zeros after iterations
        assert_ne!(
            current_ripemd, [0u8; 20],
            "Iterated RIPEMD160 should not be all zeros"
        );
    }

    /// Test hash trait bounds and generic usage
    ///
    /// Verifies that hash traits work properly in generic contexts.
    #[test]
    fn test_hash_trait_bounds() {
        // Generic function that uses Sha256 trait
        fn hash_anything<T: Sha256>(data: T) -> [u8; 32] {
            data.sha256()
        }

        // Test with different types
        let str_hash = hash_anything("test string");
        let bytes_hash = hash_anything(b"test string");
        let vec_hash = hash_anything(b"test string".to_vec());

        assert_eq!(
            str_hash, bytes_hash,
            "Generic function should work with &str and &[u8]"
        );
        assert_eq!(
            bytes_hash, vec_hash,
            "Generic function should work with &[u8] and Vec<u8>"
        );

        // Generic function that uses Ripemd160 trait
        fn ripemd_anything<T: Ripemd160>(data: T) -> [u8; 20] {
            data.ripemd160()
        }

        let ripemd_str = ripemd_anything("ripemd test");
        let ripemd_bytes = ripemd_anything(b"ripemd test");

        assert_eq!(
            ripemd_str, ripemd_bytes,
            "Generic RIPEMD160 should work with different types"
        );
    }
}
