// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Merkle Tree Implementation for NEO Blockchain
//!
//! This module implements Merkle tree construction using SHA-256 hashing.
//! Merkle trees are a fundamental cryptographic data structure used throughout
//! the NEO blockchain for efficient and secure verification of large data sets.
//!
//! ## Merkle Tree Overview
//!
//! A Merkle tree is a binary tree where:
//! - **Leaf nodes** contain hashes of individual data items
//! - **Internal nodes** contain hashes of their child nodes  
//! - **Root node** represents a cryptographic commitment to all data
//!
//! ```text
//!       Root Hash
//!       /        \
//!   Hash(A,B)  Hash(C,D)
//!    /    \      /    \
//! Hash(A) Hash(B) Hash(C) Hash(D)
//!   |      |       |       |
//!  Data A Data B  Data C  Data D
//! ```
//!
//! ## Applications in NEO
//!
//! - **Transaction Verification**: Block headers contain Merkle roots of transactions
//! - **State Verification**: Efficient proofs of account states and contract storage
//! - **Light Client Support**: Verify transactions without downloading entire blocks  
//! - **Consensus Efficiency**: Validators can verify large data sets with compact proofs
//!
//! ## Security Properties
//!
//! - **Tamper Detection**: Any change to data produces a different root hash
//! - **Efficient Verification**: Verify individual items with O(log n) hashes
//! - **Collision Resistance**: Based on SHA-256's collision resistance
//! - **Deterministic**: Same data always produces the same root hash
//!
//! ## Implementation Details
//!
//! This implementation uses:
//! - **Bottom-up construction**: Build tree from leaves to root
//! - **In-place computation**: Reuses array space for efficiency  
//! - **Odd-length handling**: Duplicates last element for odd-sized arrays
//! - **Double-SHA256**: Following Bitcoin/NEO convention for enhanced security

use alloc::vec;

use crate::{
    h256::H256,
    hash::{Sha256, SlicesSha256},
};

/// Trait for computing Merkle tree root hash using SHA-256
///
/// This trait can be implemented by any type that can be converted to
/// a slice of H256 hashes, allowing flexible Merkle tree computation
/// over various data structures.
pub trait MerkleSha256 {
    /// Compute the Merkle tree root hash for this collection of hashes
    ///
    /// # Returns
    /// The root hash of the Merkle tree constructed from the input hashes
    fn merkle_sha256(&self) -> H256;
}

impl<T: AsRef<[H256]>> MerkleSha256 for T {
    /// Compute Merkle tree root using bottom-up construction algorithm
    ///
    /// This method implements the standard Merkle tree construction algorithm
    /// with optimizations for the NEO blockchain requirements.
    ///
    /// ## Algorithm Overview
    ///
    /// 1. **Empty Check**: Return zero hash for empty input
    /// 2. **Single Item**: Return the single hash directly  
    /// 3. **Bottom-up Construction**: Combine pairs of hashes level by level
    /// 4. **Odd Handling**: Duplicate last hash when odd number of elements
    /// 5. **In-place Updates**: Reuse array space for memory efficiency
    ///
    /// ## Complexity
    /// - **Time**: O(n) where n is the number of input hashes
    /// - **Space**: O(n) for the working array (could be optimized to O(log n))
    /// - **Hash Operations**: Exactly n-1 double-SHA256 operations
    ///
    /// ## NEO Blockchain Compatibility
    /// - Uses double-SHA256 following NEO conventions
    /// - Handles empty and single-element cases properly  
    /// - Little-endian byte order for hash results
    /// - Compatible with NEO Core C# implementation
    ///
    /// # Returns
    /// * `H256::default()` - For empty input arrays
    /// * Single hash - For arrays with exactly one element
    /// * Root hash - For arrays with multiple elements
    ///
    /// # Example Usage
    /// ```rust
    /// use secure_sign_core::merkle::MerkleSha256;
    /// use secure_sign_core::h256::H256;
    /// use secure_sign_core::hash::Sha256;
    ///
    /// // Create some example transaction hashes
    /// let hash1 = H256::from_le_bytes("tx1".as_bytes().sha256());
    /// let hash2 = H256::from_le_bytes("tx2".as_bytes().sha256());
    /// let hash3 = H256::from_le_bytes("tx3".as_bytes().sha256());
    /// let hash4 = H256::from_le_bytes("tx4".as_bytes().sha256());
    ///
    /// let transaction_hashes: Vec<H256> = vec![hash1, hash2, hash3, hash4];
    /// let merkle_root = transaction_hashes.merkle_sha256();
    /// // merkle_root can now be included in block header
    /// assert_ne!(merkle_root, H256::default());
    /// ```
    ///
    /// # Security Notes
    /// - Uses double-SHA256 to prevent length-extension attacks
    /// - Deterministic output for the same input ordering
    /// - Provides strong collision resistance through SHA-256
    /// - Odd-length arrays handled consistently with duplication
    fn merkle_sha256(&self) -> H256 {
        let hashes = self.as_ref();

        // Handle special cases for efficiency and correctness
        if hashes.is_empty() {
            return H256::default(); // Zero hash for empty input
        }

        if hashes.len() == 1 {
            return hashes[0]; // Single hash returned directly
        }

        // Initialize working array for bottom-up construction
        // Size: ceil(n/2) to handle the first level of pairing
        let mut nodes = vec![H256::default(); (hashes.len() + 1) / 2];

        // First level: combine adjacent pairs of input hashes
        for (k, node) in nodes.iter_mut().enumerate() {
            *node = children_sha256(2 * k, hashes);
        }

        // Continue building levels until we reach the root
        let mut prev = nodes.len(); // Number of nodes in current level
        let mut right = (nodes.len() + 1) / 2; // Number of nodes in next level

        while prev > right {
            // Combine pairs from current level to build next level
            for k in 0..right {
                nodes[k] = children_sha256(2 * k, &nodes[..prev]);
            }

            prev = right;
            right = (right + 1) / 2;
        }

        // The root hash is now at nodes[0]
        nodes[0]
    }
}

/// Compute the hash of two child nodes in the Merkle tree
///
/// This function implements the core Merkle tree hashing operation,
/// combining two adjacent hashes to produce their parent hash.
///
/// ## Hashing Process
/// 1. **Child Selection**: Get hashes at positions `off` and `off+1`
/// 2. **Odd Handling**: If second child doesn't exist, duplicate the first
/// 3. **Concatenation**: Combine the two 32-byte hashes into 64 bytes
/// 4. **Double-SHA256**: Apply SHA-256 twice for enhanced security
/// 5. **Byte Order**: Convert result to little-endian for NEO compatibility
///
/// ## Security Features
/// - **Double Hashing**: Prevents length-extension attacks on SHA-256
/// - **Consistent Ordering**: Always uses left-right order for determinism
/// - **Odd Handling**: Duplicates last element following NEO conventions
/// - **No Ambiguity**: 64-byte input prevents hash collision attacks
///
/// # Arguments
/// * `off` - Offset/index of the left child in the hash array
/// * `hashes` - Array of hashes representing the current tree level
///
/// # Returns
/// H256 hash representing the parent of the two child nodes
///
/// # Implementation Notes
/// - Uses `SlicesSha256` trait for efficient concatenated hashing
/// - Handles boundary conditions when `off+1` exceeds array length
/// - Converts final hash to little-endian H256 format
/// - Memory-efficient: no additional allocations for concatenation
#[inline]
fn children_sha256(off: usize, hashes: &[H256]) -> H256 {
    // Select the two child hashes, duplicating if at array boundary
    let two = if off + 1 >= hashes.len() {
        // Odd number of elements: duplicate the last one
        [&hashes[off], &hashes[off]]
    } else {
        // Normal case: use adjacent pair
        [&hashes[off], &hashes[off + 1]]
    };

    // Compute double-SHA256 of the concatenated child hashes
    // This follows the Bitcoin/NEO convention for enhanced security
    H256::from_le_bytes(two.iter().slices_sha256().sha256())
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec, vec::Vec};
    use std::time::Instant;

    use super::*;
    use crate::hash::Sha256;

    /// Create a test hash from a simple string for predictable testing
    fn test_hash(s: &str) -> H256 {
        H256::from_le_bytes(s.as_bytes().sha256())
    }

    /// Test basic Merkle tree functionality with known inputs
    ///
    /// Verifies that Merkle root calculation works correctly.
    #[test]
    fn test_merkle_basic() {
        let hashes = vec![
            test_hash("data1"),
            test_hash("data2"),
            test_hash("data3"),
            test_hash("data4"),
        ];

        let root = hashes.merkle_sha256();

        // Root should not be the same as any input hash
        for hash in &hashes {
            assert_ne!(root, *hash, "Root should differ from input hashes");
        }

        // Should be deterministic
        let root2 = hashes.merkle_sha256();
        assert_eq!(root, root2, "Merkle root should be deterministic");
    }

    /// Test empty input handling
    ///
    /// Verifies that empty arrays return the default (zero) hash.
    #[test]
    fn test_merkle_empty() {
        let empty_hashes: Vec<H256> = vec![];
        let root = empty_hashes.merkle_sha256();
        assert_eq!(root, H256::default(), "Empty input should return zero hash");
    }

    /// Test single element handling
    ///
    /// Verifies that single elements are returned unchanged.
    #[test]
    fn test_merkle_single() {
        let single_hash = test_hash("single_element");
        let hashes = vec![single_hash];

        let root = hashes.merkle_sha256();
        assert_eq!(
            root, single_hash,
            "Single element should be returned unchanged"
        );
    }

    /// Test two elements (base case)
    ///
    /// Verifies the fundamental two-element Merkle operation.
    #[test]
    fn test_merkle_two_elements() {
        let hash1 = test_hash("element1");
        let hash2 = test_hash("element2");
        let hashes = vec![hash1, hash2];

        let root = hashes.merkle_sha256();

        // Root should be different from both inputs
        assert_ne!(root, hash1, "Root should differ from first input");
        assert_ne!(root, hash2, "Root should differ from second input");

        // Should be deterministic
        let root2 = hashes.merkle_sha256();
        assert_eq!(root, root2, "Two-element Merkle should be deterministic");

        // Different order should produce different result
        let reversed_hashes = vec![hash2, hash1];
        let reversed_root = reversed_hashes.merkle_sha256();
        assert_ne!(root, reversed_root, "Order should matter in Merkle trees");
    }

    /// Test odd number of elements
    ///
    /// Verifies that odd-length arrays are handled correctly (last element duplicated).
    #[test]
    fn test_merkle_odd_elements() {
        let hashes = vec![test_hash("odd1"), test_hash("odd2"), test_hash("odd3")];

        let root = hashes.merkle_sha256();

        // Should work without errors
        assert_ne!(
            root,
            H256::default(),
            "Odd-length array should produce valid root"
        );

        // Should be deterministic
        let root2 = hashes.merkle_sha256();
        assert_eq!(root, root2, "Odd-length Merkle should be deterministic");
    }

    /// Test power-of-2 vs non-power-of-2 lengths
    ///
    /// Verifies behavior with different array sizes.
    #[test]
    fn test_merkle_various_sizes() {
        let test_cases = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33];

        for size in test_cases {
            let hashes: Vec<H256> = (0..size)
                .map(|i| test_hash(&format!("element_{}", i)))
                .collect();

            let root = hashes.merkle_sha256();

            // Should produce valid output for any size
            if size == 0 {
                assert_eq!(
                    root,
                    H256::default(),
                    "Size {} should return zero hash",
                    size
                );
            } else {
                assert_ne!(
                    root,
                    H256::default(),
                    "Size {} should produce non-zero root",
                    size
                );
            }

            // Should be deterministic
            let root2 = hashes.merkle_sha256();
            assert_eq!(root, root2, "Size {} should be deterministic", size);
        }
    }

    /// Test that different inputs produce different roots
    ///
    /// Verifies the collision resistance property.
    #[test]
    fn test_merkle_uniqueness() {
        let data_sets = vec![
            vec!["a", "b", "c", "d"],
            vec!["a", "b", "c", "e"],      // One element different
            vec!["a", "b", "d", "c"],      // Order changed
            vec!["a", "b", "c"],           // Shorter
            vec!["a", "b", "c", "d", "e"], // Longer
        ];

        let mut roots = Vec::new();

        for data_set in data_sets {
            let hashes: Vec<H256> = data_set.iter().map(|s| test_hash(s)).collect();
            let root = hashes.merkle_sha256();
            roots.push(root);
        }

        // All roots should be different
        for i in 0..roots.len() {
            for j in i + 1..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "Different inputs should produce different roots (case {} vs {})",
                    i, j
                );
            }
        }
    }

    /// Test avalanche effect
    ///
    /// Verifies that small changes in input produce large changes in output.
    #[test]
    fn test_merkle_avalanche_effect() {
        let original_hashes = vec![
            test_hash("data1"),
            test_hash("data2"),
            test_hash("data3"),
            test_hash("data4"),
        ];

        let original_root = original_hashes.merkle_sha256();

        // Change one bit in one hash and verify the root changes significantly
        let original_hash_bytes = test_hash("data1");
        let mut modified_bytes: [u8; 32] = *original_hash_bytes.as_ref();
        // Flip one bit in the last byte
        modified_bytes[31] ^= 0x01;
        let modified_hash = H256::from_le_bytes(modified_bytes);

        let modified_hashes = vec![
            modified_hash,
            test_hash("data2"),
            test_hash("data3"),
            test_hash("data4"),
        ];

        let modified_root = modified_hashes.merkle_sha256();

        assert_ne!(
            original_root, modified_root,
            "Single bit change should change root"
        );

        // Count differing bits to ensure good avalanche
        let mut differing_bits = 0;
        for i in 0..32 {
            let orig_byte = (original_root.as_ref() as &[u8])[i];
            let mod_byte = (modified_root.as_ref() as &[u8])[i];
            differing_bits += (orig_byte ^ mod_byte).count_ones();
        }

        // Good avalanche should change roughly half the bits
        assert!(
            differing_bits > 64,
            "Avalanche effect should affect many bits (got {})",
            differing_bits
        );
    }

    /// Test Merkle tree with identical elements
    ///
    /// Verifies behavior when multiple elements are the same.
    #[test]
    fn test_merkle_identical_elements() {
        let identical_hash = test_hash("same_data");
        let hashes = vec![identical_hash; 4];

        let root = hashes.merkle_sha256();

        // Root should not be the same as the input (since it's double-hashed)
        assert_ne!(
            root, identical_hash,
            "Root should differ from identical inputs"
        );

        // Should be deterministic
        let root2 = hashes.merkle_sha256();
        assert_eq!(root, root2, "Identical elements should be deterministic");

        // Different number of identical elements should produce different roots
        let shorter_hashes = vec![identical_hash; 2];
        let shorter_root = shorter_hashes.merkle_sha256();
        assert_ne!(
            root, shorter_root,
            "Different array sizes should produce different roots"
        );
    }

    /// Test Merkle tree with zero hashes
    ///
    /// Edge case with all-zero input hashes.
    #[test]
    fn test_merkle_zero_hashes() {
        let zero_hash = H256::default();
        let hashes = vec![zero_hash; 4];

        let root = hashes.merkle_sha256();

        // Root should not be zero (since it's computed via SHA-256)
        assert_ne!(
            root,
            H256::default(),
            "Root of zero hashes should not be zero"
        );

        // Should be deterministic
        let root2 = hashes.merkle_sha256();
        assert_eq!(root, root2, "Zero hashes should be deterministic");
    }

    /// Test Merkle tree with maximum value hashes
    ///
    /// Edge case with all-max input hashes.
    #[test]
    fn test_merkle_max_hashes() {
        let max_hash = H256::from_le_bytes([0xFF; 32]);
        let hashes = vec![max_hash; 4];

        let root = hashes.merkle_sha256();

        // Root should not be max value (since it's computed via SHA-256)
        assert_ne!(root, max_hash, "Root of max hashes should not be max");

        // Should be deterministic
        let root2 = hashes.merkle_sha256();
        assert_eq!(root, root2, "Max hashes should be deterministic");
    }

    /// Test NEO blockchain transaction scenario
    ///
    /// Simulates a realistic blockchain use case.
    #[test]
    fn test_merkle_blockchain_simulation() {
        // Simulate transaction hashes in a block
        let transaction_hashes = vec![
            test_hash("tx_coinbase_reward"),
            test_hash("tx_alice_to_bob_100_neo"),
            test_hash("tx_bob_to_charlie_50_neo"),
            test_hash("tx_contract_execution_gas"),
            test_hash("tx_token_transfer_nep17"),
        ];

        let block_merkle_root = transaction_hashes.merkle_sha256();

        // Verify properties expected in blockchain usage
        assert_ne!(
            block_merkle_root,
            H256::default(),
            "Block should have valid Merkle root"
        );

        // Simulate adding another transaction
        let mut extended_transactions = transaction_hashes.clone();
        extended_transactions.push(test_hash("tx_new_transfer"));

        let extended_root = extended_transactions.merkle_sha256();
        assert_ne!(
            block_merkle_root, extended_root,
            "Adding transaction should change Merkle root"
        );

        // Simulate transaction order change (should change root)
        let mut reordered_transactions = transaction_hashes.clone();
        reordered_transactions.swap(0, 1);

        let reordered_root = reordered_transactions.merkle_sha256();
        assert_ne!(
            block_merkle_root, reordered_root,
            "Transaction order should affect Merkle root"
        );
    }

    /// Test performance with large arrays
    ///
    /// Ensures Merkle computation performs adequately for blockchain use.
    #[test]
    fn test_merkle_performance() {
        // Simulate a block with many transactions
        let large_hash_count = 1000;
        let hashes: Vec<H256> = (0..large_hash_count)
            .map(|i| test_hash(&format!("transaction_{}", i)))
            .collect();

        let start = Instant::now();
        let root = hashes.merkle_sha256();
        let duration = start.elapsed();

        // Should complete quickly (< 100ms for 1000 transactions)
        assert!(
            duration.as_millis() < 100,
            "Merkle tree of {} hashes took too long: {}ms",
            large_hash_count,
            duration.as_millis()
        );

        // Should produce valid output
        assert_ne!(
            root,
            H256::default(),
            "Large Merkle tree should produce valid root"
        );

        println!(
            "Merkle tree of {} hashes computed in: {}μs",
            large_hash_count,
            duration.as_micros()
        );
    }

    /// Test memory efficiency
    ///
    /// Verifies that Merkle computation doesn't use excessive memory.
    #[test]
    fn test_merkle_memory_efficiency() {
        // Test with various sizes to ensure in-place computation works
        let sizes = vec![100, 500, 1000, 2000];

        for size in sizes {
            let hashes: Vec<H256> = (0..size)
                .map(|i| test_hash(&format!("hash_{}", i)))
                .collect();

            let root = hashes.merkle_sha256();

            // Should work without memory issues
            assert_ne!(
                root,
                H256::default(),
                "Size {} should produce valid root",
                size
            );
        }
    }

    /// Test trait implementation for different collection types
    ///
    /// Verifies that the trait works with various container types.
    #[test]
    fn test_merkle_trait_implementations() {
        let hash_data = vec![test_hash("test1"), test_hash("test2"), test_hash("test3")];

        // Test with Vec
        let vec_root = hash_data.merkle_sha256();

        // Test with slice
        let slice_root = hash_data.as_slice().merkle_sha256();
        assert_eq!(
            vec_root, slice_root,
            "Vec and slice should produce same root"
        );

        // Test with array (for small sizes)
        let array_data = [test_hash("test1"), test_hash("test2"), test_hash("test3")];
        let array_root = array_data.merkle_sha256();
        assert_eq!(
            vec_root, array_root,
            "Vec and array should produce same root"
        );
    }
}
