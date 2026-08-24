// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::vec;

use crate::h256::H256;
use crate::hash::{Sha256, SlicesSha256};

pub trait MerkleSha256 {
    fn merkle_sha256(&self) -> H256;
}

impl<T: AsRef<[H256]>> MerkleSha256 for T {
    fn merkle_sha256(&self) -> H256 {
        let hashes = self.as_ref();
        if hashes.is_empty() {
            return H256::default();
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut nodes = vec![H256::default(); hashes.len().div_ceil(2)];
        for (k, node) in nodes.iter_mut().enumerate() {
            *node = children_sha256(2 * k, hashes);
        }

        let mut prev = nodes.len();
        let mut right = nodes.len().div_ceil(2);
        while prev > right {
            for k in 0..right {
                nodes[k] = children_sha256(2 * k, &nodes[..prev]);
            }

            prev = right;
            right = right.div_ceil(2);
        }

        nodes[0]
    }
}

#[inline]
fn children_sha256(off: usize, hashes: &[H256]) -> H256 {
    let two = if off + 1 >= hashes.len() {
        [&hashes[off], &hashes[off]]
    } else {
        [&hashes[off], &hashes[off + 1]]
    };

    let first = two.iter().slices_sha256();
    H256::from_le_bytes(first.sha256())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeated_hash(byte: u8) -> H256 {
        H256::from_le_bytes([byte; 32])
    }

    fn decoded_hash(value: &str) -> H256 {
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes).unwrap();
        H256::from_le_bytes(bytes)
    }

    #[test]
    fn merkle_root_matches_neo_double_sha256() {
        let empty: [H256; 0] = [];
        assert_eq!(empty.merkle_sha256(), H256::default());
        assert_eq!(vec![repeated_hash(1)].merkle_sha256(), repeated_hash(1));
        assert_eq!(
            vec![repeated_hash(1), repeated_hash(2)].merkle_sha256(),
            decoded_hash("39ce20bede82c96b8908bec4a157b09c549b3db90b9b474bda9ae9b9030310b4")
        );
        assert_eq!(
            vec![repeated_hash(1), repeated_hash(2), repeated_hash(3)].merkle_sha256(),
            decoded_hash("223e023fadf1f053df26988871f893c821c28edf77d64a955e6c2a02d547bdac")
        );
    }
}
