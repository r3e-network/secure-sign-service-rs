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

    H256::from_le_bytes(two.iter().slices_sha256().sha256())
}
