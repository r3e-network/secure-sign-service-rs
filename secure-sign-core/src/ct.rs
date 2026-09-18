// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time when they have equal length.
///
/// Unequal lengths return false after a dummy compare so the mismatch is not
/// a trivial early-return on the first differing caller-supplied secret.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        let _ = left.ct_eq(left);
        return false;
    }
    bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn equal_secrets_match_and_mismatches_do_not() {
        assert!(constant_time_eq(b"abcdef01", b"abcdef01"));
        assert!(!constant_time_eq(b"abcdef01", b"abcdef02"));
        assert!(!constant_time_eq(b"abcdef01", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
