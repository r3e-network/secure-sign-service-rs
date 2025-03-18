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

pub trait ToRevArray<T: Copy, const N: usize> {
    fn to_rev_array(&self) -> [T; N];
}

impl<T: Copy + Default, const N: usize> ToRevArray<T, N> for [T] {
    /// slice to revered array(for endian transition). slice.len() must be constant
    #[inline]
    fn to_rev_array(&self) -> [T; N] {
        let mut d = [Default::default(); N];
        d.copy_from_slice(self);
        d.reverse();
        d
    }
}

impl<T: Copy + Default, const N: usize> ToRevArray<T, N> for [T; N] {
    #[inline]
    fn to_rev_array(&self) -> [T; N] {
        let mut b = self.clone();
        b.reverse();
        b
    }
}
