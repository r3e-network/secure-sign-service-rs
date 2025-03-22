// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

pub trait CryptRandom {
    type Error: core::fmt::Debug + core::fmt::Display;

    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

pub struct EnvCryptRandom;

impl CryptRandom for EnvCryptRandom {
    type Error = getrandom::Error;

    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(buf)
    }
}
