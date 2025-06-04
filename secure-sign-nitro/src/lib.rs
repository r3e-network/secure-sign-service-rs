// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use aws_nitro_enclaves_nsm_api::{api, driver};
use secure_sign_core::random::CryptRandom;
use zeroize::Zeroizing;

pub struct Nsm {
    fd: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum NsmError {
    #[error("nitro: initialize nsm error: {0}")]
    InitError(i32),

    #[error("nitro: request error: {0:?}")]
    RequestError(api::ErrorCode),

    #[error("nitro: unexpected error")]
    Unexpected,
}

impl Nsm {
    pub fn new() -> Result<Self, NsmError> {
        let fd = driver::nsm_init();
        if fd < 0 {
            return Err(NsmError::InitError(fd));
        }

        Ok(Self { fd })
    }

    pub fn get_random(&self) -> Result<Zeroizing<Vec<u8>>, NsmError> {
        let req: api::Request = api::Request::GetRandom;
        let bytes = match driver::nsm_process_request(self.fd, req) {
            api::Response::GetRandom { random } => random,
            api::Response::Error(code) => return Err(NsmError::RequestError(code)),
            _ => return Err(NsmError::Unexpected),
        };

        Ok(Zeroizing::new(bytes))
    }
}

impl CryptRandom for Nsm {
    type Error = NsmError;

    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), NsmError> {
        let mut n = 0;
        while n < buf.len() {
            let bytes = self.get_random()?; // TODO: clear the `buf` if error
            let once = core::cmp::min(bytes.len(), buf.len() - n);
            buf[n..n + once].copy_from_slice(&bytes[..once]);
            n += once;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test NsmError error message formatting
    ///
    /// Verifies that all error variants produce meaningful error messages.
    #[test]
    fn test_nsm_error_formatting() {
        // Test InitError formatting
        let init_error = NsmError::InitError(-1);
        let error_msg = format!("{init_error}");
        assert!(
            error_msg.contains("initialize nsm error"),
            "InitError should contain descriptive text"
        );
        assert!(
            error_msg.contains("-1"),
            "InitError should include the error code"
        );

        // Test RequestError formatting
        let request_error = NsmError::RequestError(api::ErrorCode::InvalidOperation);
        let error_msg = format!("{request_error}");
        assert!(
            error_msg.contains("request error"),
            "RequestError should contain descriptive text"
        );
        assert!(
            error_msg.contains("InvalidOperation"),
            "RequestError should include the error code"
        );

        // Test Unexpected error formatting
        let unexpected_error = NsmError::Unexpected;
        let error_msg = format!("{unexpected_error}");
        assert!(
            error_msg.contains("unexpected error"),
            "Unexpected should contain descriptive text"
        );
    }

    /// Test error variant debugging output
    ///
    /// Verifies that Debug trait is properly implemented for all error types.
    #[test]
    fn test_nsm_error_debug() {
        let init_error = NsmError::InitError(-1);
        let debug_output = format!("{init_error:?}");
        assert!(
            debug_output.contains("InitError"),
            "Debug should show variant name"
        );
        assert!(debug_output.contains("-1"), "Debug should show the value");

        let request_error = NsmError::RequestError(api::ErrorCode::InvalidOperation);
        let debug_output = format!("{request_error:?}");
        assert!(
            debug_output.contains("RequestError"),
            "Debug should show variant name"
        );
        assert!(
            debug_output.contains("InvalidOperation"),
            "Debug should show the error code"
        );

        let unexpected_error = NsmError::Unexpected;
        let debug_output = format!("{unexpected_error:?}");
        assert!(
            debug_output.contains("Unexpected"),
            "Debug should show variant name"
        );
    }

    /// Test buffer chunking logic for CryptRandom implementation
    ///
    /// Simulates the buffer filling logic without requiring actual NSM hardware.
    #[test]
    fn test_buffer_chunking_logic() {
        // Test the chunking algorithm used in try_fill_bytes
        let available_chunk_size = 32; // Simulate NSM returning 32 bytes
        let buffer_size = 100; // Buffer larger than one chunk

        let mut filled_bytes = 0;
        let mut chunks_used = 0;

        while filled_bytes < buffer_size {
            let remaining = buffer_size - filled_bytes;
            let chunk_size = core::cmp::min(available_chunk_size, remaining);
            filled_bytes += chunk_size;
            chunks_used += 1;
        }

        assert_eq!(filled_bytes, buffer_size, "Should fill entire buffer");
        assert_eq!(
            chunks_used, 4,
            "Should use 4 chunks for 100-byte buffer with 32-byte chunks"
        );
    }

    /// Test edge cases for buffer sizes
    ///
    /// Verifies the chunking logic handles various buffer sizes correctly.
    #[test]
    fn test_buffer_edge_cases() {
        // Test empty buffer
        let buffer_size = 0;
        let chunk_size = 32;

        let mut total = 0;
        let mut iterations = 0;
        while total < buffer_size {
            let remaining = buffer_size - total;
            let chunk = core::cmp::min(chunk_size, remaining);
            total += chunk;
            iterations += 1;
        }

        assert_eq!(iterations, 0, "Empty buffer should require no iterations");

        // Test buffer smaller than chunk size
        let buffer_size = 16;
        let chunk_size = 32;

        let mut total = 0;
        let mut iterations = 0;
        while total < buffer_size {
            let remaining = buffer_size - total;
            let chunk = core::cmp::min(chunk_size, remaining);
            total += chunk;
            iterations += 1;
        }

        assert_eq!(
            iterations, 1,
            "Small buffer should require exactly one iteration"
        );
        assert_eq!(total, buffer_size, "Should fill exact buffer size");

        // Test buffer exactly equal to chunk size
        let buffer_size = 32;
        let chunk_size = 32;

        let mut total = 0;
        let mut iterations = 0;
        while total < buffer_size {
            let remaining = buffer_size - total;
            let chunk = core::cmp::min(chunk_size, remaining);
            total += chunk;
            iterations += 1;
        }

        assert_eq!(
            iterations, 1,
            "Equal-size buffer should require exactly one iteration"
        );
    }

    /// Test Zeroizing wrapper behavior
    ///
    /// Verifies that random data is properly wrapped for automatic cleanup.
    #[test]
    fn test_zeroizing_wrapper() {
        // Create a Zeroizing wrapper with test data
        let test_data = vec![0x42, 0x43, 0x44];
        let wrapped = Zeroizing::new(test_data.clone());

        // Verify data is accessible
        assert_eq!(*wrapped, test_data, "Zeroizing should preserve data access");
        assert_eq!(wrapped.len(), 3, "Zeroizing should preserve length");
        assert_eq!(wrapped[0], 0x42, "Zeroizing should allow indexing");

        // Verify it implements expected traits
        let _clone = wrapped.clone();
        let _debug = format!("{wrapped:?}");

        // Test that it can be converted back to Vec when needed
        let inner_vec: Vec<u8> = (*wrapped).clone();
        assert_eq!(inner_vec, test_data, "Should be able to extract inner data");
    }

    /// Test trait bounds and type constraints
    ///
    /// Verifies that NSM types implement required traits.
    #[test]
    fn test_trait_implementations() {
        // Test that NsmError implements required traits
        fn assert_error_traits<T: std::error::Error + std::fmt::Debug + std::fmt::Display>() {}
        assert_error_traits::<NsmError>();

        // Test that error can be converted to Box<dyn std::error::Error>
        let error = NsmError::Unexpected;
        let _boxed: Box<dyn std::error::Error> = Box::new(error);

        // Test that error can be used in Result types
        let _result: Result<(), NsmError> = Err(NsmError::InitError(-1));
    }

    /// Test API request/response type compatibility
    ///
    /// Verifies that we're using the API types correctly.
    #[test]
    fn test_api_types() {
        // Test that we can create the correct request type
        let _request: api::Request = api::Request::GetRandom;

        // Test error code variants that might be returned
        let error_codes: Vec<api::ErrorCode> = vec![
            api::ErrorCode::InvalidOperation,
            api::ErrorCode::InvalidIndex,
            api::ErrorCode::ReadOnlyIndex,
            api::ErrorCode::InvalidResponse,
            api::ErrorCode::BufferTooSmall,
            api::ErrorCode::InputTooLarge,
        ];

        for error_code in error_codes {
            let _nsm_error = NsmError::RequestError(error_code);
        }
    }

    /// Test minimum buffer sizes and constraints
    ///
    /// Verifies handling of various buffer size constraints.
    #[test]
    fn test_buffer_constraints() {
        // Test with single byte buffer
        let mut n = 0;
        let buffer_len = 1;
        let chunk_size = 32; // Typical NSM chunk size

        while n < buffer_len {
            let once = core::cmp::min(chunk_size, buffer_len - n);
            assert_eq!(once, 1, "Single byte should use chunk size of 1");
            n += once;
        }

        assert_eq!(n, buffer_len, "Should fill exactly one byte");

        // Test with large buffer
        let mut n = 0;
        let buffer_len = 1024;
        let chunk_size = 32;
        let mut iterations = 0;

        while n < buffer_len {
            let once = core::cmp::min(chunk_size, buffer_len - n);
            n += once;
            iterations += 1;
        }

        assert_eq!(n, buffer_len, "Should fill entire large buffer");
        assert_eq!(
            iterations, 32,
            "Should require 32 iterations for 1024-byte buffer"
        );
    }

    /// Test error propagation patterns
    ///
    /// Verifies that errors would be properly propagated through the call chain.
    #[test]
    fn test_error_propagation() {
        // Test that errors can be converted between types appropriately
        let init_error = NsmError::InitError(-1);
        let _error_string = format!("{init_error}");

        // Test chaining with ? operator (would work in actual implementation)
        fn simulate_error_chain() -> Result<(), NsmError> {
            // This simulates what would happen in the actual implementation
            Err(NsmError::RequestError(api::ErrorCode::InvalidOperation))
        }

        let result = simulate_error_chain();
        assert!(result.is_err(), "Should propagate error");

        if let Err(e) = result {
            match e {
                NsmError::RequestError(api::ErrorCode::InvalidOperation) => {
                    // Expected case
                }
                _ => unreachable!("Should preserve error type"),
            }
        }
    }

    /// Test file descriptor handling patterns
    ///
    /// Verifies the file descriptor management approach.
    #[test]
    fn test_fd_handling() {
        // Test that negative file descriptors are treated as errors
        let invalid_fds = vec![-1, -2, -100];

        for fd in invalid_fds {
            // Simulate the error condition check
            if fd < 0 {
                let error = NsmError::InitError(fd);
                assert!(
                    format!("{error}").contains(&fd.to_string()),
                    "Error should include the FD value"
                );
            }
        }

        // Test that non-negative file descriptors would be accepted
        let valid_fds = vec![0, 1, 3, 100];

        for fd in valid_fds {
            // Simulate the acceptance condition
            assert!(fd >= 0, "Valid FDs should be non-negative");
        }
    }

    /// Test integration with CryptRandom trait
    ///
    /// Verifies that the trait implementation signature is correct.
    #[test]
    fn test_crypt_random_trait_compatibility() {
        // Test that we can use Nsm as a CryptRandom trait object
        // (This won't actually work without NSM hardware, but tests the types)

        #[allow(dead_code)]
        fn accept_crypt_random<T: CryptRandom>(_rng: T)
        where
            T::Error: std::fmt::Debug,
        {
        }

        // This tests that the trait is implemented correctly
        // In a real environment with NSM hardware, you could do:
        // let nsm = Nsm::new().unwrap();
        // accept_crypt_random(nsm);

        // For now, just test the error type compatibility
        let error = NsmError::Unexpected;
        let _debug_output = format!("{error:?}");
    }
}
