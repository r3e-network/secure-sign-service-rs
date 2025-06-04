// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Secure Sign Core Library
//!
//! This is the core cryptographic and blockchain library for the Secure Sign Service.
//! It provides fundamental cryptographic primitives, NEO blockchain functionality,
//! and utility functions required for secure transaction signing operations.
//!
//! ## Library Organization
//!
//! The library is organized into several key modules:
//!
//! ### Cryptographic Primitives
//! - [`secp256r1`] - Elliptic curve cryptography (P-256/secp256r1)
//! - [`ecdsa`] - Digital signature generation and verification
//! - [`hmac`] - HMAC-SHA256 for key derivation and authentication
//! - [`scrypt`] - Memory-hard key derivation function
//! - [`random`] - Cryptographically secure random number generation
//! - [`aes`] - AES encryption/decryption utilities
//! - [`hash`] - SHA-256 and other hash functions
//! - [`merkle`] - Merkle tree construction for blockchain verification
//!
//! ### NEO Blockchain Support
//! - [`neo`] - Complete NEO N3 blockchain integration including:
//!   - NEP-6 wallet format support
//!   - NEP-2 private key encryption
//!   - Transaction signing and verification
//!   - Address generation and validation
//!   - Smart contract interaction
//!
//! ### Data Encoding and Utilities
//! - [`base58`] - Base58 and Base58Check encoding (NEO addresses)
//! - [`base64`] - Base64 encoding for binary data serialization
//! - [`bin`] - Binary data manipulation utilities
//! - [`bytes`] - Byte array conversion and manipulation
//! - [`h160`] - 160-bit hash type (script hashes, addresses)
//! - [`h256`] - 256-bit hash type (transaction hashes, block hashes)
//!
//! ## Design Principles
//!
//! ### Security First
//! - **Memory Safety**: Sensitive data automatically zeroized after use
//! - **Constant-time Operations**: Resistant to timing-based side-channel attacks
//! - **Input Validation**: Comprehensive validation of all cryptographic inputs
//! - **Error Handling**: Secure failure modes that don't leak sensitive information
//!
//! ### Performance
//! - **Zero-copy Operations**: Minimal memory allocations and copying
//! - **Efficient Algorithms**: Optimized implementations of cryptographic primitives
//! - **Hardware Acceleration**: Leverages platform-specific optimizations when available
//! - **Async-ready**: Compatible with async/await patterns
//!
//! ### Standards Compliance
//! - **NEO N3 Compatible**: Full compatibility with NEO blockchain protocols
//! - **RFC Standards**: Implements relevant IETF RFCs (6979, 7914, etc.)
//! - **Industry Standards**: Follows NIST and other cryptographic standards
//! - **Cross-platform**: Works across different operating systems and architectures
//!
//! ## Feature Flags
//!
//! - `std` (default): Enables standard library features and error types
//! - When `std` is disabled, the library operates in `no_std` mode for embedded use
//!
//! ## Security Considerations
//!
//! This library handles highly sensitive cryptographic material including private keys,
//! passphrases, and signing operations. Key security measures include:
//!
//! - **Zeroization**: All sensitive data is automatically cleared from memory
//! - **Constant-time Comparisons**: Prevents timing-based information leakage
//! - **Secure Random Generation**: Uses OS-provided cryptographically secure RNG
//! - **Side-channel Resistance**: Implementation designed to resist various attack vectors
//! - **Memory Protection**: Utilizes secure memory allocation where possible
//!
//! ## Usage Examples
//!
//! ```rust
//! use secure_sign_core::{
//!     secp256r1::Keypair,
//!     random::EnvCryptRandom,
//!     hmac::HmacSha256,
//! };
//!
//! // Generate a new keypair
//! let mut rng = EnvCryptRandom;
//! let keypair = Keypair::gen(&mut rng).expect("Should generate keypair");
//!
//! // Example key derivation
//! let salt: [u8; 0] = [];
//! let input_data = b"example data";
//! let derived_key = salt.hmac_sha256(input_data);
//!
//! assert_eq!(derived_key.len(), 32);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

// Cryptographic primitives modules
/// AES encryption and decryption utilities
pub mod aes;
/// Base58 and Base58Check encoding (used for NEO addresses)
pub mod base58;
/// Base64 encoding for binary data serialization
pub mod base64;
/// Binary data manipulation and conversion utilities
pub mod bin;
/// Byte array conversion traits and utilities
pub mod bytes;
/// ECDSA digital signature generation and verification
pub mod ecdsa;
/// 160-bit hash type for script hashes and addresses
pub mod h160;
/// 256-bit hash type for transaction and block hashes
pub mod h256;
/// SHA-256 and other cryptographic hash functions
pub mod hash;
/// HMAC-SHA256 for key derivation and message authentication
pub mod hmac;
/// Merkle tree construction for blockchain verification
pub mod merkle;
/// Cryptographically secure random number generation
pub mod random;
/// Scrypt password-based key derivation function
pub mod scrypt;
/// secp256r1 (P-256) elliptic curve cryptography
pub mod secp256r1;

// NEO blockchain-specific modules
/// Complete NEO N3 blockchain integration and utilities
pub mod neo;
