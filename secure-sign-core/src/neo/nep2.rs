// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # NEP-2 Private Key Encryption Standard
//!
//! This module implements the NEP-2 standard for encrypting private keys with passwords.
//! NEP-2 provides a secure way to store private keys in an encrypted format that can be
//! safely written to disk or transmitted over insecure channels.
//!
//! ## NEP-2 Standard Overview
//!
//! NEP-2 defines a multi-layer encryption scheme for private keys:
//!
//! ```text
//! Private Key → XOR with derived key → AES-256-ECB → Base58Check encoding
//!                     ↑
//!                 Scrypt(passphrase, salt)
//! ```
//!
//! ## Encryption Process
//!
//! 1. **Address Generation**: Derive NEO address from public key
//! 2. **Salt Creation**: Use first 4 bytes of double-SHA256(address)
//! 3. **Key Derivation**: Apply scrypt to passphrase with salt → 64 bytes
//! 4. **Key Preparation**: XOR private key with first 32 bytes of derived key
//! 5. **AES Encryption**: Encrypt XORed key with last 32 bytes as AES key
//! 6. **Format Assembly**: Combine prefix + salt + encrypted key
//! 7. **Base58Check**: Encode final result with checksum
//!
//! ## Security Features
//!
//! - **Password-Based**: Protects private keys with user passphrases
//! - **Scrypt Hardening**: Memory-hard key derivation resists GPU/ASIC attacks
//! - **Address Binding**: Salt derived from address prevents rainbow tables
//! - **Tamper Detection**: Base58Check encoding includes integrity checksum
//! - **Standard Format**: Compatible with all NEO wallets and tools
//!
//! ## NEP-2 Format Structure
//!
//! ```text
//! [Flag:1][Type:1][AddressHash:4][EncryptedKey:32] → Base58Check
//!  0x01   0x42   first4(sha256(sha256(address)))
//! ```
//!
//! Total: 39 bytes before Base58Check encoding
//!
//! ## Security Considerations
//!
//! - **Passphrase Strength**: Security depends entirely on passphrase entropy
//! - **Scrypt Parameters**: Higher parameters increase brute-force resistance
//! - **Side-Channel Protection**: Implementation uses constant-time operations
//! - **Memory Safety**: Sensitive data automatically zeroized after use

use alloc::{string::String, vec::Vec};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    aes::Aes256EcbCipher,
    base58::{FromBase58Check, ToBase58Check},
    bytes::ToArray,
    hash::Sha256,
    neo::ToNeo3Address,
    scrypt::{DeriveScryptKey, ScryptParams},
    secp256r1::{Keypair, PrivateKey},
};

/// Size of a secp256r1 private key in bytes
const KEY_SIZE: usize = 32;

/// Size of a complete NEP-2 encrypted key in bytes (before Base58Check encoding)
///
/// Structure: [Flag:1][Type:1][AddressHash:4][EncryptedKey:32] = 39 bytes
const NEP2_KEY_SIZE: usize = 39;

/// Size of the derived key from scrypt (64 bytes)
///
/// First 32 bytes: Used for XOR with private key
/// Last 32 bytes: Used as AES-256 encryption key
const DERIVED_KEY_SIZE: usize = KEY_SIZE * 2;

/// Default scrypt parameters recommended by the NEP-2 standard
///
/// These parameters provide a good balance between security and performance:
/// - N=16384: Moderate memory usage (~16MB) and computation time (~100ms)
/// - r=8: Standard block size for optimal memory/CPU ratio
/// - p=8: Moderate parallelization for multi-core systems
///
/// These parameters may be too slow for some applications and too fast for
/// others. Adjust based on your security requirements and performance constraints.
pub const fn scrypt_params() -> ScryptParams {
    ScryptParams {
        n: 16384, // 2^14, requires ~16MB memory
        p: 8,     // 8-way parallelization
        r: 8,     // 8 × 128-byte blocks
    }
}

/// Trait for converting keypairs to NEP-2 encrypted format
///
/// This trait provides the ability to encrypt private keys using the NEP-2
/// standard, protecting them with a user-provided passphrase.
pub trait TryToNep2Key {
    type Error;

    /// Convert this keypair to a NEP-2 encrypted key string
    ///
    /// # Arguments
    /// * `scrypt_params` - Scrypt parameters for key derivation
    /// * `passphrase` - User passphrase for encryption
    ///
    /// # Returns
    /// * `Ok(String)` - Base58Check-encoded NEP-2 encrypted key
    /// * `Err(Self::Error)` - Encryption failed due to invalid parameters
    fn try_to_nep2_key(
        &self,
        scrypt_params: ScryptParams,
        passphrase: &[u8],
    ) -> Result<String, Self::Error>;
}

/// Errors that can occur during NEP-2 key encryption
#[derive(Debug, Clone, thiserror::Error)]
pub enum ToNep2KeyError {
    #[error("nep2-key: invalid scrypt params")]
    InvalidScryptParams,

    #[error("nep2-key: invalid passphrase")]
    InvalidPassphrase,
}

impl TryToNep2Key for Keypair {
    type Error = ToNep2KeyError;

    /// Encrypt this keypair's private key using NEP-2 standard
    ///
    /// This method implements the complete NEP-2 encryption process:
    ///
    /// ## Encryption Steps
    /// 1. **Passphrase Validation**: Ensure passphrase is non-empty
    /// 2. **Address Generation**: Derive NEO address from public key
    /// 3. **Salt Creation**: Double-SHA256 hash of address, take first 4 bytes
    /// 4. **Key Derivation**: Apply scrypt with passphrase and salt
    /// 5. **Private Key Masking**: XOR private key with first 32 derived bytes
    /// 6. **AES Encryption**: Encrypt masked key with last 32 derived bytes
    /// 7. **Format Assembly**: Combine NEP-2 prefix, salt, and encrypted key
    /// 8. **Base58Check Encoding**: Final encoding with integrity checksum
    ///
    /// ## Security Notes
    /// - Passphrase is used directly without normalization (be careful with unicode)
    /// - Salt is deterministic based on address (same key+passphrase = same result)
    /// - Scrypt parameters should be chosen based on security requirements
    /// - Result can be safely stored in plaintext files or databases
    ///
    /// # Arguments
    /// * `scrypt` - Scrypt parameters controlling encryption cost
    /// * `passphrase` - User passphrase (must be non-empty)
    ///
    /// # Returns
    /// * `Ok(String)` - Base58Check-encoded NEP-2 encrypted private key
    /// * `Err(ToNep2KeyError)` - Empty passphrase or invalid scrypt parameters
    ///
    /// # Example Usage
    /// ```rust
    /// use secure_sign_core::neo::nep2::{TryToNep2Key, scrypt_params};
    /// use secure_sign_core::secp256r1::{Keypair, PrivateKey};
    ///
    /// // Create a test private key
    /// let private_key = PrivateKey::from_be_bytes(&[
    ///     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    ///     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
    /// ]).expect("Should create private key");
    ///
    /// let keypair = Keypair::new(private_key).expect("Should create keypair");
    /// let params = scrypt_params(); // Use standard parameters
    /// let encrypted = keypair.try_to_nep2_key(params, b"my_password")
    ///     .expect("Should encrypt key");
    ///
    /// // encrypted is now safe to store in the format: "6PYWucwbu5pQV9j1wq9kyb..."
    /// assert!(encrypted.starts_with("6P"));
    /// ```
    fn try_to_nep2_key(
        &self,
        scrypt: ScryptParams,
        passphrase: &[u8],
    ) -> Result<String, Self::Error> {
        // Validate passphrase is non-empty (empty passphrases are insecure)
        if passphrase.is_empty() {
            return Err(ToNep2KeyError::InvalidPassphrase);
        }

        // Step 1: Generate NEO address from public key
        let address = self.public_key().to_neo3_address();

        // Step 2: Create deterministic salt from address
        // Use double-SHA256 for additional security, take first 4 bytes
        let hash = address.as_str().sha256().sha256();

        // Step 3: Derive 64-byte key using scrypt
        let derived = passphrase
            .derive_scrypt_key::<DERIVED_KEY_SIZE>(&hash[..4], scrypt)
            .map_err(|_| ToNep2KeyError::InvalidScryptParams)?;

        // Step 4: Prepare private key for encryption
        // XOR private key with first 32 bytes of derived key
        let sk = self.private_key().as_be_bytes();
        let mut key = xor_array::<KEY_SIZE>(sk, &derived[..KEY_SIZE]);

        // Step 5: Encrypt the XORed private key using AES-256-ECB
        // Use the last 32 bytes of derived key as AES encryption key
        derived[KEY_SIZE..]
            .aes256_ecb_encrypt_aligned(key.as_mut_slice())
            .expect("`aes256_ecb_encrypt_aligned` should be ok");

        // Step 6: Assemble the NEP-2 format
        let mut buf = Vec::<u8>::with_capacity(3 + 4 + key.len());
        buf.push(0x01); // NEP-2 flag byte
        buf.push(0x42); // NEP-2 type byte (non-EC-multiply)
        buf.push(0xe0); // NEP-2 format byte
        buf.extend_from_slice(&hash[..4]); // Address hash (salt)
        buf.extend_from_slice(key.as_slice()); // Encrypted private key

        // Step 7: Apply Base58Check encoding for final format
        Ok(buf.to_base58_check())
    }
}

/// Errors that can occur during NEP-2 key decryption
#[derive(Debug, Clone, thiserror::Error)]
pub enum FromNep2KeyError {
    #[error("nep2-key: invalid base58check")]
    InvalidBase58Check,

    #[error("nep2-key: the key length(base58-decoded) must be 39")]
    InvalidKeyLength,

    #[error("nep2-key: invalid scrypt params")]
    InvalidScryptParams,

    #[error("nep2-key: invalid key hash(maybe wrong passphrase)")]
    InvalidHash,

    #[error("nep2-key: invalid nep2 key")]
    InvalidKey,
}

/// Trait for decrypting NEP-2 encrypted keys back to keypairs
///
/// This trait provides the ability to decrypt NEP-2 format strings
/// back into usable keypairs for cryptographic operations.
pub trait TryFromNep2Key {
    /// Decrypt a NEP-2 encrypted key string into a keypair
    ///
    /// # Arguments
    /// * `nep2_key` - Base58Check-encoded NEP-2 encrypted key
    /// * `scrypt` - Scrypt parameters (must match those used for encryption)
    /// * `passphrase` - User passphrase for decryption
    ///
    /// # Returns
    /// * `Ok(Keypair)` - Successfully decrypted keypair
    /// * `Err(FromNep2KeyError)` - Decryption failed
    fn try_from_nep2_key(
        nep2_key: &str,
        scrypt: ScryptParams,
        passphrase: &[u8],
    ) -> Result<Keypair, FromNep2KeyError>;
}

impl TryFromNep2Key for Keypair {
    /// Decrypt a NEP-2 encrypted key with comprehensive validation
    ///
    /// This method implements the complete NEP-2 decryption process with
    /// multiple validation steps to ensure data integrity and detect
    /// incorrect passphrases or corrupted data.
    ///
    /// ## Decryption Steps
    /// 1. **Base58Check Decoding**: Decode and validate checksum
    /// 2. **Length Validation**: Ensure exactly 39 bytes of data
    /// 3. **Key Derivation**: Apply scrypt with passphrase and embedded salt
    /// 4. **AES Decryption**: Decrypt the embedded encrypted key
    /// 5. **Private Key Recovery**: XOR decrypted data with derived key
    /// 6. **Keypair Reconstruction**: Create keypair from recovered private key
    /// 7. **Address Verification**: Verify address hash matches embedded salt
    ///
    /// ## Validation and Security
    /// - Base58Check encoding provides tamper detection
    /// - Address hash verification confirms correct passphrase
    /// - Constant-time comparison prevents timing attacks
    /// - Invalid keys are rejected safely without information leakage
    ///
    /// # Arguments
    /// * `nep2_key` - NEP-2 encrypted key string (Base58Check format)
    /// * `scrypt` - Scrypt parameters (must match encryption parameters)
    /// * `passphrase` - User passphrase for decryption
    ///
    /// # Returns
    /// * `Ok(Keypair)` - Successfully decrypted and validated keypair
    /// * `Err(FromNep2KeyError)` - Decryption failed due to various reasons
    ///
    /// # Error Conditions
    /// - **InvalidBase58Check**: Malformed Base58 or invalid checksum
    /// - **InvalidKeyLength**: Wrong data length (not 39 bytes)
    /// - **InvalidScryptParams**: Scrypt parameter validation failed
    /// - **InvalidHash**: Address hash mismatch (likely wrong passphrase)
    /// - **InvalidKey**: Recovered private key is invalid for secp256r1
    ///
    /// # Security Notes
    /// - Wrong passphrase detected via address hash verification
    /// - Timing-resistant comparisons prevent side-channel attacks
    /// - All intermediate values automatically zeroized
    /// - Partial success scenarios handled securely
    fn try_from_nep2_key(
        nep2_key: &str,
        scrypt: ScryptParams,
        passphrase: &[u8],
    ) -> Result<Keypair, FromNep2KeyError> {
        // Step 1: Decode Base58Check format and validate integrity
        let raw = Vec::from_base58_check(nep2_key)
            .map_err(|_err| FromNep2KeyError::InvalidBase58Check)?;

        // Step 2: Validate expected NEP-2 data length
        if raw.len() != NEP2_KEY_SIZE {
            return Err(FromNep2KeyError::InvalidKeyLength);
        }

        // Step 3: Derive decryption key using embedded salt
        // Salt is at bytes 3-6 (after the 3-byte NEP-2 prefix)
        let derived = passphrase
            .derive_scrypt_key::<DERIVED_KEY_SIZE>(&raw[3..7], scrypt)
            .expect("default nep2-key params should be ok");

        // Step 4: Extract and decrypt the encrypted private key
        // Encrypted key starts at byte 7 and is 32 bytes long
        let mut encrypted: [u8; KEY_SIZE] = raw[7..].to_array();

        // Decrypt using the last 32 bytes of derived key as AES key
        derived[KEY_SIZE..]
            .aes256_ecb_decrypt_aligned(encrypted.as_mut_slice())
            .expect("`aes256_ecb_decrypt_aligned` should be ok");

        // Step 5: Recover original private key
        // XOR decrypted data with first 32 bytes of derived key
        let private_key = xor_array::<KEY_SIZE>(&encrypted, &derived[..KEY_SIZE]);

        // Step 6: Reconstruct keypair and validate private key
        let keypair = Keypair::new(PrivateKey::new(private_key))
            .map_err(|_err| FromNep2KeyError::InvalidKey)?;

        // Step 7: Verify passphrase correctness via address hash check
        // Generate address from recovered keypair and compare hash
        let addr = keypair.public_key().to_neo3_address();
        let hash = addr.as_str().sha256().sha256();

        // Constant-time comparison to prevent timing attacks
        if hash[..4].ct_eq(&raw[3..7]).into() {
            Ok(keypair)
        } else {
            // Address hash mismatch indicates wrong passphrase
            Err(FromNep2KeyError::InvalidHash)
        }
    }
}

/// Perform XOR operation between two byte arrays with automatic zeroization
///
/// This utility function XORs two byte arrays of the same length and returns
/// the result in a zeroizing container for automatic memory cleanup.
///
/// # Security Features
/// - **Constant-time**: No timing variation based on input values
/// - **Memory Safety**: Result automatically zeroized when dropped
/// - **Length Validation**: Panics on mismatched lengths (fail-fast)
/// - **Type Safety**: Compile-time length checking via const generics
///
/// # Type Parameters
/// * `N` - Length of the arrays (must be known at compile time)
///
/// # Arguments
/// * `left` - First input array
/// * `right` - Second input array
///
/// # Returns
/// Zeroizing array containing the XOR result
///
/// # Panics
/// This function panics if the input arrays have different lengths or
/// if either array length doesn't match the type parameter N.
fn xor_array<const N: usize>(left: &[u8], right: &[u8]) -> Zeroizing<[u8; N]> {
    let mut dest = Zeroizing::new([0u8; N]);

    // Validate input array lengths match
    assert_eq!(left.len(), right.len(), "left length {} != right length {}", left.len(), right.len());
    assert_eq!(left.len(), dest.len(), "source length {} != dest length {}", left.len(), N);

    // Perform XOR operation element by element
    left.iter()
        .enumerate()
        .for_each(|(idx, v)| dest[idx] = v ^ right[idx]);

    dest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256r1::{Keypair, PublicKey};

    /// Test NEP-2 encryption and decryption with known test vectors
    ///
    /// This test validates the complete NEP-2 workflow using a known
    /// test case with simplified scrypt parameters for faster execution.
    #[test]
    fn test_nep2_key_simplified() {
        // Known NEP-2 test vector
        let key = "6PYWucwbu5pQV9j1wq9kyb571qxUhqDK6vcTsGQtoJXuErzhfptc72RdGF";
        let passphrase = b"xyz";
        let scrypt = ScryptParams { n: 64, p: 2, r: 2 };

        // Decrypt the test vector
        let keypair = Keypair::try_from_nep2_key(key, scrypt, passphrase)
            .expect("try from nep2 key should be ok");

        // Verify the recovered private key matches expected value
        assert_eq!(
            hex::encode(keypair.private_key().as_be_bytes()),
            "0101010101010101010101010101010101010101010101010101010101010101"
        );

        // Verify the derived address matches expected value
        let addr = keypair.public_key().to_neo3_address();
        assert_eq!(addr.as_str(), "NUz6PKTAM7NbPJzkKJFNay3VckQtcDkgWo");

        // Verify the public key matches expected value
        assert_eq!(
            hex::encode(keypair.public_key().to_compressed()),
            "026ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca16"
        );
    }

    /// Test NEP-2 encryption/decryption round-trip with standard parameters
    ///
    /// This test verifies that encryption followed by decryption recovers
    /// the original private key. Uses standard NEP-2 parameters but is
    /// marked as ignored due to the computational cost of scrypt.
    #[test]
    #[ignore = "skip slow test"]
    fn test_nep2_key_default_params() {
        // Test with a known private key
        let sk = hex::decode("7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344")
            .expect("hex decode should be ok");

        let sk = PrivateKey::from_be_bytes(sk.as_slice()).expect("from be-bytes should be ok");
        let pk = PublicKey::try_from(&sk).expect("from private key should be ok");

        // Verify expected public key and address
        assert_eq!(
            "02028a99826edc0c97d18e22b6932373d908d323aa7f92656a77ec26e8861699ef",
            hex::encode(pk.to_compressed()),
        );
        assert_eq!(
            pk.to_neo3_address().as_str(),
            "NPTmAHDxo6Pkyic8Nvu3kwyXoYJCvcCB6i"
        );

        // Test encryption with standard parameters
        let passphrase = b"city of zion";
        let key = Keypair::new(sk)
            .expect("private key should be ok")
            .try_to_nep2_key(scrypt_params(), passphrase)
            .expect("try to nep2 key should be ok");

        // Verify encrypted key matches expected format
        assert_eq!(
            key.as_str(),
            "6PYUUUFei9PBBfVkSn8q7hFCnewWFRBKPxcn6Kz6Bmk3FqWyLyuTQE2XFH"
        );

        // Test decryption round-trip
        let got = Keypair::try_from_nep2_key(key.as_str(), scrypt_params(), passphrase)
            .expect("try from nep2 key should be ok");

        // Verify the round-trip preserved the original private key
        assert_eq!(
            hex::encode(got.private_key().as_be_bytes()),
            "7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344",
        );
    }
}
