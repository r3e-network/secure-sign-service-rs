// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use sgx_types::*;

extern "C" {
    pub fn secure_sign_sgx_startup(eid: sgx_enclave_id_t, retval: *mut i32) -> sgx_status_t;

    pub fn secure_sign_sgx_diffie_hellman(
        eid: sgx_enclave_id_t,
        retval: *mut i32, // less than 0 means error, 0 means success
        blob_ephemeral_public_key: *const u8,
        blob_ephemeral_public_key_len: usize,
        alice_ephemeral_public_key: *mut u8,
    ) -> sgx_status_t;

    pub fn secure_sign_sgx_start_signer(
        eid: sgx_enclave_id_t,
        retval: *mut i32, // less than 0 means error, 0 means success
        encrypted_wallet_passphrase: *const u8,
        encrypted_wallet_passphrase_len: usize,
        nonce: *const u8,
        nonce_len: usize,
    ) -> sgx_status_t;

    pub fn secure_sign_sgx_account_status(
        eid: sgx_enclave_id_t,
        retval: *mut i32, // less than 0 means error, 0 means the status of the account.
        public_key: *const u8,
        public_key_len: usize,
    ) -> sgx_status_t;

    pub fn secure_sign_sgx_sign_block(
        eid: sgx_enclave_id_t,
        retval: *mut i32, // less than 0 means error, 0 means success
        public_key: *const u8,
        public_key_len: usize,
        trimmed_block: *const u8, // protobuf encoded TrimmedBlock
        trimmed_block_len: usize, // length of protobuf encoded TrimmedBlock
        network: u32,
        sign: *mut u8, // signature is 64 bytes, so sign buffer should be at least 64 bytes
        sign_len: usize, // length of sign buffer
    ) -> sgx_status_t;

    pub fn secure_sign_sgx_sign_extensible_payload(
        eid: sgx_enclave_id_t,
        retval: *mut i32, // less than 0 means error, greater than 0 means the length of protobuf encoded `multi_signs`
        extensible_payload: *const u8, // protobuf encoded ExtensiblePayload
        extensible_payload_len: usize, // length of protobuf encoded ExtensiblePayload
        script_hashes: *const u8, // script hash in little endian
        script_hashes_len: usize, // length of script hash
        network: u32,
        multi_signs: *mut u8,   // protobuf encoded MultiAccountSigns
        multi_signs_len: usize, // length of protobuf encoded MultiAccountSigns
    ) -> sgx_status_t;
}
