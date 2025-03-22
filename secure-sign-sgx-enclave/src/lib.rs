// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

#![no_std]
#![allow(static_mut_refs)]

mod startup;

use core::slice;

use secure_sign_core::bytes::ToArray;
use secure_sign_core::h160::{H160, H160_SIZE};
use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::neo::sign::*;
use secure_sign_core::neo::signpb::*;
use secure_sign_core::secp256r1::KEY_SIZE;

use prost::Message;
use zeroize::Zeroizing;

// This is not thread safe on startup. But it's don't matter after startup.
static mut STATE: EnclaveState = EnclaveState {
    // state: AtomicU32::new(0),
    wallet: None,
    shared_secret: None,
    signer: None,
};

struct EnclaveState {
    // state: AtomicU32,
    wallet: Option<Nep6Wallet>,
    shared_secret: Option<Zeroizing<[u8; startup::SHARED_KEY_SIZE]>>,
    signer: Option<Signer>,
}

#[repr(i32)]
pub enum ErrCode {
    InvalidNep6Wallet = -1,
    InvalidEphemeralPublicKey = -2,
    InvalidStartupState = -3,
    InvalidScriptHashes = -4,
    InvalidPublicKey = -5,
    InvalidTrimmedBlock = -6,
    InvalidExtensiblePayload = -7,
    AlreadyExchanged = -8,
    GenKeypairError = -9,
    DecryptPassphraseError = -10,
    DecryptWalletError = -11,
    NoSuchAccount = -12,
    AccountLocked = -13,
    EcdsaSignError = -14,
    BufferTooSmall = -15,
    MultiSignsTooLarge = -16,
}

#[no_mangle]
pub extern "C" fn secure_sign_sgx_startup() -> i32 {
    // let nep6_wallet = unsafe { slice::from_raw_parts(nep6_wallet, nep6_wallet_len) };
    match startup::secure_sign_sgx_startup(/* nep6_wallet */) {
        Ok(()) => 0,
        Err(r) => r as i32,
    }
}

#[no_mangle]
pub extern "C" fn secure_sign_sgx_diffie_hellman(
    blob_ephemeral_public_key: *const u8,
    blob_ephemeral_public_key_len: usize,
    alice_ephemeral_public_key: *mut u8, // at least 33 bytes
) -> i32 {
    let blob_public_key =
        unsafe { slice::from_raw_parts(blob_ephemeral_public_key, blob_ephemeral_public_key_len) };

    let alice_public_key = match startup::secure_sign_sgx_diffie_hellman(blob_public_key) {
        Ok(alice_public_key) => alice_public_key,
        Err(r) => return r as i32,
    };

    unsafe {
        slice::from_raw_parts_mut(alice_ephemeral_public_key, KEY_SIZE + 1)
            .copy_from_slice(alice_public_key.as_slice());
    }
    0
}

#[no_mangle]
pub extern "C" fn secure_sign_sgx_start_signer(
    encrypted_wallet_passphrase: *const u8,
    encrypted_wallet_passphrase_len: usize,
    nonce: *const u8,
    nonce_len: usize,
) -> i32 {
    let encrypted_wallet_passphrase = unsafe {
        slice::from_raw_parts(encrypted_wallet_passphrase, encrypted_wallet_passphrase_len)
    };
    let nonce = unsafe { slice::from_raw_parts(nonce, nonce_len) };

    match startup::secure_sign_sgx_start_signer(encrypted_wallet_passphrase, nonce) {
        Ok(()) => 0,
        Err(err) => err as i32,
    }
}

#[no_mangle]
pub extern "C" fn secure_sign_sgx_account_status(
    public_key: *const u8,
    public_key_len: usize,
) -> i32 {
    let public_key = unsafe { slice::from_raw_parts(public_key, public_key_len) };

    let signer = unsafe { STATE.signer.as_ref() };
    let Some(signer) = signer else {
        return ErrCode::InvalidStartupState as i32;
    };

    match signer.get_account_status(public_key) {
        Ok(status) => status as i32,
        Err(GetAccountStatusError::InvalidPublicKey(_)) => ErrCode::InvalidPublicKey as i32,
    }
}

#[no_mangle]
pub extern "C" fn secure_sign_sgx_sign_block(
    public_key: *const u8,
    public_key_len: usize,
    trimmed_block: *const u8,
    trimmed_block_len: usize,
    network: u32,
    sign: *mut u8, // signature is 64 bytes, so sign buffer should be at least 64 bytes
) -> i32 {
    let public_key = unsafe { slice::from_raw_parts(public_key, public_key_len) };
    let trimmed_block = unsafe { slice::from_raw_parts(trimmed_block, trimmed_block_len) };

    let Ok(trimmed_block) = TrimmedBlock::decode(trimmed_block) else {
        return ErrCode::InvalidTrimmedBlock as i32;
    };

    let signer = unsafe { STATE.signer.as_ref() };
    let Some(signer) = signer else {
        return ErrCode::InvalidStartupState as i32;
    };

    let r = match signer.sign_block(public_key, &trimmed_block, network) {
        Ok(r) => r,
        Err(err) => return sign_err_code(err),
    };

    unsafe { slice::from_raw_parts_mut(sign, r.len()).copy_from_slice(r.as_slice()) };
    0
}

#[no_mangle]
pub extern "C" fn secure_sign_sgx_sign_extensible_payload(
    extensible_payload: *const u8,
    extensible_payload_len: usize,
    script_hashes: *const u8, // scipt hash in little endian
    script_hashes_len: usize, // script_hashes_len must be a multiple of H160_SIZE, and in (H160_SIZE, 128 * H160_SIZE]
    network: u32,
    multi_signs: *mut u8,   // multi_signs is protobuf encoded MultiAccountSigns
    multi_signs_len: usize, // must large enough to store encode multi_signs
) -> i32 {
    let extensible_payload =
        unsafe { slice::from_raw_parts(extensible_payload, extensible_payload_len) };
    let script_hashes = unsafe { slice::from_raw_parts(script_hashes, script_hashes_len) };
    let multi_signs = unsafe { slice::from_raw_parts_mut(multi_signs, multi_signs_len) };

    let Ok(extensible_payload) = ExtensiblePayload::decode(extensible_payload) else {
        return ErrCode::InvalidExtensiblePayload as i32;
    };

    if script_hashes.len() == 0
        || script_hashes.len() % H160_SIZE != 0
        || script_hashes.len() > 128 * H160_SIZE
    {
        return ErrCode::InvalidScriptHashes as i32;
    }

    let signer = unsafe { STATE.signer.as_ref() };
    let Some(signer) = signer else {
        return ErrCode::InvalidStartupState as i32;
    };

    let script_hashes = script_hashes
        .chunks(H160_SIZE)
        .map(|chunk| H160::from_le_bytes(chunk.to_array()))
        .collect();
    let signs = match signer.sign_extensible_payload(&extensible_payload, script_hashes, network) {
        Ok(r) => r,
        Err(err) => return sign_err_code(err),
    };

    let encoded_signs = signs.encode_to_vec();
    if encoded_signs.len() > multi_signs_len {
        return ErrCode::BufferTooSmall as i32;
    }

    if encoded_signs.len() > i32::MAX as usize {
        // this is a sanity check, should not happen
        return ErrCode::MultiSignsTooLarge as i32;
    }

    multi_signs[..encoded_signs.len()].copy_from_slice(encoded_signs.as_slice());
    encoded_signs.len() as i32
}

fn sign_err_code(err: SignError) -> i32 {
    match err {
        SignError::InvalidPublicKey(_) => ErrCode::InvalidPublicKey as i32,
        SignError::NoSuchAccount => ErrCode::NoSuchAccount as i32,
        SignError::AccountLocked => ErrCode::AccountLocked as i32,
        SignError::EcdsaSignError(_) => ErrCode::EcdsaSignError as i32,
        SignError::InvalidBlock(_) => ErrCode::InvalidTrimmedBlock as i32,
        SignError::InvalidExtensiblePayload(_) => ErrCode::InvalidExtensiblePayload as i32,
    }
}
