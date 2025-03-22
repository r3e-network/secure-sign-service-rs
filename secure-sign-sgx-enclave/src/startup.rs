// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use secure_sign_core::hmac::HmacSha256;
use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::neo::sign::{AccountDecrypting, Signer};
use secure_sign_core::random::EnvCryptRandom;
use secure_sign_core::secp256r1::{Keypair, KEY_SIZE};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::Zeroizing;

use crate::{ErrCode, STATE};

pub(crate) const SHARED_KEY_SIZE: usize = 32;

// const STATE_NOT_STARTED: u32 = 0;
// const STATE_STARTED: u32 = 1;
// const STATE_KEY_EXCHANGED: u32 = 2;
// const STATE_SIGNER_STARTED: u32 = 3;

static WALLET: &'static str = core::include_str!(core::env!("WALLET_PATH"));

pub(crate) fn secure_sign_sgx_startup() -> Result<(), ErrCode> {
    let wallet = serde_json::from_slice::<Nep6Wallet>(WALLET.as_bytes())
        .map_err(|_err| ErrCode::InvalidNep6Wallet)?;

    if unsafe { STATE.wallet.is_some() } {
        return Err(ErrCode::InvalidStartupState); // unexpected state
    }

    unsafe { STATE.wallet = Some(wallet) };
    Ok(())
}

pub(crate) fn secure_sign_sgx_diffie_hellman(
    blob_ephemeral_public_key: &[u8],
) -> Result<[u8; KEY_SIZE + 1], ErrCode> {
    let blob_public_key = p256::PublicKey::from_sec1_bytes(blob_ephemeral_public_key)
        .map_err(|_err| ErrCode::InvalidEphemeralPublicKey)?;

    if unsafe { STATE.wallet.is_none() } {
        return Err(ErrCode::InvalidStartupState);
    }

    if unsafe { STATE.shared_secret.is_some() } {
        return Err(ErrCode::AlreadyExchanged);
    }

    let alice_keypair = Keypair::gen_random(&mut EnvCryptRandom)
        .map_err(|_gen_keypair_err| ErrCode::GenKeypairError)?;

    let alice_private_key = alice_keypair.private_key();
    let alice_private_key = p256::SecretKey::from_slice(alice_private_key.as_be_bytes())
        .map_err(|_err| ErrCode::GenKeypairError)?;

    let shared_secret = p256::ecdh::diffie_hellman(
        alice_private_key.to_nonzero_scalar(),
        blob_public_key.as_affine(),
    );

    let salt: [u8; 0] = [];
    unsafe {
        STATE.shared_secret = Some(Zeroizing::new(
            salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice()),
        ));
    }

    Ok(alice_keypair.public_key().to_compressed())
}

pub(crate) fn secure_sign_sgx_start_signer(
    encrypted_wallet_passphrase: &[u8],
    nonce: &[u8],
) -> Result<(), ErrCode> {
    let shared_secret = unsafe { STATE.shared_secret.clone() };
    let Some(shared_secret) = shared_secret else {
        return Err(ErrCode::InvalidStartupState);
    };

    let key: Key<Aes256Gcm> = (*shared_secret).into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce);

    let wallet_passphrase = cipher
        .decrypt(&nonce, encrypted_wallet_passphrase)
        .map(|x| Zeroizing::new(x))
        .map_err(|_err| ErrCode::DecryptPassphraseError)?;

    let wallet = unsafe { STATE.wallet.as_ref() };
    let Some(wallet) = wallet else {
        return Err(ErrCode::InvalidStartupState);
    };

    let accounts = wallet
        .decrypt_accounts(wallet_passphrase.as_slice())
        .map_err(|_err| ErrCode::DecryptWalletError)?;

    if unsafe { STATE.signer.is_some() } {
        return Err(ErrCode::InvalidStartupState);
    }

    unsafe { STATE.signer = Some(Signer::new(accounts)) };
    Ok(())
}
