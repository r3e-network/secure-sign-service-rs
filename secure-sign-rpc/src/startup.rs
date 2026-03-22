// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;
use std::sync::{Arc, Mutex};

use secure_sign_core::hmac::HmacSha256;
use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::neo::sign::{Account, AccountDecrypting};
use secure_sign_core::random::CryptRandom;
use secure_sign_core::secp256r1::Keypair;

use crate::startpb::{startup_service_server::StartupService, *};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use p256::ecdh;
use tokio::sync::oneshot;
use tonic::async_trait;
use zeroize::Zeroizing;

const SHARED_KEY_SIZE: usize = 32;

/// Helper to lock the mutex, converting a poisoned lock into a gRPC internal error.
#[allow(clippy::result_large_err)]
fn lock_state<T>(
    state: &std::sync::Mutex<T>,
) -> Result<std::sync::MutexGuard<'_, T>, tonic::Status> {
    state
        .lock()
        .map_err(|_| tonic::Status::internal("internal state corrupted"))
}

pub trait StartSigner: Send + Sync + 'static {
    fn start(self, accounts: Vec<Account>) -> Result<oneshot::Sender<()>, Box<dyn Error>>;
}

pub trait RecipientProvider: Send + Sync + 'static {
    fn prepare_attestation_document(&mut self) -> Result<Vec<u8>, Box<dyn Error>>;

    fn decrypt_ciphertext_for_recipient(
        &mut self,
        ciphertext_for_recipient: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>>;
}

pub struct UnsupportedRecipientProvider;

impl RecipientProvider for UnsupportedRecipientProvider {
    fn prepare_attestation_document(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Recipient attestation is not supported in this mode",
        )
        .into())
    }

    fn decrypt_ciphertext_for_recipient(
        &mut self,
        _ciphertext_for_recipient: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Recipient decrypt is not supported in this mode",
        )
        .into())
    }
}

struct StartupState<Start, Random, Recipient> {
    wallet: Nep6Wallet,
    crypt_random: Random,
    shared_secret: Option<Zeroizing<[u8; SHARED_KEY_SIZE]>>,
    start: Option<Start>,
    recipient: Recipient,
    recipient_attestation_prepared: bool,
}

impl<Start: StartSigner, Random: CryptRandom + Send + Sync + 'static, Recipient: RecipientProvider>
    StartupState<Start, Random, Recipient>
{
    fn start(&mut self, accounts: Vec<Account>) -> Result<(), Box<dyn Error>> {
        let start = self.start.take().ok_or("Start signer not set")?;
        let sender = start.start(accounts)?;
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = sender.send(());
        });
        Ok(())
    }
}

pub struct DefaultStartupService<Start, Random, Recipient> {
    state: Arc<Mutex<StartupState<Start, Random, Recipient>>>,
}

impl<Start, Random, Recipient> DefaultStartupService<Start, Random, Recipient> {
    pub fn new(wallet: Nep6Wallet, crypt_random: Random, start: Start, recipient: Recipient) -> Self {
        Self {
            state: Arc::new(Mutex::new(StartupState {
                wallet,
                crypt_random,
                shared_secret: None,
                start: Some(start),
                recipient,
                recipient_attestation_prepared: false,
            })),
        }
    }
}

#[async_trait]
impl<
        Start: StartSigner,
        Random: CryptRandom + Send + Sync + 'static,
        Recipient: RecipientProvider,
    > StartupService for DefaultStartupService<Start, Random, Recipient>
{
    async fn diffie_hellman(
        &self,
        req: tonic::Request<DiffieHellmanRequest>,
    ) -> Result<tonic::Response<DiffieHellmanResponse>, tonic::Status> {
        let req = req.into_inner();
        let blob_public_key = req.blob_ephemeral_public_key.as_slice();
        let blob_public_key = p256::PublicKey::from_sec1_bytes(blob_public_key)
            .map_err(|_err| tonic::Status::invalid_argument("Invalid blob ephemeral public key"))?;

        let mut state = lock_state(&self.state)?;
        if state.shared_secret.is_some() {
            return Err(tonic::Status::already_exists("Key has been exchanged"));
        }

        let alice_keypair = Keypair::gen_random(&mut state.crypt_random).map_err(|err| {
            tonic::Status::internal(format!("Get ephemeral keypair error: {}", err))
        })?;

        let alice_private_key = alice_keypair.private_key();
        let alice_private_key = p256::SecretKey::from_slice(alice_private_key.as_be_bytes())
            .map_err(|_err| tonic::Status::internal("Invalid alice private key"))?;

        let shared_secret = ecdh::diffie_hellman(
            alice_private_key.to_nonzero_scalar(),
            blob_public_key.as_affine(),
        );
        let res = DiffieHellmanResponse {
            alice_ephemeral_public_key: alice_keypair.public_key().to_compressed().into(),
        };

        let salt: [u8; 0] = [];
        state.shared_secret = Some(Zeroizing::new(
            salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice()),
        ));
        Ok(tonic::Response::new(res))
    }

    async fn start_signer(
        &self,
        req: tonic::Request<StartSignerRequest>,
    ) -> Result<tonic::Response<StartSignerResponse>, tonic::Status> {
        let req = req.into_inner();
        if req.nonce.len() != 12 {
            return Err(tonic::Status::invalid_argument("Invalid nonce"));
        }

        let mut state = lock_state(&self.state)?;
        if state.start.is_none() {
            return Err(tonic::Status::failed_precondition("Start signer not set"));
        }

        let Some(shared_secret) = state.shared_secret.clone() else {
            return Err(tonic::Status::failed_precondition(
                "Key exchange not completed",
            ));
        };

        let key: Key<Aes256Gcm> = (*shared_secret).into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(req.nonce.as_ref());

        let wallet_passphrase = cipher
            .decrypt(nonce, req.encrypted_wallet_passphrase.as_slice())
            .map(Zeroizing::new)
            .map_err(|_err| tonic::Status::invalid_argument("Invalid encrypted data or nonce"))?;

        let accounts = state
            .wallet
            .decrypt_accounts(wallet_passphrase.as_slice())
            .map_err(|err| {
                tonic::Status::invalid_argument(format!("Invalid wallet or passphrase: {}", err))
            })?;

        let _ = state
            .start(accounts)
            .map_err(|err| tonic::Status::internal(format!("Start signer error: {}", err)))?;

        Ok(tonic::Response::new(StartSignerResponse {}))
    }

    async fn get_kms_recipient_attestation(
        &self,
        _req: tonic::Request<GetKmsRecipientAttestationRequest>,
    ) -> Result<tonic::Response<GetKmsRecipientAttestationResponse>, tonic::Status> {
        let mut state = lock_state(&self.state)?;

        if state.start.is_none() {
            return Err(tonic::Status::failed_precondition("Start signer not set"));
        }

        let attestation_document = state
            .recipient
            .prepare_attestation_document()
            .map_err(|err| {
                tonic::Status::internal(format!("Prepare recipient attestation error: {}", err))
            })?;

        state.recipient_attestation_prepared = true;

        Ok(tonic::Response::new(GetKmsRecipientAttestationResponse {
            attestation_document,
        }))
    }

    async fn start_signer_with_recipient_ciphertext(
        &self,
        req: tonic::Request<StartSignerWithRecipientCiphertextRequest>,
    ) -> Result<tonic::Response<StartSignerWithRecipientCiphertextResponse>, tonic::Status> {
        let req = req.into_inner();
        if req.ciphertext_for_recipient.is_empty() {
            return Err(tonic::Status::invalid_argument(
                "ciphertext_for_recipient is required",
            ));
        }

        let mut state = lock_state(&self.state)?;
        if state.start.is_none() {
            return Err(tonic::Status::failed_precondition("Start signer not set"));
        }

        if !state.recipient_attestation_prepared {
            return Err(tonic::Status::failed_precondition(
                "Recipient attestation not prepared",
            ));
        }

        let wallet_passphrase = state
            .recipient
            .decrypt_ciphertext_for_recipient(req.ciphertext_for_recipient.as_slice())
            .map_err(|err| {
                tonic::Status::invalid_argument(format!(
                    "Invalid recipient ciphertext or attestation session: {}",
                    err
                ))
            })?;

        let accounts = state
            .wallet
            .decrypt_accounts(wallet_passphrase.as_slice())
            .map_err(|err| {
                tonic::Status::invalid_argument(format!("Invalid wallet or passphrase: {}", err))
            })?;

        let _ = state
            .start(accounts)
            .map_err(|err| tonic::Status::internal(format!("Start signer error: {}", err)))?;

        state.recipient_attestation_prepared = false;

        Ok(tonic::Response::new(
            StartSignerWithRecipientCiphertextResponse {},
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sign_core::random::EnvCryptRandom;
    use secure_sign_core::scrypt::ScryptParams;

    struct MockStartSigner;

    impl StartSigner for MockStartSigner {
        fn start(self, _: Vec<Account>) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
            let (sender, _receiver) = oneshot::channel();
            Ok(sender)
        }
    }

    struct MockRecipientProvider {
        passphrase: Vec<u8>,
        prepared: bool,
    }

    impl RecipientProvider for MockRecipientProvider {
        fn prepare_attestation_document(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
            self.prepared = true;
            Ok(vec![0xAA, 0xBB, 0xCC])
        }

        fn decrypt_ciphertext_for_recipient(
            &mut self,
            _ciphertext_for_recipient: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
            if !self.prepared {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "attestation not prepared",
                )
                .into());
            }
            Ok(Zeroizing::new(self.passphrase.clone()))
        }
    }

    fn test_wallet() -> Nep6Wallet {
        let json = r#"{
            "name": "xyz",
            "version": "3.0",
            "scrypt": { "n": 64, "r": 2, "p": 2 },
            "accounts": [
                {
                    "address": "NUz6PKTAM7NbPJzkKJFNay3VckQtcDkgWo",
                    "label": null,
                    "isdefault": true,
                    "lock": false,
                    "key": "6PYWucwbu5pQV9j1wq9kyb571qxUhqDK6vcTsGQtoJXuErzhfptc72RdGF",
                    "contract": {
                        "script": "DCECb/A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhZBVuezJw==",
                        "deployed": false,
                        "parameters": [{"name": "signature", "type": "Signature"}]
                    }
                }
            ]
        }"#;
        serde_json::from_str::<Nep6Wallet>(json).expect("wallet parse should succeed")
    }

    #[tokio::test]
    async fn test_diffie_hellman() {
        let wallet = Nep6Wallet {
            name: Some("test".into()),
            version: "0".into(),
            scrypt: ScryptParams { n: 128, r: 1, p: 1 },
            accounts: vec![],
            extra: None,
        };
        let blob_keypair = Keypair::gen_random(&mut EnvCryptRandom)
            .expect("Generate random blob keypair should be OK");

        let blob_public_key = blob_keypair.public_key().to_compressed();
        let startup_service = DefaultStartupService::new(
            wallet,
            EnvCryptRandom,
            MockStartSigner,
            UnsupportedRecipientProvider,
        );
        let req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let res = startup_service
            .diffie_hellman(tonic::Request::new(req))
            .await
            .expect("Diffie-Hellman error");

        let alice_public_key = res.into_inner().alice_ephemeral_public_key;
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key.as_slice())
            .expect("Invalid alice public key");

        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .expect("Invalid blob private key");

        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        let salt: [u8; 0] = [];
        let shared_secret1 = salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice());

        let state = startup_service.state.lock().unwrap();
        let shared_secret2 = state.shared_secret.clone().unwrap();
        assert_eq!(shared_secret1, *shared_secret2);
    }

    #[tokio::test]
    async fn test_start_signer_with_recipient_ciphertext_requires_attestation() {
        let startup_service = DefaultStartupService::new(
            test_wallet(),
            EnvCryptRandom,
            MockStartSigner,
            MockRecipientProvider {
                passphrase: b"xyz".to_vec(),
                prepared: false,
            },
        );

        let req = StartSignerWithRecipientCiphertextRequest {
            ciphertext_for_recipient: vec![0x01],
        };
        let err = startup_service
            .start_signer_with_recipient_ciphertext(tonic::Request::new(req))
            .await
            .expect_err("must fail when attestation is not prepared");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("Recipient attestation not prepared"));
    }

    #[tokio::test]
    async fn test_start_signer_with_recipient_ciphertext_success() {
        let startup_service = DefaultStartupService::new(
            test_wallet(),
            EnvCryptRandom,
            MockStartSigner,
            MockRecipientProvider {
                passphrase: b"xyz".to_vec(),
                prepared: false,
            },
        );

        let att = startup_service
            .get_kms_recipient_attestation(tonic::Request::new(
                GetKmsRecipientAttestationRequest {},
            ))
            .await
            .expect("get attestation should succeed")
            .into_inner();
        assert!(!att.attestation_document.is_empty());

        startup_service
            .start_signer_with_recipient_ciphertext(tonic::Request::new(
                StartSignerWithRecipientCiphertextRequest {
                    ciphertext_for_recipient: vec![0x02, 0x03],
                },
            ))
            .await
            .expect("start signer should succeed");

        let err = startup_service
            .start_signer_with_recipient_ciphertext(tonic::Request::new(
                StartSignerWithRecipientCiphertextRequest {
                    ciphertext_for_recipient: vec![0x02, 0x03],
                },
            ))
            .await
            .expect_err("second start must fail");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("Start signer not set"));
    }
}
