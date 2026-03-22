// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;

use secure_sign_core::hmac::HmacSha256;
use secure_sign_core::random::EnvCryptRandom;
use secure_sign_core::secp256r1::Keypair;
use secure_sign_rpc::servicepb::secure_sign_client::SecureSignClient;
use secure_sign_rpc::servicepb::GetAccountStatusRequest;
use secure_sign_rpc::startpb::startup_service_client::StartupServiceClient;
use secure_sign_rpc::startpb::{
    DiffieHellmanRequest, GetKmsRecipientAttestationRequest, StartSignerRequest,
    StartSignerWithRecipientCiphertextRequest,
};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use p256::ecdh;
use secure_sign_rpc::vsock;
use tonic::transport::{Channel, Endpoint};
use zeroize::Zeroizing;

/// Shared connection arguments for CLI commands that connect to the service.
#[derive(clap::Args, Clone)]
pub struct ConnectionArgs {
    #[arg(long, help = "The service port", default_value = "9991")]
    pub port: u16,

    #[arg(long, help = "The vsock cid (when use vsock)", default_value = "0")]
    pub cid: u32,
}

impl ConnectionArgs {
    async fn connect(&self) -> Result<Channel, Box<dyn Error>> {
        if self.cid > 0 {
            vsock::vsock_channel(self.cid, self.port).await
        } else {
            let endpoint = format!("http://localhost:{}", self.port);
            let conn = Endpoint::new(endpoint)?.connect().await?;
            Ok(conn)
        }
    }
}

#[derive(clap::Args)]
#[command(about = "Decrypt the wallet of the running secure-sign-service")]
pub struct DecryptCmd {
    #[command(flatten)]
    pub conn: ConnectionArgs,
}

impl DecryptCmd {
    fn read_passphrase(&self) -> Result<Zeroizing<String>, Box<dyn Error>> {
        let passphrase = rpassword::prompt_password("The password of the wallet: ")
            .map_err(|err| format!("Failed to read passphrase: {}", err))?;
        Ok(Zeroizing::new(passphrase))
    }

    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let channel = self.conn.connect().await?;
        let mut client = StartupServiceClient::new(channel);

        let blob_keypair = Keypair::gen_random(&mut EnvCryptRandom)
            .map_err(|err| format!("Failed to get blob keypair: {}", err))?;
        let res = client
            .diffie_hellman(DiffieHellmanRequest {
                blob_ephemeral_public_key: blob_keypair.public_key().to_compressed().into(),
            })
            .await
            .map_err(|s| format!("Failed to diffie hellman: {}:{}", s.code(), s.message()))?;

        let alice_public_key = res.get_ref().alice_ephemeral_public_key.as_slice();
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key)
            .map_err(|_err| tonic::Status::invalid_argument("Invalid alice ephemeral keypair"))?;

        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .map_err(|_err| tonic::Status::internal("Invalid blob ephemeral keypair"))?;

        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        let salt: [u8; 0] = [];
        let aes_key = Zeroizing::new(salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice()));
        let aes_key: Key<Aes256Gcm> = (*aes_key).into();

        let cipher = Aes256Gcm::new(&aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        log::info!("Start to decrypt wallet...");
        let ciphertext = {
            let passphrase = self.read_passphrase()?;
            cipher
                .encrypt(&nonce, passphrase.as_bytes())
                .map_err(|err| format!("Failed to encrypt passphrase: {}", err))?
        };

        client
            .start_signer(StartSignerRequest {
                encrypted_wallet_passphrase: ciphertext,
                nonce: nonce.as_slice().into(),
            })
            .await
            .map_err(|s| format!("Failed to start signer: {}:{}", s.code(), s.message()))?;

        log::info!("Signer starting...");
        Ok(())
    }
}

#[derive(clap::Args)]
#[command(about = "Get KMS recipient attestation document for Nitro auto-unlock")]
pub struct RecipientAttestationCmd {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    #[arg(
        long,
        help = "Output path for raw attestation document, or '-' to print base64",
        default_value = "-"
    )]
    pub output: String,
}

impl RecipientAttestationCmd {
    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let channel = self.conn.connect().await?;
        let mut client = StartupServiceClient::new(channel);
        let res = client
            .get_kms_recipient_attestation(GetKmsRecipientAttestationRequest {})
            .await
            .map_err(|s| {
                format!(
                    "Failed to get recipient attestation: {}:{}",
                    s.code(),
                    s.message()
                )
            })?;

        let document = res.into_inner().attestation_document;
        if self.output == "-" {
            std::println!("{}", BASE64.encode(document));
        } else {
            std::fs::write(&self.output, document)?;
            std::println!("Wrote recipient attestation document to {}", self.output);
        }

        Ok(())
    }
}

#[derive(clap::Args)]
#[command(about = "Start signer using KMS CiphertextForRecipient (base64)")]
pub struct StartRecipientCmd {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    #[arg(long, help = "Base64-encoded KMS CiphertextForRecipient")]
    pub ciphertext_base64: String,
}

impl StartRecipientCmd {
    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let ciphertext_for_recipient = BASE64
            .decode(self.ciphertext_base64.as_bytes())
            .map_err(|err| format!("Invalid base64 ciphertext_for_recipient: {}", err))?;

        let channel = self.conn.connect().await?;
        let mut client = StartupServiceClient::new(channel);
        client
            .start_signer_with_recipient_ciphertext(StartSignerWithRecipientCiphertextRequest {
                ciphertext_for_recipient,
            })
            .await
            .map_err(|s| {
                format!(
                    "Failed to start signer with recipient ciphertext: {}:{}",
                    s.code(),
                    s.message()
                )
            })?;

        log::info!("Signer starting via recipient ciphertext...");
        Ok(())
    }
}

#[derive(clap::Args)]
#[command(about = "Get the status of the account")]
pub struct StatusCmd {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    #[arg(long, help = "The hex-encoded public key")]
    pub public_key: String,
}

impl StatusCmd {
    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let public_key = hex::decode(&self.public_key)
            .map_err(|err| format!("Failed to decode public key: {}", err))?;

        let channel = self.conn.connect().await?;
        let mut client = SecureSignClient::new(channel);
        let res = client
            .get_account_status(GetAccountStatusRequest { public_key })
            .await
            .map_err(|s| format!("Failed to get account status: {}:{}", s.code(), s.message()))?;

        let status = account_status(res.get_ref().status);
        std::println!("Account {} status: {}", self.public_key, status);
        Ok(())
    }
}

fn account_status(status: i32) -> String {
    match status {
        0 => "NoSuchAccount".into(),
        1 => "NoPrivateKey".into(),
        2 => "Single".into(),
        3 => "Multiple".into(),
        4 => "Locked".into(),
        _ => format!("AccountStatus({})", status),
    }
}
