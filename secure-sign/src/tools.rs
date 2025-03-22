// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;

use secure_sign_core::hmac::HmacSha256;
use secure_sign_core::random::EnvCryptRandom;
use secure_sign_core::secp256r1::Keypair;
use secure_sign_rpc::servicepb::secure_sign_client::SecureSignClient;
use secure_sign_rpc::servicepb::GetAccountStatusRequest;
use secure_sign_rpc::startpb::startup_service_client::StartupServiceClient;
use secure_sign_rpc::startpb::{DiffieHellmanRequest, StartSignerRequest};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use p256::ecdh;
use secure_sign_rpc::vsock;
use tonic::transport::{Channel, Endpoint};
use zeroize::Zeroizing;

#[derive(clap::Args)]
#[command(about = "Decrypt the wallet of the running secure-sign-service")]
pub struct DecryptCmd {
    #[arg(
        long,
        help = "The service-port(sgx, mock) or service-port + 1(nitro)",
        default_value = "9991"
    )]
    pub port: u16,

    #[arg(long, help = "The vsock cid(when use vsock)", default_value = "0")]
    pub cid: u32,
}

impl DecryptCmd {
    fn read_passphrase(&self) -> Result<Zeroizing<String>, Box<dyn Error>> {
        let passphrase = rpassword::prompt_password("The password of the wallet: ")
            .map_err(|err| format!("Failed to read passphrase: {}", err))?;
        Ok(Zeroizing::new(passphrase))
    }

    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let channel = if self.cid > 0 {
            vsock::vsock_channel(self.cid, self.port).await
        } else {
            tcp_channel(self.port).await
        }?;

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
                encrypted_wallet_passphrase: ciphertext.into(),
                nonce: nonce.as_slice().into(),
            })
            .await
            .map_err(|s| format!("Failed to start signer: {}:{}", s.code(), s.message()))?;

        log::info!("Signer starting...");
        Ok(())
    }
}

#[derive(clap::Args)]
#[command(about = "Get the status of the account")]
pub struct StatusCmd {
    #[arg(long, help = "The service-port", default_value = "9991")]
    pub port: u16,

    #[arg(long, help = "The vsock cid(when use vsock)", default_value = "0")]
    pub cid: u32,

    #[arg(long, help = "The hex-encoded public key")]
    pub public_key: String,
}

impl StatusCmd {
    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let public_key = hex::decode(&self.public_key)
            .map_err(|err| format!("Failed to decode public key: {}", err))?;

        let channel = if self.cid > 0 {
            vsock::vsock_channel(self.cid, self.port).await
        } else {
            tcp_channel(self.port).await
        }?;

        let mut client = SecureSignClient::new(channel);
        let res = client
            .get_account_status(GetAccountStatusRequest {
                public_key: public_key.into(),
            })
            .await
            .map_err(|s| format!("Failed to get account status: {}:{}", s.code(), s.message()))?;

        let status = account_status(res.get_ref().status);
        std::println!("Account {} status: {}", self.public_key, status);
        Ok(())
    }
}

async fn tcp_channel(port: u16) -> Result<Channel, Box<dyn Error>> {
    let endpoint = format!("http://localhost:{}", port);
    let conn = Endpoint::new(endpoint)?.connect().await?;
    Ok(conn)
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
