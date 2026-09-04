// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;
#[cfg(feature = "vsock")]
use std::fs::OpenOptions;
#[cfg(feature = "vsock")]
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(feature = "vsock")]
use std::os::unix::fs::OpenOptionsExt;
use std::string::String;

use secure_sign_core::neo::sign::{Account, Signer};
use secure_sign_rpc::servicepb::secure_sign_server::SecureSignServer;
#[cfg(feature = "vsock")]
use secure_sign_rpc::startup::RecipientProvider;
use secure_sign_rpc::startup::StartSigner;
use secure_sign_rpc::DefaultSignService;

use tokio::sync::oneshot;
use tonic::transport::Server;

#[cfg(feature = "vsock")]
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
#[cfg(feature = "vsock")]
use rsa::RsaPrivateKey;
#[cfg(feature = "vsock")]
use secure_sign_nitro::Nsm;
#[cfg(feature = "vsock")]
use std::process::Command;
#[cfg(feature = "vsock")]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "vsock")]
use zeroize::Zeroizing;

pub struct DefaultStartSigner {
    cid: u32, // 0 if tcp
    port: u16,
    consensus_network: Option<u32>,
    enable_sign_transaction: bool,
    gas_sweep_destination: Option<String>,
    gas_sweep_destination_script_hash: Option<String>,
}

impl DefaultStartSigner {
    #[allow(unused)]
    pub fn with_vsock(cid: u32, port: u16) -> Self {
        Self {
            cid,
            port,
            consensus_network: None,
            enable_sign_transaction: false,
            gas_sweep_destination: None,
            gas_sweep_destination_script_hash: None,
        }
    }

    #[cfg(feature = "vsock")]
    pub fn with_vsock_consensus(cid: u32, port: u16, network: u32) -> Self {
        Self {
            cid,
            port,
            consensus_network: Some(network),
            enable_sign_transaction: false,
            gas_sweep_destination: None,
            gas_sweep_destination_script_hash: None,
        }
    }

    #[cfg(feature = "vsock")]
    pub fn with_gas_sweep_deploy_config(
        mut self,
        enable_sign_transaction: bool,
        gas_sweep_destination: Option<String>,
        gas_sweep_destination_script_hash: Option<String>,
    ) -> Self {
        self.enable_sign_transaction = enable_sign_transaction;
        self.gas_sweep_destination = gas_sweep_destination;
        self.gas_sweep_destination_script_hash = gas_sweep_destination_script_hash;
        self
    }

    #[allow(unused)]
    pub fn with_tcp(port: u16) -> Self {
        Self {
            cid: 0,
            port,
            consensus_network: None,
            enable_sign_transaction: false,
            gas_sweep_destination: None,
            gas_sweep_destination_script_hash: None,
        }
    }
}

impl StartSigner for DefaultStartSigner {
    fn start(self, accounts: Vec<Account>) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        if accounts.is_empty() {
            return Err("no accounts available to start signer".into());
        }
        let source_public_key = accounts[0].keypair.public_key().to_compressed().to_vec();
        let enable = self.enable_sign_transaction;
        let dest = self.gas_sweep_destination.clone();
        let dest_hash = self.gas_sweep_destination_script_hash.clone();
        let network_for_policy = self
            .consensus_network
            .unwrap_or(secure_sign_core::neo::consensus::NEO_N3_MAINNET_MAGIC);
        let gas_sweep_policy = secure_sign_core::neo::gas_sweep_policy::build_deploy_policy(
            network_for_policy,
            enable,
            source_public_key,
            dest.as_deref(),
            dest_hash.as_deref(),
        )
        .map_err(|err| format!("gas sweep deploy config: {err}"))?;

        let signer = Signer::new(accounts);
        let sign_service = match self.consensus_network {
            Some(network) => DefaultSignService::new_consensus(signer, network),
            None => DefaultSignService::new(signer),
        }
        .with_gas_sweep_policy(gas_sweep_policy);
        let router = Server::builder()
            .accept_http1(true)
            .add_service(SecureSignServer::new(sign_service));

        let (tx, rx) = oneshot::channel::<()>();
        if self.cid > 0 {
            let incoming = secure_sign_rpc::vsock::vsock_incoming(self.cid, self.port)?;
            log::info!("Starting vsock server on {}:{}", self.cid, self.port);
            tokio::spawn(async move {
                let r = router
                    .serve_with_incoming_shutdown(incoming, async { rx.await.unwrap_or(()) })
                    .await;
                if let Err(err) = r {
                    log::error!("vsock server error: {}", err);
                }
            });
        } else {
            let ip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
            log::info!("Starting tcp server on {}", ip_addr);
            tokio::spawn(async move {
                let r = router
                    .serve_with_shutdown(ip_addr, async { rx.await.unwrap_or(()) })
                    .await;
                if let Err(err) = r {
                    log::error!("tcp server error: {}", err);
                }
            });
        }

        Ok(tx)
    }
}

#[cfg(feature = "vsock")]
pub struct NitroRecipientProvider {
    private_key: Option<RsaPrivateKey>,
}

#[cfg(feature = "vsock")]
impl NitroRecipientProvider {
    pub fn new() -> Self {
        Self { private_key: None }
    }

    fn create_private_file(path: &str, contents: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(())
    }

    fn decrypt_cfr_with_openssl(
        private_key: &RsaPrivateKey,
        cfr: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| std::io::Error::other(format!("time error: {}", err)))?
            .as_nanos();
        let unique = format!("{}-{nonce}", std::process::id());
        let key_path = format!("/tmp/secure-sign-recipient-key-{unique}.der");
        let cfr_path = format!("/tmp/secure-sign-recipient-cfr-{unique}.der");
        let out_path = format!("/tmp/secure-sign-recipient-out-{unique}.bin");

        // RAII guard: ensures all temporary files are removed on any exit path.
        struct TempFileGuard<'a> {
            paths: &'a [&'a str],
        }
        impl Drop for TempFileGuard<'_> {
            fn drop(&mut self) {
                for path in self.paths {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let _guard = TempFileGuard {
            paths: &[key_path.as_str(), cfr_path.as_str(), out_path.as_str()],
        };

        let key_der = private_key
            .to_pkcs8_der()
            .map_err(|err| std::io::Error::other(format!("Encode private key failed: {}", err)))?;

        Self::create_private_file(&key_path, key_der.as_bytes())?;
        Self::create_private_file(&cfr_path, cfr)?;
        Self::create_private_file(&out_path, &[])?;

        let output = Command::new("openssl")
            .args([
                "cms",
                "-decrypt",
                "-inform",
                "DER",
                "-in",
                cfr_path.as_str(),
                "-inkey",
                key_path.as_str(),
                "-keyform",
                "DER",
                "-out",
                out_path.as_str(),
            ])
            .output()
            .map_err(|err| std::io::Error::other(format!("openssl exec failed: {}", err)))?;

        if output.status.success() {
            return std::fs::read(&out_path).map_err(Into::into);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "openssl CMS decrypt failed (status: {}, stderr: {:?}), ciphertext length: {}",
                output.status,
                stderr,
                cfr.len(),
            ),
        )
        .into())
    }
}

#[cfg(feature = "vsock")]
impl RecipientProvider for NitroRecipientProvider {
    fn prepare_attestation_document(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut nsm = Nsm::new().map_err(|err| std::io::Error::other(err.to_string()))?;

        let private_key = RsaPrivateKey::new(&mut nsm, 2048)
            .map_err(|err| std::io::Error::other(format!("Generate RSA key failed: {}", err)))?;

        let public_key_der = private_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|err| {
                std::io::Error::other(format!("Encode recipient public key failed: {}", err))
            })?;

        let attestation_document = nsm
            .get_attestation_with_public_key(public_key_der.as_ref())
            .map_err(|err| {
                std::io::Error::other(format!("Get attestation document failed: {}", err))
            })?;

        self.private_key = Some(private_key);

        Ok(attestation_document)
    }

    fn decrypt_ciphertext_for_recipient(
        &mut self,
        ciphertext_for_recipient: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        let Some(private_key) = self.private_key.take() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "recipient attestation session is not prepared",
            )
            .into());
        };

        let wallet_passphrase =
            Self::decrypt_cfr_with_openssl(&private_key, ciphertext_for_recipient)?;

        Ok(Zeroizing::new(wallet_passphrase))
    }
}
