// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;

#[allow(unused_imports)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(feature = "vsock")]
use secure_sign_core::neo::consensus::NEO_N3_MAINNET_MAGIC;
use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::random::EnvCryptRandom;
use secure_sign_rpc::startpb::startup_service_server::StartupServiceServer;
use secure_sign_rpc::startup::DefaultStartupService;
#[cfg(not(feature = "vsock"))]
use secure_sign_rpc::startup::UnsupportedRecipientProvider;

use tokio::sync::oneshot;
use tonic::transport::Server;

use crate::startup::DefaultStartSigner;
#[cfg(feature = "vsock")]
use crate::startup::NitroRecipientProvider;

#[cfg(all(feature = "vsock", feature = "tcp"))]
compile_error!("vsock and tcp cannot be both enabled");

#[derive(clap::Args)]
#[command(about = "Run the secure-sign-service")]
pub(crate) struct RunCmd {
    #[arg(long, help = "The wallet file path")]
    pub wallet: String,

    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    #[cfg(feature = "vsock")]
    #[arg(
        long,
        help = "The vsock context identifier(must greater than 1024)",
        default_value = "2345"
    )]
    pub cid: u32,

    #[cfg(feature = "vsock")]
    #[arg(
        long,
        help = "The only Neo network magic this consensus signer may sign",
        default_value_t = NEO_N3_MAINNET_MAGIC
    )]
    pub network: u32,

    /// Master switch for allowlisted SignTransaction (default OFF).
    #[arg(long, default_value_t = false, env = "ENABLE_SIGN_TRANSACTION")]
    pub enable_sign_transaction: bool,

    /// Deploy-time allowlisted GAS sweep destination address (never hardcode in git).
    #[arg(long, env = "GAS_SWEEP_DESTINATION_ADDRESS")]
    pub gas_sweep_destination: Option<String>,

    /// Deploy-time allowlisted destination script hash (LE hex).
    #[arg(long, env = "GAS_SWEEP_DESTINATION_SCRIPT_HASH")]
    pub gas_sweep_destination_script_hash: Option<String>,
}

impl RunCmd {
    pub fn run(&self) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        let wallet: Nep6Wallet = {
            let content = std::fs::read_to_string(&self.wallet)?;
            serde_json::from_str(&content)?
        };

        #[cfg(feature = "vsock")]
        return self.run_vsock(wallet);

        #[cfg(not(feature = "vsock"))]
        return self.run_tcp(wallet);
    }

    #[cfg(feature = "vsock")]
    fn run_vsock(&self, wallet: Nep6Wallet) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        let startup = DefaultStartSigner::with_vsock_consensus(self.cid, self.port, self.network)
            .with_gas_sweep_deploy_config(
                self.enable_sign_transaction,
                self.gas_sweep_destination.clone(),
                self.gas_sweep_destination_script_hash.clone(),
            );
        let service = DefaultStartupService::new(
            wallet,
            EnvCryptRandom,
            startup,
            NitroRecipientProvider::new(),
        );
        let (tx, rx) = oneshot::channel::<()>();

        let incoming = secure_sign_rpc::vsock::vsock_incoming(self.cid, self.port + 1)
            .map_err(|err| format!("Failed to create vsock incoming: {}", err))?;
        tokio::spawn(async move {
            let r = Server::builder()
                .accept_http1(true)
                .add_service(StartupServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async { rx.await.unwrap_or(()) })
                .await;
            if let Err(err) = r {
                log::error!("vsock server error: {}", err);
            }
        });

        Ok(tx)
    }

    #[cfg(not(feature = "vsock"))]
    fn run_tcp(&self, wallet: Nep6Wallet) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        let startup = DefaultStartSigner::with_tcp(self.port);
        let service = DefaultStartupService::new(
            wallet,
            EnvCryptRandom,
            startup,
            UnsupportedRecipientProvider,
        );
        let (tx, rx) = oneshot::channel::<()>();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port + 1);
        tokio::spawn(async move {
            let r = Server::builder()
                .accept_http1(true)
                .add_service(StartupServiceServer::new(service))
                .serve_with_shutdown(addr, async { rx.await.unwrap_or(()) })
                .await;
            if let Err(err) = r {
                log::error!("tcp server error: {}", err);
            }
        });

        Ok(tx)
    }
}
