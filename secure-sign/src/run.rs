// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

#[allow(unused_imports)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::random::EnvCryptRandom;
use secure_sign_rpc::startpb::startup_service_server::StartupServiceServer;
use secure_sign_rpc::startup::DefaultStartupService;

use tokio::sync::oneshot;
use tonic::transport::Server;

use crate::startup::DefaultStartSigner;

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
    #[arg(long, help = "The vsock context identifier", default_value = "0")]
    pub cid: u32,
}

impl RunCmd {
    pub fn run(&self) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>> {
        let wallet: Nep6Wallet = {
            let content = std::fs::read_to_string(&self.wallet)?;
            serde_json::from_str(&content)?
        };

        #[cfg(feature = "vsock")]
        let startup = DefaultStartSigner::with_vsock(self.cid, self.port);

        #[cfg(not(feature = "vsock"))]
        let startup = DefaultStartSigner::with_tcp(self.port);

        let service = DefaultStartupService::new(wallet, EnvCryptRandom, startup);
        let (tx, rx) = oneshot::channel::<()>();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port + 1);
        log::info!("Starting startup server on {}", addr);

        tokio::spawn(async move {
            let r = Server::builder()
                .add_service(StartupServiceServer::new(service))
                .serve_with_shutdown(addr, async { rx.await.unwrap_or(()) })
                .await;
            if let Err(err) = r {
                log::error!("startup server error: {}", err);
            }
        });

        Ok(tx)
    }
}
