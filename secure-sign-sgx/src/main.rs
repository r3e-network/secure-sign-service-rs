// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

mod ffi;

pub mod enclave;
pub mod service;
pub mod sign;
pub mod startup;

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::enclave::SgxEnclave;
use crate::service::SgxSignService;

use secure_sign_rpc::servicepb::secure_sign_server::SecureSignServer;
use secure_sign_rpc::startpb::startup_service_server::StartupServiceServer;

use clap::{command, Parser, Subcommand};
use tokio::signal;
use tokio::sync::oneshot;
use tonic::transport::Server;

#[derive(clap::Args)]
#[command(about = "Run the secure-sign-service")]
pub struct RunCmd {
    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    #[arg(
        long,
        help = "The enclave file path",
        default_value = "secure_sign_sgx_enclave.signed.so"
    )]
    pub enclave: String,

    #[arg(long, help = "Whether to run in debug mode", default_value = "false")]
    pub debug: bool,
}

impl RunCmd {
    pub fn run(&self) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        let enclave = SgxEnclave::new(self.enclave.clone(), None, self.debug)
            .map_err(|err| format!("Failed to create enclave: {}", err))?;

        let service = Arc::new(SgxSignService::new(enclave));
        let (tx, rx) = oneshot::channel::<()>();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
        log::info!("Starting startup server on {}", addr);

        tokio::spawn(async move {
            let r = Server::builder()
                .accept_http1(true)
                .add_service(StartupServiceServer::from_arc(service.clone()))
                .add_service(SecureSignServer::from_arc(service))
                .serve_with_shutdown(addr, async { rx.await.unwrap_or(()) })
                .await;
            if let Err(err) = r {
                log::error!("startup server error: {}", err);
            }
        });

        Ok(tx)
    }
}

#[derive(Subcommand)]
enum Commands {
    Run(RunCmd),
}

#[derive(Parser)]
#[command(author = "R3E Network Team")]
#[command(version = "0.1.0")]
#[command(about = "A rust implementation for secure-sign-service based on sgx")]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let cli = Cli::parse();
    let shutdown_tx = match cli.commands {
        Commands::Run(run) => run.run()?,
    };

    signal::ctrl_c().await?;
    log::info!("Shutting down...");

    shutdown_tx
        .send(())
        .expect("Failed to send shutdown signal");
    Ok(())
}
