// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use clap::{command, Parser, Subcommand};
use secure_sign_core::neo::sign::Signer;
use secure_sign_rpc::servicepb::secure_sign_server::SecureSignServer;
use secure_sign_rpc::unencrypted::*;
use secure_sign_rpc::SignServiceFacade;
use tonic::transport::Server;

#[derive(Subcommand)]
enum Commands {
    Run(RunCmd),
}

#[derive(clap::Args)]
pub(crate) struct RunCmd {
    #[arg(long, help = "The wallet file path")]
    pub wallet: String,

    #[arg(long, help = "The listen address", default_value = "0.0.0.0:9991")]
    pub listen: String,
}

#[derive(Parser)]
#[command(author = "R3E Network Team")]
#[command(version = "0.1.0")]
#[command(about = "A rust implementation for secure-sign-service")]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.commands {
        Commands::Run(run) => {
            // start grpc server
            let addr = run.listen.parse()?;
            let signer = Signer::new(vec![]);
            let unencrypted_sign_service = UnencryptedSignService::new(signer);
            let sign_service_facade = SignServiceFacade::new(unencrypted_sign_service);

            println!("Listening on {}", addr);
            Server::builder()
                .add_service(SecureSignServer::new(sign_service_facade))
                .serve(addr)
                .await?;
        }
    }
    Ok(())
}
