// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

mod mock;
mod run;
mod startup;
mod tools;

use std::error::Error;

use clap::{command, Parser, Subcommand};
use tokio::signal;

#[derive(Subcommand)]
enum Commands {
    #[cfg(not(feature = "tools"))]
    Run(run::RunCmd),

    Mock(mock::MockCmd),
    Decrypt(tools::DecryptCmd),
    Status(tools::StatusCmd),
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
async fn main() -> Result<(), Box<dyn Error>> {
    // logger cannot be initialized in enclave
    env_logger::try_init()?;

    let cli = Cli::parse();
    let shutdown_tx = match cli.commands {
        #[cfg(not(feature = "tools"))]
        Commands::Run(run) => run.run()?,

        Commands::Mock(mock) => mock.run()?,
        Commands::Decrypt(decrypt) => return decrypt.run().await,
        Commands::Status(status) => return status.run().await,
    };

    signal::ctrl_c().await?;
    log::info!("Shutting down...");

    shutdown_tx
        .send(())
        .expect("Failed to send shutdown signal");
    Ok(())
}
