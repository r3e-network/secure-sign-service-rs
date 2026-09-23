// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

mod mock;
mod run;
mod startup;
mod tools;

use std::error::Error;

use clap::{Parser, Subcommand};
use tokio::signal;

#[derive(Subcommand)]
enum Commands {
    #[cfg(not(feature = "tools"))]
    Run(run::RunCmd),

    Mock(mock::MockCmd),
    Decrypt(tools::DecryptCmd),
    Status(tools::StatusCmd),
    RecipientAttestation(tools::RecipientAttestationCmd),
    StartRecipient(tools::StartRecipientCmd),
}

#[derive(Parser)]
#[command(author = "R3E Network Team")]
#[command(version)]
#[command(about = "Neo Signer RS secure signing service")]
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
        Commands::RecipientAttestation(attestation) => return attestation.run().await,
        Commands::StartRecipient(start) => return start.run().await,
    };

    signal::ctrl_c().await?;
    log::info!("Shutting down...");

    shutdown_tx
        .send(())
        .expect("Failed to send shutdown signal");
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    /// A signer must be told which network it signs for. `--network` used to
    /// default to mainnet magic, which made that choice silently.
    /// `mock` arguments other than `--network`. The vsock (Nitro) build also
    /// requires the enclave's context identifier, so it is supplied there and
    /// `--network` is the only argument these tests leave out.
    fn mock_args_without_network() -> Vec<&'static str> {
        let mut args = vec!["secure-sign", "mock", "--wallet", "wallet.json"];
        if cfg!(feature = "vsock") {
            args.extend(["--cid", "3"]);
        }
        args
    }

    #[test]
    fn mock_refuses_to_start_without_an_explicit_network() {
        let parsed = Cli::try_parse_from(mock_args_without_network());
        let err = match parsed {
            Ok(_) => panic!("mock parsed without --network; the network must be explicit"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(
            err.to_string().contains("--network"),
            "error should name the missing flag: {err}"
        );
    }

    #[test]
    fn mock_accepts_an_explicit_network() {
        let mut args = mock_args_without_network();
        args.extend(["--network", "860833102"]);
        let parsed = Cli::try_parse_from(args);
        assert!(
            parsed.is_ok(),
            "an explicit --network must parse: {:?}",
            parsed.err()
        );
    }

    #[cfg(not(feature = "tools"))]
    #[test]
    fn run_refuses_to_start_without_an_explicit_network() {
        let parsed = Cli::try_parse_from(["secure-sign", "run"]);
        let err = match parsed {
            Ok(_) => panic!("run parsed without --network; the network must be explicit"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(
            err.to_string().contains("--network"),
            "error should name the missing flag: {err}"
        );
    }
}
