// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Secure Sign Service - Main Application Entry Point
//!
//! This is the primary command-line interface for the Secure Sign Service.
//! The application provides four main commands:
//!
//! - **run**: Production service with encrypted wallet decryption
//! - **mock**: Development service with plain-text passphrase
//! - **decrypt**: Client tool to securely provide wallet passphrase
//! - **status**: Client tool to query account status
//!
//! ## Two-Phase Operation
//!
//! The service implements a two-phase security model:
//! 1. **Startup Phase**: Wallet decryption via secure ECDH + AES protocol
//! 2. **Signing Phase**: Cryptographic operations with protected keys

mod mock;
mod run;
mod startup;
mod tools;

use clap::{command, Parser, Subcommand};
use tokio::signal;

/// Available CLI commands for the Secure Sign Service
///
/// Each command provides different functionality:
/// - Service commands (run, mock) start the gRPC server
/// - Client commands (decrypt, status) connect to running services
#[derive(Subcommand)]
enum Commands {
    /// Start production service (requires separate wallet decryption)
    Run(run::RunCmd),
    /// Start development service (passphrase provided directly)
    Mock(mock::MockCmd),
    /// Connect to service and provide wallet decryption passphrase
    Decrypt(tools::DecryptCmd),
    /// Query account status from running service
    Status(tools::StatusCmd),
}

/// Command-line interface definition
///
/// Uses clap for robust argument parsing with automatic help generation
/// and validation. All commands support --help for detailed usage.
#[derive(Parser)]
#[command(author = "R3E Network Team")]
#[command(version = "0.1.0")]
#[command(about = "A rust implementation for secure-sign-service")]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

/// Application entry point with async runtime and signal handling
///
/// The main function coordinates:
/// 1. Logging initialization for observability
/// 2. Command parsing and execution
/// 3. Graceful shutdown handling via SIGINT
///
/// ## Service Commands vs Client Commands
///
/// - **Service commands** (run, mock) return a shutdown sender and await SIGINT
/// - **Client commands** (decrypt, status) execute and return immediately
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with environment-based configuration
    // Set RUST_LOG environment variable to control logging levels
    env_logger::init();

    // Parse command-line arguments
    let cli = Cli::parse();

    // Execute the appropriate command
    // Service commands return a shutdown channel, client commands execute directly
    let shutdown_tx = match cli.commands {
        Commands::Run(run) => run.run()?,
        Commands::Mock(mock) => mock.run()?,
        // Client commands execute and return immediately
        Commands::Decrypt(decrypt) => return decrypt.run().await,
        Commands::Status(status) => return status.run().await,
    };

    // For service commands: wait for SIGINT (Ctrl+C) for graceful shutdown
    signal::ctrl_c().await?;
    log::info!("Shutting down...");

    // Send shutdown signal to the running service
    // This triggers graceful shutdown of the gRPC server and cleanup of resources
    shutdown_tx
        .send(())
        .expect("Failed to send shutdown signal");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Test CLI command parsing functionality
    ///
    /// Verifies that clap correctly parses all command variants and their arguments.
    #[test]
    fn test_cli_command_parsing() {
        // Test run command parsing
        let args = vec![
            "secure-sign",
            "run",
            "--wallet",
            "test-wallet.json",
            "--port",
            "9991",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Run command should parse successfully");

        if let Ok(cli) = cli {
            match cli.commands {
                Commands::Run(_) => {} // Expected
                _ => panic!("Should parse as Run command"),
            }
        }

        // Test mock command parsing
        let args = vec![
            "secure-sign",
            "mock",
            "--wallet",
            "test-wallet.json",
            "--port",
            "9992",
            "--passphrase",
            "test123",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Mock command should parse successfully");

        if let Ok(cli) = cli {
            match cli.commands {
                Commands::Mock(_) => {} // Expected
                _ => panic!("Should parse as Mock command"),
            }
        }

        // Test decrypt command parsing
        let args = vec!["secure-sign", "decrypt", "--port", "9991"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Decrypt command should parse successfully");

        if let Ok(cli) = cli {
            match cli.commands {
                Commands::Decrypt(_) => {} // Expected
                _ => panic!("Should parse as Decrypt command"),
            }
        }

        // Test status command parsing
        let args = vec![
            "secure-sign",
            "status",
            "--port",
            "9991",
            "--public-key",
            "03a1b2c3",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Status command should parse successfully");

        if let Ok(cli) = cli {
            match cli.commands {
                Commands::Status(_) => {} // Expected
                _ => panic!("Should parse as Status command"),
            }
        }
    }

    /// Test CLI argument validation
    ///
    /// Verifies that invalid arguments are properly rejected.
    #[test]
    fn test_cli_argument_validation() {
        // Test missing required arguments
        let args = vec!["secure-sign", "status"]; // Missing --public-key
        let cli = Cli::try_parse_from(args);
        assert!(
            cli.is_err(),
            "Should fail when required arguments are missing"
        );

        // Test port number outside valid u16 range
        let args = vec![
            "secure-sign",
            "run",
            "--wallet",
            "test.json",
            "--port",
            "99999",
        ];
        let cli = Cli::try_parse_from(args);
        // clap will validate u16 range - 99999 is outside u16::MAX (65535)
        assert!(cli.is_err(), "Should reject port numbers outside u16 range");

        // Test empty values
        let args = vec![
            "secure-sign",
            "status",
            "--public-key",
            "",
            "--port",
            "9991",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(
            cli.is_ok(),
            "Should parse with empty public key (will fail at runtime)"
        );
    }

    /// Test CLI help generation
    ///
    /// Verifies that help text is generated correctly for all commands.
    #[test]
    fn test_cli_help_generation() {
        // Test main help
        let args = vec!["secure-sign", "--help"];
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "Help should cause parse failure (normal behavior)"
        );

        // Test subcommand help
        let args = vec!["secure-sign", "run", "--help"];
        let result = Cli::try_parse_from(args);
        assert!(
            result.is_err(),
            "Subcommand help should cause parse failure (normal behavior)"
        );
    }

    /// Test CLI default values
    ///
    /// Verifies that default values are applied correctly when arguments are omitted.
    #[test]
    fn test_cli_default_values() {
        // Test decrypt command with defaults
        let args = vec!["secure-sign", "decrypt"];
        let cli = Cli::try_parse_from(args).expect("Should parse with defaults");

        if let Commands::Decrypt(decrypt_cmd) = cli.commands {
            assert_eq!(decrypt_cmd.port, 9991, "Should use default port");
            assert_eq!(decrypt_cmd.cid, 0, "Should use default CID");
        } else {
            panic!("Should parse as Decrypt command");
        }

        // Test status command defaults
        let args = vec!["secure-sign", "status", "--public-key", "test"];
        let cli = Cli::try_parse_from(args).expect("Should parse with defaults");

        if let Commands::Status(status_cmd) = cli.commands {
            assert_eq!(status_cmd.port, 9991, "Should use default port");
            assert_eq!(status_cmd.cid, 0, "Should use default CID");
            assert_eq!(
                status_cmd.public_key, "test",
                "Should preserve provided public key"
            );
        } else {
            panic!("Should parse as Status command");
        }
    }

    /// Test command type detection
    ///
    /// Verifies that the correct command variant is matched.
    #[test]
    fn test_command_type_detection() {
        let test_cases = vec![
            (vec!["secure-sign", "run", "--wallet", "test.json"], "run"),
            (
                vec![
                    "secure-sign",
                    "mock",
                    "--wallet",
                    "test.json",
                    "--passphrase",
                    "pass",
                ],
                "mock",
            ),
            (vec!["secure-sign", "decrypt"], "decrypt"),
            (
                vec!["secure-sign", "status", "--public-key", "abc123"],
                "status",
            ),
        ];

        for (args, expected_type) in test_cases {
            let cli = Cli::try_parse_from(args).expect("Should parse successfully");

            let actual_type = match cli.commands {
                Commands::Run(_) => "run",
                Commands::Mock(_) => "mock",
                Commands::Decrypt(_) => "decrypt",
                Commands::Status(_) => "status",
            };

            assert_eq!(
                actual_type, expected_type,
                "Should detect correct command type"
            );
        }
    }

    /// Test CLI metadata
    ///
    /// Verifies that CLI metadata (version, author, description) is set correctly.
    #[test]
    fn test_cli_metadata() {
        use clap::CommandFactory;

        let cmd = Cli::command();

        // Test version
        assert!(cmd.get_version().is_some(), "Should have version set");
        assert_eq!(
            cmd.get_version().unwrap(),
            "0.1.0",
            "Should have correct version"
        );

        // Test author
        assert!(cmd.get_author().is_some(), "Should have author set");
        assert!(
            cmd.get_author().unwrap().contains("R3E Network Team"),
            "Should have correct author"
        );

        // Test description
        assert!(cmd.get_about().is_some(), "Should have description set");
        let about_text = cmd.get_about().unwrap().to_string();
        assert!(
            about_text.contains("secure-sign-service"),
            "Should mention service name"
        );
    }

    /// Test command validation edge cases
    ///
    /// Tests various edge cases and boundary conditions for command arguments.
    #[test]
    fn test_command_validation_edge_cases() {
        // Test minimum port number
        let args = vec!["secure-sign", "run", "--wallet", "test.json", "--port", "1"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Should accept minimum port number");

        // Test maximum valid port number
        let args = vec![
            "secure-sign",
            "run",
            "--wallet",
            "test.json",
            "--port",
            "65535",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Should accept maximum port number");

        // Test VSOCK CID values
        let args = vec!["secure-sign", "decrypt", "--cid", "0"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Should accept CID 0 (TCP mode)");

        let args = vec!["secure-sign", "decrypt", "--cid", "4294967295"]; // Max u32
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Should accept maximum CID value");

        // Test long public keys
        let long_public_key = "a".repeat(130); // Uncompressed public key length
        let args = vec!["secure-sign", "status", "--public-key", &long_public_key];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Should accept long public keys");
    }

    /// Test CLI subcommand isolation
    ///
    /// Verifies that arguments are properly isolated between subcommands.
    #[test]
    fn test_subcommand_isolation() {
        // Verify that wallet argument only applies to run/mock commands
        let args = vec!["secure-sign", "decrypt", "--wallet", "should-not-work.json"];
        let cli = Cli::try_parse_from(args);
        assert!(
            cli.is_err(),
            "Decrypt command should not accept wallet argument"
        );

        // Verify that passphrase argument only applies to mock command
        let args = vec!["secure-sign", "run", "--passphrase", "should-not-work"];
        let cli = Cli::try_parse_from(args);
        assert!(
            cli.is_err(),
            "Run command should not accept passphrase argument"
        );

        // Verify that public-key argument only applies to status command
        let args = vec!["secure-sign", "decrypt", "--public-key", "should-not-work"];
        let cli = Cli::try_parse_from(args);
        assert!(
            cli.is_err(),
            "Decrypt command should not accept public-key argument"
        );
    }
}
