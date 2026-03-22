// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;

use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::neo::sign::AccountDecrypting;
use secure_sign_rpc::startup::StartSigner;

use tokio::sync::oneshot;

use crate::startup::DefaultStartSigner;

#[derive(clap::Args)]
#[command(about = "Run the mock secure-sign-service")]
pub(crate) struct MockCmd {
    #[arg(long, help = "The wallet file path")]
    pub wallet: String,

    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    #[cfg(feature = "vsock")]
    #[arg(long, help = "The vsock context identifier")]
    pub cid: u32,

    #[arg(
        long,
        help = "The passphrase of the wallet (reads from stdin if omitted)",
        default_value = None,
    )]
    pub passphrase: Option<String>,
}

impl MockCmd {
    fn read_passphrase(&self) -> Result<String, Box<dyn Error>> {
        match &self.passphrase {
            Some(p) => Ok(p.clone()),
            None => rpassword::prompt_password("The password of the wallet: ")
                .map_err(|err| format!("Failed to read passphrase: {}", err).into()),
        }
    }

    pub fn run(&self) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        let passphrase = self.read_passphrase()?;

        #[allow(unused)]
        let accounts = {
            let content = std::fs::read_to_string(&self.wallet)?;
            let wallet: Nep6Wallet = serde_json::from_str(&content)?;
            wallet.decrypt_accounts(passphrase.as_bytes())?
        };

        #[cfg(feature = "vsock")]
        return DefaultStartSigner::with_vsock(self.cid, self.port).start(accounts);

        #[cfg(not(feature = "vsock"))]
        return DefaultStartSigner::with_tcp(self.port).start(accounts);
    }
}
