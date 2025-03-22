// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use secure_sign_core::neo::sign::{Account, Signer};
use secure_sign_rpc::servicepb::secure_sign_server::SecureSignServer;
use secure_sign_rpc::startup::StartSigner;
use secure_sign_rpc::DefaultSignService;

use tokio::sync::oneshot;
use tonic::transport::Server;

pub struct DefaultStartSigner {
    cid: u32, // 0 if tcp
    port: u16,
}

impl DefaultStartSigner {
    #[allow(unused)]
    pub fn with_vsock(cid: u32, port: u16) -> Self {
        Self { cid, port }
    }

    #[allow(unused)]
    pub fn with_tcp(port: u16) -> Self {
        Self { cid: 0, port }
    }
}

impl StartSigner for DefaultStartSigner {
    fn start(self, accounts: Vec<Account>) -> Result<oneshot::Sender<()>, Box<dyn Error>> {
        let sign_service = DefaultSignService::new(Signer::new(accounts));
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
