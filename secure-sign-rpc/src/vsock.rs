// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper_util::rt::tokio::TokioIo;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tonic::transport::{Channel, Endpoint, Uri};

pub type VsockIncoming = tokio_vsock::Incoming;

#[inline]
pub fn vsock_incoming(cid: u32, port: u16) -> Result<VsockIncoming, std::io::Error> {
    let addr = VsockAddr::new(cid, port as u32);
    VsockListener::bind(addr).map(|listener| listener.incoming())
}

pub struct VsockConnector {
    cid: u32,
    port: u16,
}

impl VsockConnector {
    pub fn new(cid: u32, port: u16) -> Self {
        Self { cid, port }
    }
}

impl tower::Service<Uri> for VsockConnector {
    type Response = VsockStream;

    type Error = std::io::Error;

    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let addr = VsockAddr::new(self.cid, self.port as u32);
        Box::pin(async move { VsockStream::connect(addr).await })
    }
}

pub async fn vsock_channel(cid: u32, port: u16) -> Result<Channel, Box<dyn std::error::Error>> {
    let endpoint = Endpoint::try_from(format!("http://127.0.0.1:{}/{}", port, cid))?; // Just a placeholder
    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_uri: Uri| {
            let addr = VsockAddr::new(cid, port as u32);
            async move {
                let stream = VsockStream::connect(addr).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;

    Ok(channel)
}
