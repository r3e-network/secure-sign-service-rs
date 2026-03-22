// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;

use hyper_util::rt::tokio::TokioIo;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tonic::transport::{Channel, Endpoint, Uri};

pub type VsockIncoming = tokio_vsock::Incoming;

#[inline]
pub fn vsock_incoming(cid: u32, port: u16) -> Result<VsockIncoming, std::io::Error> {
    let addr = VsockAddr::new(cid, port as u32);
    VsockListener::bind(addr).map(|listener| listener.incoming())
}

pub async fn vsock_channel(cid: u32, port: u16) -> Result<Channel, Box<dyn Error>> {
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
