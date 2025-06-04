# API Examples

This document provides practical examples of using the Secure Sign Service API in various programming languages.

## 🚀 Getting Started

### Prerequisites
- Secure Sign Service running on port 9991
- Wallet decrypted and ready for signing
- gRPC client library for your language

### Service Endpoints
```
TCP:   localhost:9991  (default)
VSOCK: CID:PORT        (TEE environments)
```

## 📖 Basic Examples

### 1. Account Status Check

#### Rust
```rust
use tonic::Request;
use secure_sign_rpc::startup_service_client::StartupServiceClient;
use secure_sign_rpc::GetAccountStatusRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StartupServiceClient::connect("http://127.0.0.1:9991").await?;
    
    let request = Request::new(GetAccountStatusRequest {
        public_key: "03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
    });
    
    let response = client.get_account_status(request).await?;
    let status = response.into_inner();
    
    println!("Account status: {:?}", status);
    println!("Public key: {}", status.public_key);
    println!("NEO address: {}", status.neo_address);
    
    Ok(())
}
```

#### Python
```python
import grpc
import asyncio
from secure_sign_rpc import startup_service_pb2_grpc, startup_service_pb2

async def get_account_status():
    async with grpc.aio.insecure_channel('127.0.0.1:9991') as channel:
        stub = startup_service_pb2_grpc.StartupServiceStub(channel)
        
        request = startup_service_pb2.GetAccountStatusRequest(
            public_key="03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        )
        
        response = await stub.GetAccountStatus(request)
        
        print(f"Account status:")
        print(f"  Public key: {response.public_key}")
        print(f"  NEO address: {response.neo_address}")
        print(f"  Ready for signing: {response.ready}")

if __name__ == "__main__":
    asyncio.run(get_account_status())
```

#### Go
```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "path/to/secure_sign_rpc"
)

func main() {
    conn, err := grpc.Dial("127.0.0.1:9991", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := pb.NewStartupServiceClient(conn)
    
    req := &pb.GetAccountStatusRequest{
        PublicKey: "03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
    }
    
    resp, err := client.GetAccountStatus(context.Background(), req)
    if err != nil {
        log.Fatalf("GetAccountStatus failed: %v", err)
    }
    
    fmt.Printf("Account status:\n")
    fmt.Printf("  Public key: %s\n", resp.PublicKey)
    fmt.Printf("  NEO address: %s\n", resp.NeoAddress)
    fmt.Printf("  Ready: %t\n", resp.Ready)
}
```

#### JavaScript/Node.js
```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const PROTO_PATH = './secure_sign_rpc.proto';

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
});

const secureSignProto = grpc.loadPackageDefinition(packageDefinition);

async function getAccountStatus() {
    const client = new secureSignProto.StartupService('127.0.0.1:9991', grpc.credentials.createInsecure());
    
    const request = {
        public_key: '03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890'
    };
    
    return new Promise((resolve, reject) => {
        client.GetAccountStatus(request, (error, response) => {
            if (error) {
                reject(error);
            } else {
                console.log('Account status:');
                console.log(`  Public key: ${response.public_key}`);
                console.log(`  NEO address: ${response.neo_address}`);
                console.log(`  Ready: ${response.ready}`);
                resolve(response);
            }
        });
    });
}

getAccountStatus().catch(console.error);
```

### 2. Wallet Decryption

#### Rust
```rust
use tonic::Request;
use secure_sign_rpc::startup_service_client::StartupServiceClient;
use secure_sign_rpc::{DiffieHellmanRequest, StartSignerRequest};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StartupServiceClient::connect("http://127.0.0.1:9991").await?;
    
    // Step 1: Initiate Diffie-Hellman key exchange
    let dh_request = Request::new(DiffieHellmanRequest {
        public_key: vec![/* client public key bytes */],
    });
    
    let dh_response = client.diffie_hellman(dh_request).await?;
    let server_public_key = dh_response.into_inner().public_key;
    
    // Step 2: Derive shared secret and encrypt passphrase
    // (Implementation depends on your crypto library)
    
    // Step 3: Send encrypted passphrase
    print!("Enter wallet passphrase: ");
    io::stdout().flush().unwrap();
    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase).unwrap();
    let passphrase = passphrase.trim();
    
    // Encrypt passphrase with shared secret
    let encrypted_passphrase = encrypt_passphrase(passphrase, &shared_secret)?;
    
    let start_request = Request::new(StartSignerRequest {
        encrypted_passphrase,
    });
    
    let start_response = client.start_signer(start_request).await?;
    
    if start_response.into_inner().success {
        println!("✅ Wallet decrypted successfully!");
    } else {
        println!("❌ Failed to decrypt wallet");
    }
    
    Ok(())
}
```

#### Python
```python
import grpc
import asyncio
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secure_sign_rpc import startup_service_pb2_grpc, startup_service_pb2

async def decrypt_wallet():
    async with grpc.aio.insecure_channel('127.0.0.1:9991') as channel:
        stub = startup_service_pb2_grpc.StartupServiceStub(channel)
        
        # Step 1: Diffie-Hellman key exchange
        # (Generate client key pair first)
        client_private_key, client_public_key = generate_key_pair()
        
        dh_request = startup_service_pb2.DiffieHellmanRequest(
            public_key=client_public_key
        )
        
        dh_response = await stub.DiffieHellman(dh_request)
        server_public_key = dh_response.public_key
        
        # Step 2: Derive shared secret
        shared_secret = derive_shared_secret(client_private_key, server_public_key)
        
        # Step 3: Encrypt passphrase
        passphrase = getpass.getpass("Enter wallet passphrase: ")
        encrypted_passphrase = encrypt_passphrase(passphrase, shared_secret)
        
        start_request = startup_service_pb2.StartSignerRequest(
            encrypted_passphrase=encrypted_passphrase
        )
        
        start_response = await stub.StartSigner(start_request)
        
        if start_response.success:
            print("✅ Wallet decrypted successfully!")
        else:
            print("❌ Failed to decrypt wallet")

def encrypt_passphrase(passphrase: str, shared_secret: bytes) -> bytes:
    # Derive encryption key from shared secret
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure-sign-passphrase',
    )
    key = kdf.derive(shared_secret)
    
    # Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, passphrase.encode(), None)
    
    return nonce + ciphertext

if __name__ == "__main__":
    asyncio.run(decrypt_wallet())
```

### 3. Signing Operations

#### Rust - Sign Extensible Payload
```rust
use tonic::Request;
use secure_sign_rpc::secure_sign_client::SecureSignClient;
use secure_sign_rpc::SignExtensiblePayloadRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SecureSignClient::connect("http://127.0.0.1:9991").await?;
    
    let request = Request::new(SignExtensiblePayloadRequest {
        public_key: "03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
        payload: vec![/* your payload bytes */],
        magic: 0x334f454e, // NEO N3 mainnet magic
    });
    
    let response = client.sign_extensible_payload(request).await?;
    let signature = response.into_inner();
    
    println!("Signature: {}", hex::encode(signature.signature));
    println!("Invocation script: {}", hex::encode(signature.invocation_script));
    
    Ok(())
}
```

#### Python - Sign Block Header
```python
import grpc
import asyncio
from secure_sign_rpc import secure_sign_pb2_grpc, secure_sign_pb2

async def sign_block():
    async with grpc.aio.insecure_channel('127.0.0.1:9991') as channel:
        stub = secure_sign_pb2_grpc.SecureSignStub(channel)
        
        # Block header data (example)
        block_data = bytes([
            # Version (4 bytes)
            0x00, 0x00, 0x00, 0x00,
            # Previous block hash (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            # Merkle root (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            # Timestamp (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            # Nonce (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        
        request = secure_sign_pb2.SignBlockRequest(
            public_key="03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
            unsigned_data=block_data,
            magic=0x334f454e  # NEO N3 mainnet
        )
        
        response = await stub.SignBlock(request)
        
        print(f"Block signed successfully!")
        print(f"Signature: {response.signature.hex()}")
        print(f"Invocation script: {response.invocation_script.hex()}")

if __name__ == "__main__":
    asyncio.run(sign_block())
```

## 🔧 Advanced Examples

### 1. Batch Signing
```rust
use tonic::Request;
use secure_sign_rpc::secure_sign_client::SecureSignClient;
use secure_sign_rpc::SignExtensiblePayloadRequest;
use futures::future::try_join_all;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SecureSignClient::connect("http://127.0.0.1:9991").await?;
    
    let payloads = vec![
        vec![0x01, 0x02, 0x03],
        vec![0x04, 0x05, 0x06],
        vec![0x07, 0x08, 0x09],
    ];
    
    let public_key = "03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890";
    let magic = 0x334f454e;
    
    // Create futures for all signing operations
    let signing_futures = payloads.into_iter().map(|payload| {
        let mut client_clone = client.clone();
        let public_key = public_key.to_string();
        
        async move {
            let request = Request::new(SignExtensiblePayloadRequest {
                public_key,
                payload,
                magic,
            });
            
            client_clone.sign_extensible_payload(request).await
        }
    });
    
    // Execute all signing operations concurrently
    let results = try_join_all(signing_futures).await?;
    
    for (i, result) in results.into_iter().enumerate() {
        let signature = result.into_inner();
        println!("Payload {}: {}", i, hex::encode(signature.signature));
    }
    
    Ok(())
}
```

### 2. Connection Retry Logic
```python
import grpc
import asyncio
import logging
from grpc import aio
from secure_sign_rpc import startup_service_pb2_grpc, startup_service_pb2

class SecureSignClient:
    def __init__(self, address: str, max_retries: int = 3):
        self.address = address
        self.max_retries = max_retries
        self.channel = None
        self.stub = None
    
    async def connect(self):
        self.channel = aio.insecure_channel(self.address)
        self.stub = startup_service_pb2_grpc.StartupServiceStub(self.channel)
    
    async def disconnect(self):
        if self.channel:
            await self.channel.close()
    
    async def get_account_status_with_retry(self, public_key: str):
        for attempt in range(self.max_retries):
            try:
                request = startup_service_pb2.GetAccountStatusRequest(
                    public_key=public_key
                )
                response = await self.stub.GetAccountStatus(request)
                return response
            
            except grpc.aio.AioRpcError as e:
                if attempt == self.max_retries - 1:
                    raise
                
                logging.warning(f"Attempt {attempt + 1} failed: {e.code()}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        raise Exception("All retry attempts failed")

async def main():
    client = SecureSignClient('127.0.0.1:9991')
    
    try:
        await client.connect()
        
        response = await client.get_account_status_with_retry(
            "03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        )
        
        print(f"Account status: {response}")
        
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. VSOCK Client (for TEE environments)
```rust
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use std::task::{Context, Poll};

// Custom VSOCK connector
pub struct VsockConnector {
    cid: u32,
    port: u32,
}

impl VsockConnector {
    pub fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }
    
    pub async fn connect(&self) -> Result<Channel, Box<dyn std::error::Error>> {
        let uri = Uri::from_static("http://[::]:0"); // Dummy URI
        
        let channel = Endpoint::from(uri)
            .connect_with_connector(service_fn(move |_| async move {
                // Create VSOCK connection
                let stream = vsock::VsockStream::connect(self.cid, self.port)?;
                Ok::<_, std::io::Error>(stream)
            }))
            .await?;
        
        Ok(channel)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connector = VsockConnector::new(3, 9991); // CID 3, Port 9991
    let channel = connector.connect().await?;
    
    let mut client = StartupServiceClient::new(channel);
    
    let request = Request::new(GetAccountStatusRequest {
        public_key: "03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
    });
    
    let response = client.get_account_status(request).await?;
    println!("VSOCK response: {:?}", response.into_inner());
    
    Ok(())
}
```

## 🧪 Testing Examples

### 1. Unit Test with Mock Service
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};
    
    struct MockStartupService;
    
    #[tonic::async_trait]
    impl StartupService for MockStartupService {
        async fn get_account_status(
            &self,
            request: Request<GetAccountStatusRequest>,
        ) -> Result<Response<GetAccountStatusResponse>, Status> {
            let req = request.into_inner();
            
            let response = GetAccountStatusResponse {
                public_key: req.public_key,
                neo_address: "NTest123456789".to_string(),
                ready: true,
            };
            
            Ok(Response::new(response))
        }
        
        // Implement other required methods...
    }
    
    #[tokio::test]
    async fn test_account_status() -> Result<(), Box<dyn std::error::Error>> {
        // Start mock server
        let addr = "127.0.0.1:19991".parse()?;
        let service = MockStartupService;
        
        let server = Server::builder()
            .add_service(StartupServiceServer::new(service))
            .serve(addr);
        
        tokio::spawn(server);
        
        // Test client
        let mut client = StartupServiceClient::connect("http://127.0.0.1:19991").await?;
        
        let request = Request::new(GetAccountStatusRequest {
            public_key: "test_key".to_string(),
        });
        
        let response = client.get_account_status(request).await?;
        let status = response.into_inner();
        
        assert_eq!(status.public_key, "test_key");
        assert_eq!(status.neo_address, "NTest123456789");
        assert!(status.ready);
        
        Ok(())
    }
}
```

### 2. Integration Test Script
```bash
#!/bin/bash
# Integration test script

set -euo pipefail

echo "🧪 Starting integration tests..."

# Start service in background
./target/secure-sign-tcp mock --wallet secure-sign/config/nep6_wallet.json --passphrase "test123" --port 19991 &
SERVICE_PID=$!

# Wait for service to start
sleep 2

# Test account status
echo "Testing account status..."
python3 -c "
import grpc
import sys
sys.path.append('.')
from secure_sign_rpc import startup_service_pb2_grpc, startup_service_pb2

channel = grpc.insecure_channel('127.0.0.1:19991')
stub = startup_service_pb2_grpc.StartupServiceStub(channel)

request = startup_service_pb2.GetAccountStatusRequest(
    public_key='03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890'
)

response = stub.GetAccountStatus(request)
print(f'✅ Account status test passed: {response.ready}')
"

# Test signing
echo "Testing signing operation..."
python3 -c "
import grpc
import sys
sys.path.append('.')
from secure_sign_rpc import secure_sign_pb2_grpc, secure_sign_pb2

channel = grpc.insecure_channel('127.0.0.1:19991')
stub = secure_sign_pb2_grpc.SecureSignStub(channel)

request = secure_sign_pb2.SignExtensiblePayloadRequest(
    public_key='03a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890',
    payload=b'test payload',
    magic=0x334f454e
)

response = stub.SignExtensiblePayload(request)
print(f'✅ Signing test passed: {len(response.signature)} bytes')
"

# Cleanup
kill $SERVICE_PID
wait $SERVICE_PID 2>/dev/null || true

echo "✅ All integration tests passed!"
```

## 📚 Best Practices

### 1. Error Handling
```rust
use tonic::Status;

async fn handle_grpc_errors() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SecureSignClient::connect("http://127.0.0.1:9991").await?;
    
    let request = Request::new(SignExtensiblePayloadRequest {
        public_key: "invalid_key".to_string(),
        payload: vec![],
        magic: 0,
    });
    
    match client.sign_extensible_payload(request).await {
        Ok(response) => {
            println!("Success: {:?}", response.into_inner());
        }
        Err(status) => {
            match status.code() {
                tonic::Code::InvalidArgument => {
                    eprintln!("Invalid request parameters: {}", status.message());
                }
                tonic::Code::PermissionDenied => {
                    eprintln!("Wallet not decrypted or invalid key: {}", status.message());
                }
                tonic::Code::Unavailable => {
                    eprintln!("Service unavailable: {}", status.message());
                }
                _ => {
                    eprintln!("Unexpected error: {}", status);
                }
            }
        }
    }
    
    Ok(())
}
```

### 2. Connection Management
```python
import grpc
from contextlib import asynccontextmanager

@asynccontextmanager
async def secure_sign_client(address: str):
    """Context manager for secure sign client with proper cleanup"""
    channel = grpc.aio.insecure_channel(address)
    try:
        startup_stub = startup_service_pb2_grpc.StartupServiceStub(channel)
        sign_stub = secure_sign_pb2_grpc.SecureSignStub(channel)
        yield startup_stub, sign_stub
    finally:
        await channel.close()

# Usage
async def main():
    async with secure_sign_client('127.0.0.1:9991') as (startup, sign):
        # Use the clients
        status = await startup.GetAccountStatus(request)
        signature = await sign.SignExtensiblePayload(request)
```

### 3. Configuration Management
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientConfig {
    pub service_address: String,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub vsock_cid: Option<u32>,
    pub vsock_port: Option<u32>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            service_address: "http://127.0.0.1:9991".to_string(),
            timeout_seconds: 30,
            max_retries: 3,
            vsock_cid: None,
            vsock_port: None,
        }
    }
}

impl ClientConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }
    
    pub fn is_vsock(&self) -> bool {
        self.vsock_cid.is_some() && self.vsock_port.is_some()
    }
}
```

---

## 🔗 Additional Resources

- [API Reference](api.md) - Complete API documentation
- [Architecture](architecture.md) - System design details
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Security Policy](../SECURITY.md) - Security practices and reporting 