# API Reference

## Overview

The Secure Sign Service provides a gRPC-based API for cryptographic signing operations, specifically designed for NEO blockchain integration. The service operates in two phases: a startup phase for secure wallet decryption and a signing phase for cryptographic operations.

## Service Definition

### StartupService (Phase 1: Wallet Decryption)

The startup service handles secure wallet decryption:

```protobuf
service StartupService {
    rpc DiffieHellman(DiffieHellmanRequest) returns (DiffieHellmanResponse);
    rpc StartSigner(StartSignerRequest) returns (StartSignerResponse);
}
```

### SecureSign Service (Phase 2: Signing Operations)

The main signing service provides three core operations:

```protobuf
service SecureSign {
    rpc SignExtensiblePayload(SignExtensiblePayloadRequest) returns (SignExtensiblePayloadResponse);
    rpc SignBlock(SignBlockRequest) returns (SignBlockResponse);
    rpc GetAccountStatus(GetAccountStatusRequest) returns (GetAccountStatusResponse);
}
```

## Phase 1: Startup Service Methods

### DiffieHellman

Establishes a shared secret for secure passphrase transmission.

#### Request Structure

```protobuf
message DiffieHellmanRequest {
    bytes blob_ephemeral_public_key = 1;
}
```

**Fields:**
- `blob_ephemeral_public_key`: Client's ephemeral public key (33 bytes compressed)

#### Response Structure

```protobuf
message DiffieHellmanResponse {
    bytes alice_ephemeral_public_key = 1;
}
```

**Fields:**
- `alice_ephemeral_public_key`: Service's ephemeral public key (33 bytes compressed)

### StartSigner

Provides encrypted wallet passphrase to decrypt and start the signing service.

#### Request Structure

```protobuf
message StartSignerRequest {
    bytes encrypted_wallet_passphrase = 1;
    bytes nonce = 2;
}
```

**Fields:**
- `encrypted_wallet_passphrase`: AES-256-GCM encrypted passphrase
- `nonce`: 12-byte nonce used for encryption

#### Response Structure

```protobuf
message StartSignerResponse { }
```

Empty response indicates successful wallet decryption and signer startup.

## Phase 2: Signing Service Methods

### SignExtensiblePayload

Signs NEO extensible payloads including transactions, oracle responses, and other blockchain operations.

#### Request Structure

```protobuf
message SignExtensiblePayloadRequest {
    signpb.ExtensiblePayload payload = 1;
    repeated bytes script_hashes = 2;
    uint32 network = 3;
}
```

**Fields:**
- `payload`: The extensible payload to be signed
- `script_hashes`: List of H160 script hashes (20 bytes each)
- `network`: NEO network identifier (e.g., 860833102 for mainnet)

#### Response Structure

```protobuf
message SignExtensiblePayloadResponse {
    repeated signpb.AccountSigns signs = 1;
}
```

**Fields:**
- `signs`: Array of account signatures, one-to-one mapping with script_hashes

#### Usage Example

```bash
# Using grpcurl (assuming service running on localhost:9991)
grpcurl -plaintext \
  -d '{
    "payload": {
      "category": "Oracle",
      "validBlockStart": 100,
      "validBlockEnd": 200,
      "sender": "0x1234567890abcdef1234567890abcdef12345678",
      "data": "0xdeadbeef"
    },
    "scriptHashes": ["0x1234567890abcdef1234567890abcdef12345678"],
    "network": 860833102
  }' \
  localhost:9991 servicepb.SecureSign/SignExtensiblePayload
```

---

### SignBlock

Signs NEO block headers for consensus participation.

#### Request Structure

```protobuf
message SignBlockRequest {
    signpb.TrimmedBlock block = 1;
    bytes public_key = 2;
    uint32 network = 3;
}
```

**Fields:**
- `block`: The block header to be signed
- `public_key`: Compressed or uncompressed public key (33 or 65 bytes)
- `network`: NEO network identifier

#### Response Structure

```protobuf
message SignBlockResponse {
    bytes signature = 1;
}
```

**Fields:**
- `signature`: The cryptographic signature (typically 64 bytes for ECDSA)

#### Usage Example

```bash
grpcurl -plaintext \
  -d '{
    "block": {
      "header": {
        "version": 0,
        "prevHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "merkleRoot": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "timestamp": 1640995200000,
        "nonce": 12345,
        "index": 1,
        "primaryIndex": 0,
        "nextConsensus": "0x1234567890abcdef1234567890abcdef12345678"
      },
      "txHashes": []
    },
    "publicKey": "0x03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816",
    "network": 860833102
  }' \
  localhost:9991 servicepb.SecureSign/SignBlock
```

---

### GetAccountStatus

Retrieves account signing capability and multi-signature information.

#### Request Structure

```protobuf
message GetAccountStatusRequest {
    bytes public_key = 1;
}
```

**Fields:**
- `public_key`: Compressed or uncompressed public key (33 or 65 bytes)

#### Response Structure

```protobuf
message GetAccountStatusResponse {
    signpb.AccountStatus status = 1;
}
```

**Fields:**
- `status`: Account status information including signing capability

#### Usage Example

```bash
grpcurl -plaintext \
  -d '{
    "publicKey": "0x03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816"
  }' \
  localhost:9991 servicepb.SecureSign/GetAccountStatus
```

## Data Structures

### ExtensiblePayload

```protobuf
message ExtensiblePayload {
    string category = 1;
    uint32 valid_block_start = 2;
    uint32 valid_block_end = 3;
    bytes sender = 4;      // H160 (20 bytes)
    bytes data = 5;
}
```

**Purpose**: Represents a NEO extensible payload that can contain various types of blockchain data.

**Fields:**
- `category`: Type of payload (e.g., "Oracle", "StateRoot")
- `valid_block_start`: First valid block for this payload
- `valid_block_end`: Last valid block for this payload
- `sender`: Script hash of the sender (H160)
- `data`: Payload-specific data

### TrimmedBlock

```protobuf
message TrimmedBlock {
    Header header = 1;
    repeated bytes tx_hashes = 2;  // H256 list
}
```

**Purpose**: Lightweight block representation for signing.

### Header

```protobuf
message Header {
    uint32 version = 1;
    bytes prev_hash = 2;        // H256 (32 bytes)
    bytes merkle_root = 3;      // H256 (32 bytes)
    uint64 timestamp = 4;       // Unix milliseconds
    uint64 nonce = 5;
    uint32 index = 6;
    uint32 primary_index = 7;
    bytes next_consensus = 8;   // H160 (20 bytes)
}
```

**Purpose**: NEO block header structure.

### AccountStatus

```protobuf
enum AccountStatus {
    NoSuchAccount = 0;
    NoPrivateKey = 1;
    Single = 2;
    Multiple = 3;
    Locked = 4;
}
```

**Values:**
- `NoSuchAccount`: Account doesn't exist in the service
- `NoPrivateKey`: Account exists but no private key available
- `Single`: Single-signature account
- `Multiple`: Multi-signature account
- `Locked`: Account is temporarily locked

### AccountSigns

```protobuf
message AccountSigns {
    repeated AccountSign signs = 1;
    AccountContract contract = 2;
    AccountStatus status = 3;
}
```

**Purpose**: Contains signing results and account metadata.

### AccountSign

```protobuf
message AccountSign {
    bytes signature = 1;
    bytes public_key = 2;
}
```

**Purpose**: Individual signature with associated public key.

### AccountContract

```protobuf
message AccountContract {
    bytes script = 1;
    repeated uint32 parameters = 2;
    bool deployed = 3;
}
```

**Purpose**: Smart contract information for multi-sig accounts.

## Error Handling

### gRPC Status Codes

The service uses standard gRPC status codes:

- `OK` (0): Success
- `INVALID_ARGUMENT` (3): Invalid request parameters
- `NOT_FOUND` (5): Account or key not found
- `PERMISSION_DENIED` (7): Insufficient permissions
- `UNAVAILABLE` (14): Service temporarily unavailable
- `INTERNAL` (13): Internal server error

### Error Response Example

```json
{
  "error": {
    "code": 3,
    "message": "Invalid public key format",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.BadRequest",
        "field_violations": [
          {
            "field": "public_key",
            "description": "Expected 33 or 65 bytes, got 32"
          }
        ]
      }
    ]
  }
}
```

## Authentication & Authorization

### Mutual TLS (mTLS)

For production deployments, the service supports mutual TLS authentication:

```bash
# Client with mTLS
grpcurl -cert client.crt -key client.key -cacert ca.crt \
  -d '{"publicKey": "0x03..."}' \
  secure-sign.example.com:443 servicepb.SecureSign/GetAccountStatus
```

### TEE Attestation

When running in TEE environments, clients can request attestation:

```bash
# Request service attestation (implementation-specific)
grpcurl -plaintext \
  localhost:50051 servicepb.SecureSign/GetAttestation
```

## Service Workflow

### Typical Usage Pattern

1. **Start Service**: Run service with encrypted wallet
2. **Decrypt Wallet**: Use `decrypt` command to provide passphrase
3. **Perform Operations**: Use gRPC API for signing operations
4. **Shutdown**: Service clears keys from memory on shutdown

## Client Libraries

### Rust Client

```rust
use tonic::Request;
use secure_sign_rpc::servicepb::{
    secure_sign_client::SecureSignClient,
    GetAccountStatusRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SecureSignClient::connect("http://localhost:50051").await?;

    let request = Request::new(GetAccountStatusRequest {
        public_key: hex::decode("03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816")?,
    });

    let response = client.get_account_status(request).await?;
    println!("Account status: {:?}", response.get_ref().status);
    
    Ok(())
}
```

### Python Client

```python
import grpc
from secure_sign_rpc import servicepb_pb2, servicepb_pb2_grpc

def get_account_status(public_key_hex):
    channel = grpc.insecure_channel('localhost:50051')
    stub = servicepb_pb2_grpc.SecureSignStub(channel)
    
    request = servicepb_pb2.GetAccountStatusRequest(
        public_key=bytes.fromhex(public_key_hex)
    )
    
    response = stub.GetAccountStatus(request)
    return response.status

# Usage
status = get_account_status("03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816")
print(f"Account status: {status}")
```

## Performance Considerations

### Request Optimization

1. **Batch Operations**: Group multiple signatures in single requests
2. **Connection Reuse**: Maintain persistent gRPC connections
3. **Compression**: Enable gRPC compression for large payloads

### Response Caching

- Account status responses can be cached (TTL: 5 minutes)
- Block signatures are unique and should not be cached
- Public key validation results can be cached

### Monitoring Metrics

Key metrics to monitor:

- `grpc_requests_total`: Total request count by method
- `grpc_request_duration_seconds`: Request latency histogram
- `signatures_generated_total`: Total signatures created
- `authentication_failures_total`: Failed authentication attempts

## Troubleshooting

### Common Issues

1. **Invalid Public Key Format**
   - Ensure public keys are 33 (compressed) or 65 (uncompressed) bytes
   - Verify hex encoding is correct

2. **Network Mismatch**
   - Check network ID matches service configuration
   - Verify blockchain network compatibility

3. **Account Not Found**
   - Ensure wallet is loaded in the service
   - Verify public key corresponds to loaded account

4. **TEE Attestation Failures**
   - Check TEE environment is properly configured
   - Verify attestation certificate chain

### Debug Mode

Enable debug logging for detailed request/response information:

```bash
RUST_LOG=debug ./secure-sign run --config config.json
```

### Health Checks

The service provides health check endpoints:

```bash
# gRPC health check
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check

# Custom health endpoint (if enabled)
curl http://localhost:8080/health
``` 