// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Independent Neo N3 RPC agreement checks for the economic signing path.

use std::sync::Arc;
use std::time::Duration;

mod endpoint;
pub use endpoint::{HostResolver, SystemHostResolver};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use reqwest::{Client, Url};
use secure_sign_core::bin::to_varint_le;
use secure_sign_core::h160::H160;
use secure_sign_core::neo::check_sign::CheckSign;
use secure_sign_core::neo::gas_sweep_constants::gas_script_hash;
use secure_sign_core::neo::gas_sweep_policy::script_hash_from_public_key;
use secure_sign_core::neo::tx::UnsignedTransaction;
use secure_sign_core::secp256r1::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MAX_RPC_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RpcVerificationError {
    #[error("exactly two independent RPC endpoints are required")]
    EndpointCount,

    #[error("RPC endpoint must use HTTPS")]
    HttpsRequired,

    #[error("RPC endpoints must use different hosts")]
    HostsNotIndependent,

    #[error("RPC endpoints must resolve to disjoint public address sets")]
    ResolutionsNotIndependent,

    #[error("RPC DNS resolution failed for {host}: {reason}")]
    DnsResolution { host: String, reason: String },

    #[error("RPC endpoint is not allowed: {0}")]
    EndpointNotAllowed(String),

    #[error("invalid RPC endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("RPC transport failed for {endpoint}: {reason}")]
    Transport { endpoint: String, reason: String },

    #[error("RPC response from {endpoint} is invalid: {reason}")]
    InvalidResponse { endpoint: String, reason: String },

    #[error("RPC {method} failed on {endpoint}: {reason}")]
    Rpc {
        endpoint: String,
        method: String,
        reason: String,
    },

    #[error("independent RPC nodes disagree on {field}")]
    Disagreement { field: &'static str },

    #[error("RPC height skew {actual} exceeds maximum {maximum}")]
    HeightSkew { actual: u32, maximum: u32 },

    #[error("transaction has expired at height {tip}")]
    TransactionExpired { tip: u32 },

    #[error("transaction valid-until height is too far ahead")]
    ValidUntilTooFar,

    #[error("transaction system fee does not match dual-RPC simulation")]
    SystemFeeMismatch,

    #[error("transaction network fee does not match dual-RPC calculation")]
    NetworkFeeMismatch,

    #[error("transaction simulation did not HALT successfully")]
    SimulationFailed,

    #[error("invalid signer public key: {0}")]
    InvalidPublicKey(String),

    #[error("numeric RPC value is outside the supported range")]
    NumericRange,

    #[error("both RPC broadcasts failed")]
    BroadcastFailed,
}

#[derive(Clone, Debug)]
pub(crate) struct NeoRpcClient {
    pub(crate) endpoint: Url,
    pub(crate) label: String,
    pub(crate) client: Client,
}

#[derive(Clone, Debug)]
pub struct DualRpcVerifier {
    endpoints: [NeoRpcClient; 2],
    max_height_skew: u32,
    max_valid_until_delta: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainState {
    /// Lower of the two independently observed balances.
    pub safe_balance: u64,
    pub min_height: u32,
    pub max_height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RpcSnapshot {
    pub height: u32,
    pub balance: u64,
    pub system_fee: u64,
    pub network_fee: u64,
    pub simulation_succeeded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedGasSweep {
    /// Lower of the two independently observed balances.
    pub safe_balance: u64,
    pub min_height: u32,
    pub max_height: u32,
    pub system_fee: u64,
    pub network_fee: u64,
}

impl DualRpcVerifier {
    pub fn from_csv(
        endpoints: &str,
        timeout: Duration,
        max_height_skew: u32,
        max_valid_until_delta: u32,
    ) -> Result<Self, RpcVerificationError> {
        Self::from_csv_with_resolver(
            endpoints,
            timeout,
            max_height_skew,
            max_valid_until_delta,
            Arc::new(SystemHostResolver),
        )
    }

    pub fn from_csv_with_resolver(
        endpoints: &str,
        timeout: Duration,
        max_height_skew: u32,
        max_valid_until_delta: u32,
        resolver: Arc<dyn HostResolver>,
    ) -> Result<Self, RpcVerificationError> {
        Ok(Self {
            endpoints: endpoint::build_clients(endpoints, timeout, resolver)?,
            max_height_skew,
            max_valid_until_delta,
        })
    }

    pub async fn read_chain_state(
        &self,
        source: &H160,
    ) -> Result<ChainState, RpcVerificationError> {
        let (first, second) = tokio::try_join!(
            self.endpoints[0].query_head_balance(source),
            self.endpoints[1].query_head_balance(source)
        )?;
        let (min_height, max_height) = ordered(first.0, second.0);
        check_height_skew(min_height, max_height, self.max_height_skew)?;
        Ok(ChainState {
            safe_balance: first.1.min(second.1),
            min_height,
            max_height,
        })
    }

    pub async fn estimate_transaction(
        &self,
        tx: &UnsignedTransaction,
        public_key: &[u8],
    ) -> Result<VerifiedGasSweep, RpcVerificationError> {
        let source = script_hash_from_public_key(public_key)
            .map_err(RpcVerificationError::InvalidPublicKey)?;
        let (first, second) = tokio::try_join!(
            self.endpoints[0].query_snapshot(tx, public_key, &source),
            self.endpoints[1].query_snapshot(tx, public_key, &source)
        )?;
        compare_snapshots(
            tx,
            &first,
            &second,
            self.max_height_skew,
            self.max_valid_until_delta,
            false,
        )
    }

    pub async fn verify_transaction(
        &self,
        tx: &UnsignedTransaction,
        public_key: &[u8],
    ) -> Result<VerifiedGasSweep, RpcVerificationError> {
        let source = script_hash_from_public_key(public_key)
            .map_err(RpcVerificationError::InvalidPublicKey)?;
        let (first, second) = tokio::try_join!(
            self.endpoints[0].query_snapshot(tx, public_key, &source),
            self.endpoints[1].query_snapshot(tx, public_key, &source)
        )?;
        compare_snapshots(
            tx,
            &first,
            &second,
            self.max_height_skew,
            self.max_valid_until_delta,
            true,
        )
    }

    pub async fn broadcast(&self, signed_tx: &[u8]) -> Result<String, RpcVerificationError> {
        let params = json!([BASE64.encode(signed_tx)]);
        for endpoint in &self.endpoints {
            match endpoint.call("sendrawtransaction", params.clone()).await {
                Ok(value) => {
                    if let Some(hash) = value
                        .get("hash")
                        .and_then(Value::as_str)
                        .or_else(|| value.as_str())
                    {
                        let digits = hash.strip_prefix("0x").unwrap_or(hash);
                        if digits.len() == 64 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                        {
                            return Ok(hash.to_owned());
                        }
                    }
                    if value == Value::Bool(true) {
                        return Ok(String::new());
                    }
                }
                Err(RpcVerificationError::Rpc { reason, .. })
                    if is_duplicate_broadcast(&reason) =>
                {
                    return Ok(String::new());
                }
                Err(_) => continue,
            }
        }
        Err(RpcVerificationError::BroadcastFailed)
    }

    pub async fn application_log(
        &self,
        transaction_hash: &str,
    ) -> Result<Option<Value>, RpcVerificationError> {
        let mut first_failure = None;
        for endpoint in &self.endpoints {
            match endpoint
                .call("getapplicationlog", json!([transaction_hash]))
                .await
            {
                Ok(value) => return Ok(Some(value)),
                Err(RpcVerificationError::Rpc { reason, .. })
                    if reason.to_ascii_lowercase().contains("unknown") =>
                {
                    continue;
                }
                Err(err) => {
                    if first_failure.is_none() {
                        first_failure = Some(err);
                    }
                }
            }
        }
        match first_failure {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }
}

impl NeoRpcClient {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcVerificationError> {
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|err| RpcVerificationError::Transport {
                endpoint: self.label.clone(),
                reason: clean_reason(&err),
            })?;
        if !response.status().is_success() {
            return Err(RpcVerificationError::Transport {
                endpoint: self.label.clone(),
                reason: format!("HTTP {}", response.status().as_u16()),
            });
        }
        if response.content_length().unwrap_or(0) > MAX_RPC_RESPONSE_BYTES as u64 {
            return Err(RpcVerificationError::InvalidResponse {
                endpoint: self.label.clone(),
                reason: "response is too large".to_owned(),
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|err| RpcVerificationError::Transport {
                    endpoint: self.label.clone(),
                    reason: clean_reason(&err),
                })?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
                return Err(RpcVerificationError::InvalidResponse {
                    endpoint: self.label.clone(),
                    reason: "response is too large".to_owned(),
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|err| {
            RpcVerificationError::InvalidResponse {
                endpoint: self.label.clone(),
                reason: clean_reason(&err),
            }
        })?;
        if let Some(error) = payload.get("error").filter(|value| !value.is_null()) {
            return Err(RpcVerificationError::Rpc {
                endpoint: self.label.clone(),
                method: method.to_owned(),
                reason: sanitize_rpc_error(error),
            });
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| RpcVerificationError::InvalidResponse {
                endpoint: self.label.clone(),
                reason: "missing result".to_owned(),
            })
    }

    async fn query_head_balance(&self, source: &H160) -> Result<(u32, u64), RpcVerificationError> {
        let balance_params = json!([
            gas_script_hash().to_string(),
            "balanceOf",
            [{"type": "Hash160", "value": source.to_string()}]
        ]);
        let (count, balance) = tokio::try_join!(
            self.call("getblockcount", json!([])),
            self.call("invokefunction", balance_params)
        )?;
        Ok((parse_tip(&count)?, parse_integer_stack(&balance)?))
    }

    async fn query_snapshot(
        &self,
        tx: &UnsignedTransaction,
        public_key: &[u8],
        source: &H160,
    ) -> Result<RpcSnapshot, RpcVerificationError> {
        let full_tx = transaction_with_dummy_witness(&tx.hash_data, public_key)?;
        let balance_params = json!([
            gas_script_hash().to_string(),
            "balanceOf",
            [{"type": "Hash160", "value": source.to_string()}]
        ]);
        let simulation_params = json!([
            BASE64.encode(&tx.script),
            [{"account": source.to_string(), "scopes": "CalledByEntry"}]
        ]);
        let (count, balance, simulation, network_fee) = tokio::try_join!(
            self.call("getblockcount", json!([])),
            self.call("invokefunction", balance_params),
            self.call("invokescript", simulation_params),
            self.call("calculatenetworkfee", json!([BASE64.encode(full_tx)]))
        )?;

        let (simulation_succeeded, system_fee) = parse_simulation(&simulation)?;
        Ok(RpcSnapshot {
            height: parse_tip(&count)?,
            balance: parse_integer_stack(&balance)?,
            system_fee,
            network_fee: parse_named_u64(&network_fee, "networkfee")?,
            simulation_succeeded,
        })
    }
}

pub fn transaction_with_signature(
    unsigned_tx: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, RpcVerificationError> {
    if signature.len() != 64 {
        return Err(RpcVerificationError::InvalidResponse {
            endpoint: "signer".to_owned(),
            reason: "signature must be 64 bytes".to_owned(),
        });
    }
    let compressed = PublicKey::try_to_compressed(public_key)
        .map_err(|err| RpcVerificationError::InvalidPublicKey(err.to_string()))?;
    let verification = CheckSign::from_compressed_public_key(&compressed);
    let mut invocation = Vec::with_capacity(66);
    invocation.extend_from_slice(&[0x0c, 0x40]);
    invocation.extend_from_slice(signature);

    let mut out = Vec::with_capacity(unsigned_tx.len() + invocation.len() + 48);
    out.extend_from_slice(unsigned_tx);
    out.push(0x01);
    append_varbytes(&mut out, &invocation);
    append_varbytes(&mut out, verification.as_bytes());
    Ok(out)
}

fn transaction_with_dummy_witness(
    unsigned_tx: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, RpcVerificationError> {
    transaction_with_signature(unsigned_tx, public_key, &[0u8; 64])
}

fn append_varbytes(out: &mut Vec<u8>, value: &[u8]) {
    let (size, encoded) = to_varint_le(value.len() as u64);
    out.extend_from_slice(&encoded[..size as usize]);
    out.extend_from_slice(value);
}

fn compare_snapshots(
    tx: &UnsignedTransaction,
    first: &RpcSnapshot,
    second: &RpcSnapshot,
    max_height_skew: u32,
    max_valid_until_delta: u32,
    enforce_declared_fees: bool,
) -> Result<VerifiedGasSweep, RpcVerificationError> {
    if first.system_fee != second.system_fee {
        return Err(RpcVerificationError::Disagreement {
            field: "system fee",
        });
    }
    if first.network_fee != second.network_fee {
        return Err(RpcVerificationError::Disagreement {
            field: "network fee",
        });
    }
    if !first.simulation_succeeded || !second.simulation_succeeded {
        return Err(RpcVerificationError::SimulationFailed);
    }

    let (min_height, max_height) = ordered(first.height, second.height);
    check_height_skew(min_height, max_height, max_height_skew)?;
    if tx.valid_until_block <= max_height {
        return Err(RpcVerificationError::TransactionExpired { tip: max_height });
    }
    if tx.valid_until_block > min_height.saturating_add(max_valid_until_delta) {
        return Err(RpcVerificationError::ValidUntilTooFar);
    }
    if enforce_declared_fees && tx.system_fee != first.system_fee {
        return Err(RpcVerificationError::SystemFeeMismatch);
    }
    if enforce_declared_fees && tx.network_fee != first.network_fee {
        return Err(RpcVerificationError::NetworkFeeMismatch);
    }

    Ok(VerifiedGasSweep {
        safe_balance: first.balance.min(second.balance),
        min_height,
        max_height,
        system_fee: first.system_fee,
        network_fee: first.network_fee,
    })
}

fn ordered(first: u32, second: u32) -> (u32, u32) {
    if first <= second {
        (first, second)
    } else {
        (second, first)
    }
}

fn check_height_skew(
    min_height: u32,
    max_height: u32,
    maximum: u32,
) -> Result<(), RpcVerificationError> {
    let actual = max_height.saturating_sub(min_height);
    if actual > maximum {
        Err(RpcVerificationError::HeightSkew { actual, maximum })
    } else {
        Ok(())
    }
}

fn parse_tip(value: &Value) -> Result<u32, RpcVerificationError> {
    let count = parse_u64(value)?;
    let tip = count
        .checked_sub(1)
        .ok_or(RpcVerificationError::NumericRange)?;
    u32::try_from(tip).map_err(|_| RpcVerificationError::NumericRange)
}

fn parse_integer_stack(value: &Value) -> Result<u64, RpcVerificationError> {
    if value.get("state").and_then(Value::as_str) != Some("HALT") {
        return Err(RpcVerificationError::SimulationFailed);
    }
    let item = value
        .get("stack")
        .and_then(Value::as_array)
        .and_then(|stack| stack.first())
        .ok_or_else(|| RpcVerificationError::InvalidResponse {
            endpoint: "RPC".to_owned(),
            reason: "missing stack result".to_owned(),
        })?;
    if item.get("type").and_then(Value::as_str) != Some("Integer") {
        return Err(RpcVerificationError::InvalidResponse {
            endpoint: "RPC".to_owned(),
            reason: "expected Integer stack result".to_owned(),
        });
    }
    parse_u64(item.get("value").unwrap_or(&Value::Null))
}

fn parse_simulation(value: &Value) -> Result<(bool, u64), RpcVerificationError> {
    let halted = value.get("state").and_then(Value::as_str) == Some("HALT");
    let stack_true = value
        .get("stack")
        .and_then(Value::as_array)
        .and_then(|stack| stack.first())
        .map(|item| {
            item.get("type").and_then(Value::as_str) == Some("Boolean")
                && item.get("value").and_then(Value::as_bool) == Some(true)
        })
        .unwrap_or(false);
    let fee = parse_named_u64(value, "gasconsumed")?;
    Ok((halted && stack_true, fee))
}

fn parse_named_u64(value: &Value, key: &str) -> Result<u64, RpcVerificationError> {
    parse_u64(value.get(key).unwrap_or(&Value::Null))
}

fn parse_u64(value: &Value) -> Result<u64, RpcVerificationError> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .and_then(|raw| raw.parse::<u64>().ok())
        .ok_or(RpcVerificationError::NumericRange)
}

fn sanitize_rpc_error(value: &Value) -> String {
    let text = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("RPC error");
    text.chars().take(160).collect()
}

fn is_duplicate_broadcast(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("already exists")
        || lower == "alreadyexists"
        || lower.contains("already in")
        || lower.contains("already known")
}

pub(crate) fn clean_reason(reason: &impl std::fmt::Display) -> String {
    redact_url_secrets(&reason.to_string())
        .chars()
        .take(160)
        .collect()
}

pub(crate) fn redact_url_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == ':' && chars.peek() == Some(&'/') {
            out.push(ch);
            continue;
        }
        if ch == '/' && out.ends_with(':') && chars.peek() == Some(&'/') {
            out.push(ch);
            out.push(chars.next().unwrap());
            let mut authority = String::new();
            while let Some(&next) = chars.peek() {
                if next == '/' || next == '?' || next == '#' || next.is_whitespace() {
                    break;
                }
                authority.push(chars.next().unwrap());
            }
            if let Some(at) = authority.rfind('@') {
                out.push_str("redacted@");
                out.push_str(&authority[at + 1..]);
            } else {
                out.push_str(&authority);
            }
            continue;
        }
        if ch == '?' || ch == '#' {
            out.push(ch);
            out.push_str("redacted");
            while let Some(&next) = chars.peek() {
                if next.is_whitespace() || next == '?' || next == '#' {
                    break;
                }
                chars.next();
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sign_core::neo::gas_transfer_script::build_gas_transfer_script;
    use secure_sign_core::neo::tx::encode_unsigned_transaction;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    async fn broadcast_replies(replies: Vec<Value>) -> Result<String, RpcVerificationError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            for reply in replies {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["method"], "sendrawtransaction");
                assert_eq!(request["params"], json!([BASE64.encode([1, 2, 3])]));
                let body = reply.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        // Local fixtures bypass endpoint construction only inside this test module.
        let client = NeoRpcClient {
            endpoint,
            label: "fixture".to_owned(),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
        };
        let verifier = DualRpcVerifier {
            endpoints: [client.clone(), client],
            max_height_skew: 3,
            max_valid_until_delta: 100,
        };
        let result = verifier.broadcast(&[1, 2, 3]).await;
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        result
    }

    #[tokio::test]
    async fn broadcast_accepts_standard_neo_hash_object() {
        let hash = format!("0x{}", "12".repeat(32));
        let result = broadcast_replies(vec![
            json!({"jsonrpc":"2.0", "id":1, "result":{"hash":hash}}),
        ])
        .await;
        assert_eq!(result.unwrap(), hash);
    }

    #[tokio::test]
    async fn broadcast_falls_back_after_rejection() {
        let hash = format!("0x{}", "34".repeat(32));
        let result = broadcast_replies(vec![
            json!({"jsonrpc":"2.0", "id":1, "result":false}),
            json!({"jsonrpc":"2.0", "id":1, "result":{"hash":hash}}),
        ])
        .await;
        assert_eq!(result.unwrap(), hash);
    }

    #[tokio::test]
    async fn broadcast_rejects_empty_malformed_and_failed_results() {
        for value in [
            json!(false),
            Value::Null,
            json!({}),
            json!({"hash":""}),
            json!(""),
            json!({"hash":"not-a-hash"}),
        ] {
            let reply = json!({"jsonrpc":"2.0", "id":1, "result":value});
            assert!(broadcast_replies(vec![reply.clone(), reply]).await.is_err());
        }
    }

    #[tokio::test]
    async fn broadcast_preserves_string_boolean_and_duplicate_acknowledgements() {
        let hash = format!("0x{}", "56".repeat(32));
        assert_eq!(
            broadcast_replies(vec![json!({"jsonrpc":"2.0", "id":1, "result":hash})])
                .await
                .unwrap(),
            hash
        );
        assert_eq!(
            broadcast_replies(vec![json!({"jsonrpc":"2.0", "id":1, "result":true})])
                .await
                .unwrap(),
            ""
        );
        assert_eq!(
            broadcast_replies(vec![
                json!({"jsonrpc":"2.0", "id":1, "error":{"code":-501,"message":"AlreadyExists"}})
            ])
            .await
            .unwrap(),
            ""
        );
    }

    fn snapshot(height: u32) -> RpcSnapshot {
        RpcSnapshot {
            height,
            balance: 10_000_000_000,
            system_fee: 215_925,
            network_fee: 37_824,
            simulation_succeeded: true,
        }
    }

    fn transaction(valid_until: u32) -> UnsignedTransaction {
        let source = H160::from_le_bytes([0x11; 20]);
        let destination = H160::from_le_bytes([0x22; 20]);
        let script = build_gas_transfer_script(&source, &destination, 9_899_746_251);
        let raw = encode_unsigned_transaction(1, 215_925, 37_824, valid_until, &source, &script);
        secure_sign_core::neo::tx::decode_unsigned_transaction(&raw).unwrap()
    }

    fn public_ips(first: [u8; 4], second: [u8; 4]) -> Arc<dyn HostResolver> {
        use std::collections::{BTreeSet, HashMap};
        use std::net::{IpAddr, Ipv4Addr};

        Arc::new(endpoint::MapResolver {
            answers: HashMap::from([
                (
                    "rpc-a.example".to_owned(),
                    BTreeSet::from([IpAddr::V4(Ipv4Addr::from(first))]),
                ),
                (
                    "rpc-b.example".to_owned(),
                    BTreeSet::from([IpAddr::V4(Ipv4Addr::from(second))]),
                ),
            ]),
        })
    }

    fn verifier_from(
        urls: &str,
        resolver: Arc<dyn HostResolver>,
    ) -> Result<DualRpcVerifier, RpcVerificationError> {
        DualRpcVerifier::from_csv_with_resolver(urls, Duration::from_secs(1), 3, 100, resolver)
    }

    #[test]
    fn clean_reason_redacts_userinfo_query_and_fragment() {
        let rendered = clean_reason(
            &"GET https://user:super-secret@rpc.example/path?api_key=super-secret#frag",
        );
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("api_key=super-secret"), "{rendered}");
        assert!(rendered.contains("redacted@rpc.example"), "{rendered}");
        assert!(rendered.contains("?redacted"), "{rendered}");
        assert!(rendered.contains("#redacted"), "{rendered}");
    }

    #[test]
    fn endpoint_configuration_requires_independent_https_hosts() {
        assert!(verifier_from(
            "https://rpc-a.example,https://rpc-b.example",
            public_ips([1, 1, 1, 1], [8, 8, 8, 8])
        )
        .is_ok());
        assert!(matches!(
            verifier_from(
                "http://rpc-a.example,https://rpc-b.example",
                public_ips([1, 1, 1, 1], [8, 8, 8, 8])
            ),
            Err(RpcVerificationError::HttpsRequired)
        ));
        assert!(matches!(
            verifier_from(
                "https://rpc-a.example/a,https://rpc-a.example/b",
                public_ips([1, 1, 1, 1], [8, 8, 8, 8])
            ),
            Err(RpcVerificationError::HostsNotIndependent)
        ));
        assert!(DualRpcVerifier::from_csv(
            "https://127.0.0.1,https://rpc-b.example",
            Duration::from_secs(1),
            3,
            100
        )
        .is_err());
    }

    #[test]
    fn overlapping_or_private_dns_answers_are_rejected() {
        use std::collections::{BTreeSet, HashMap};
        use std::net::{IpAddr, Ipv4Addr};

        assert!(matches!(
            verifier_from(
                "https://rpc-a.example,https://rpc-b.example",
                public_ips([1, 1, 1, 1], [1, 1, 1, 1])
            ),
            Err(RpcVerificationError::ResolutionsNotIndependent)
        ));

        let private_dns = Arc::new(endpoint::MapResolver {
            answers: HashMap::from([
                (
                    "rpc-a.example".to_owned(),
                    BTreeSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]),
                ),
                (
                    "rpc-b.example".to_owned(),
                    BTreeSet::from([IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]),
                ),
            ]),
        });
        assert!(matches!(
            verifier_from("https://rpc-a.example,https://rpc-b.example", private_dns),
            Err(RpcVerificationError::EndpointNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn redirects_are_rejected_by_the_http_client() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            while stream.read_line(&mut line).await.unwrap() != 0 {
                if line == "\r\n" {
                    break;
                }
                line.clear();
            }
            stream
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://203.0.113.10/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let client = NeoRpcClient {
            endpoint,
            label: "fixture".to_owned(),
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
        };
        let err = client.call("getblockcount", json!([])).await.unwrap_err();
        match err {
            RpcVerificationError::Transport { reason, .. } => {
                assert!(
                    reason.contains("302") || reason.to_ascii_lowercase().contains("redirect"),
                    "{reason}"
                );
            }
            other => panic!("expected transport failure, got {other}"),
        }
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dns_rebinding_or_resolution_change_fails_closed() {
        use std::collections::{BTreeSet, HashMap};
        use std::net::{IpAddr, Ipv4Addr};

        let resolver = Arc::new(endpoint::SequenceResolver {
            answers: std::sync::Mutex::new(HashMap::from([
                (
                    "rpc-a.example".to_owned(),
                    vec![
                        BTreeSet::from([IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
                        BTreeSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
                    ],
                ),
                (
                    "rpc-b.example".to_owned(),
                    vec![
                        BTreeSet::from([IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]),
                        BTreeSet::from([IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]),
                    ],
                ),
            ])),
        });
        let verifier = verifier_from("https://rpc-a.example,https://rpc-b.example", resolver)
            .expect("initial public pins must succeed");
        let err = verifier.endpoints[0]
            .call("getblockcount", json!([]))
            .await
            .unwrap_err();
        let text = error_chain(&err);
        assert!(
            text.contains("not allowed")
                || text.contains("non-public")
                || text.contains("changed")
                || text.contains("error sending request"),
            "{text}"
        );
    }

    fn error_chain(err: &dyn std::error::Error) -> String {
        let mut text = err.to_string();
        let mut current = err.source();
        while let Some(source) = current {
            text.push_str(" :: ");
            text.push_str(&source.to_string());
            current = source.source();
        }
        text
    }

    #[test]
    fn neo_duplicate_broadcast_errors_are_idempotent() {
        assert!(is_duplicate_broadcast("Inventory already exists on chain"));
        assert!(is_duplicate_broadcast("Already in the mempool"));
        assert!(is_duplicate_broadcast("AlreadyExists"));
        assert!(!is_duplicate_broadcast("Insufficient network fee"));
    }

    #[test]
    fn agreement_uses_safe_balance_and_rejects_height_fee_or_simulation_failures() {
        let tx = transaction(1_080);
        let first = snapshot(1_000);
        let mut second = snapshot(1_001);
        assert!(compare_snapshots(&tx, &first, &second, 3, 100, true).is_ok());

        second.balance += 1;
        assert_eq!(
            compare_snapshots(&tx, &first, &second, 3, 100, true)
                .unwrap()
                .safe_balance,
            first.balance
        );
        second = snapshot(1_004);
        assert!(matches!(
            compare_snapshots(&tx, &first, &second, 3, 100, true),
            Err(RpcVerificationError::HeightSkew { .. })
        ));
        second = snapshot(1_001);
        second.network_fee += 1;
        assert!(matches!(
            compare_snapshots(&tx, &first, &second, 3, 100, true),
            Err(RpcVerificationError::Disagreement {
                field: "network fee"
            })
        ));
        second = snapshot(1_001);
        second.simulation_succeeded = false;
        assert!(matches!(
            compare_snapshots(&tx, &first, &second, 3, 100, true),
            Err(RpcVerificationError::SimulationFailed)
        ));
    }

    #[test]
    fn agreement_rejects_stale_or_overlong_transactions() {
        let first = snapshot(1_000);
        let second = snapshot(1_001);
        assert!(matches!(
            compare_snapshots(&transaction(1_001), &first, &second, 3, 100, true),
            Err(RpcVerificationError::TransactionExpired { .. })
        ));
        assert!(matches!(
            compare_snapshots(&transaction(1_101), &first, &second, 3, 100, true),
            Err(RpcVerificationError::ValidUntilTooFar)
        ));
    }

    #[test]
    fn witness_assembly_is_canonical() {
        let public_key =
            hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                .unwrap();
        let signed = transaction_with_signature(&[1, 2, 3], &public_key, &[0x44; 64]).unwrap();
        assert_eq!(&signed[..3], &[1, 2, 3]);
        assert_eq!(signed[3], 1);
        assert_eq!(signed[4], 66);
        assert_eq!(&signed[5..7], &[0x0c, 0x40]);
        assert_eq!(signed[71], 40);
        assert_eq!(signed.len(), 112);
    }
}
