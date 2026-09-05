// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{FixedOffset, Utc};
use clap::Parser;
use fs2::FileExt;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use secure_sign_core::ecdsa::ECC256_SIGN_SIZE;
use secure_sign_core::neo::gas_sweep_constants::{
    FEE_CAP_FRACTIONS, GAS_SWEEP_NETWORK_MAGIC, ONE_GAS_FRACTIONS,
};
use secure_sign_core::neo::gas_sweep_policy::{
    build_deploy_policy, parse_neo3_address_to_script_hash, script_hash_from_public_key,
    GasSweepValidationRequest,
};
use secure_sign_core::neo::gas_transfer_script::build_gas_transfer_script;
use secure_sign_core::neo::tx::{
    decode_unsigned_transaction, encode_unsigned_transaction, UnsignedTransaction,
};
use secure_sign_core::neo::ToSignData;
use secure_sign_core::random::{CryptRandom, EnvCryptRandom};
use secure_sign_neo_rpc::{transaction_with_signature, DualRpcVerifier};
use secure_sign_rpc::servicepb::secure_sign_client::SecureSignClient;
use secure_sign_rpc::servicepb::SignTransactionRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tonic::transport::Endpoint;
use url::Url;

const PLAN_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Build, verify, sign, and optionally broadcast the daily council GAS sweep"
)]
struct Args {
    #[arg(long, env = "GAS_SWEEP_RPC_URLS")]
    rpc_urls: String,

    #[arg(long, env = "SIGNER_PUBLIC_KEY")]
    public_key: String,

    #[arg(long, env = "GAS_SWEEP_DESTINATION_ADDRESS")]
    destination: String,

    #[arg(
        long,
        default_value = "http://10.78.0.1:9991",
        env = "SIGNER_GATEWAY_ENDPOINT"
    )]
    gateway_endpoint: String,

    #[arg(long, default_value_t = GAS_SWEEP_NETWORK_MAGIC)]
    network: u32,

    #[arg(long, default_value_t = ONE_GAS_FRACTIONS)]
    reserve: u64,

    #[arg(long, default_value_t = 90)]
    valid_for_blocks: u32,

    #[arg(long, default_value_t = 10)]
    max_height_skew: u32,

    #[arg(long, default_value_t = 120)]
    max_valid_until_delta: u32,

    #[arg(long, default_value_t = 4_000)]
    rpc_timeout_ms: u64,

    #[arg(long, default_value_t = 2_000)]
    gateway_timeout_ms: u64,

    #[arg(long, default_value_t = 120)]
    confirmation_timeout_seconds: u64,

    #[arg(
        long,
        default_value = "/var/lib/neo-signer/gas-sweep-plan.json",
        env = "GAS_SWEEP_STATE_PATH"
    )]
    state_path: PathBuf,

    /// Required to sign and broadcast. Without this flag the command is a dry run.
    #[arg(long, default_value_t = false)]
    broadcast: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlanStatus {
    Planned,
    Signed,
    Broadcast,
    Confirmed,
    NoOp,
    Expired,
}

#[derive(Debug, Serialize, Deserialize)]
struct SweepPlan {
    version: u32,
    day: String,
    created_at: String,
    network: u32,
    source_script_hash: String,
    destination_script_hash: String,
    unsigned_tx_base64: String,
    expected_amount: u64,
    expected_fee_total: u64,
    transaction_hash: String,
    signature_base64: Option<String>,
    broadcast_hash: Option<String>,
    status: PlanStatus,
}

struct ProcessLock {
    file: File,
}

impl ProcessLock {
    fn acquire(state_path: &Path) -> Result<Self, Box<dyn Error>> {
        let parent = state_path
            .parent()
            .ok_or("state path must have a parent directory")?;
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let lock_path = state_path.with_extension("lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)?;
        file.try_lock_exclusive()
            .map_err(|_| "another GAS sweep process is already running")?;
        Ok(Self { file })
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Debug, Serialize)]
struct CommandResult<'a> {
    status: PlanStatus,
    day: &'a str,
    transaction_hash: &'a str,
    amount_fractions: u64,
    fee_fractions: u64,
    broadcast: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    validate_args(&args)?;
    let _lock = ProcessLock::acquire(&args.state_path)?;

    let public_key = hex::decode(&args.public_key)?;
    let source = script_hash_from_public_key(&public_key)?;
    let destination = parse_neo3_address_to_script_hash(&args.destination)?;
    let day = shanghai_day();
    let verifier = DualRpcVerifier::from_csv(
        &args.rpc_urls,
        Duration::from_millis(args.rpc_timeout_ms),
        args.max_height_skew,
        args.max_valid_until_delta,
    )?;

    let mut plan = match load_plan(&args.state_path)? {
        Some(mut existing) if existing.day == day => {
            validate_saved_plan(
                &existing,
                &args,
                &source.to_string(),
                &destination.to_string(),
            )?;
            if args.broadcast
                && matches!(
                    existing.status,
                    PlanStatus::Planned | PlanStatus::Signed | PlanStatus::Broadcast
                )
            {
                let log = verifier.application_log(&existing.transaction_hash).await?;
                confirm_plan_from_log(&mut existing, log.as_ref())?;
            }
            existing
        }
        Some(existing)
            if matches!(
                existing.status,
                PlanStatus::Confirmed | PlanStatus::NoOp | PlanStatus::Expired
            ) =>
        {
            build_plan(&args, &verifier, &public_key, &day).await?
        }
        Some(mut existing) => {
            validate_saved_plan(
                &existing,
                &args,
                &source.to_string(),
                &destination.to_string(),
            )?;
            let log = verifier.application_log(&existing.transaction_hash).await?;
            if confirm_plan_from_log(&mut existing, log.as_ref())? {
                save_plan(&args.state_path, &existing)?;
                build_plan(&args, &verifier, &public_key, &day).await?
            } else {
                let raw = BASE64.decode(existing.unsigned_tx_base64.as_bytes())?;
                let old_tx = decode_unsigned_transaction(&raw)?;
                let chain = verifier.read_chain_state(&source).await?;
                if chain.max_height < old_tx.valid_until_block {
                    return Err(format!(
                        "unresolved sweep plan from {} is still valid and must be retried",
                        existing.day
                    )
                    .into());
                }
                existing.status = PlanStatus::Expired;
                save_plan(&args.state_path, &existing)?;
                build_plan(&args, &verifier, &public_key, &day).await?
            }
        }
        _ => build_plan(&args, &verifier, &public_key, &day).await?,
    };
    save_plan(&args.state_path, &plan)?;

    if !args.broadcast || plan.status == PlanStatus::NoOp {
        print_result(&plan, false)?;
        return Ok(());
    }
    if plan.status == PlanStatus::Confirmed {
        print_result(&plan, true)?;
        return Ok(());
    }
    if plan.status == PlanStatus::Expired {
        return Err("today's saved sweep transaction expired before broadcast".into());
    }

    let unsigned = BASE64.decode(plan.unsigned_tx_base64.as_bytes())?;
    let tx = decode_unsigned_transaction(&unsigned)?;
    let signature = match plan.signature_base64.as_deref() {
        Some(encoded) => BASE64.decode(encoded.as_bytes())?,
        None => {
            let signature = request_signature(&args, &plan, &public_key).await?;
            verify_signature(&public_key, args.network, &tx, &signature)?;
            plan.signature_base64 = Some(BASE64.encode(&signature));
            plan.status = PlanStatus::Signed;
            save_plan(&args.state_path, &plan)?;
            signature
        }
    };
    verify_signature(&public_key, args.network, &tx, &signature)?;
    let signed_tx = transaction_with_signature(&unsigned, &public_key, &signature)?;

    let expected_hash = plan.transaction_hash.clone();
    let broadcast_hash = verifier.broadcast(&signed_tx).await?;
    if !broadcast_hash.is_empty()
        && normalize_hash(&broadcast_hash) != normalize_hash(&expected_hash)
    {
        return Err("RPC returned a transaction hash different from the signed transaction".into());
    }
    plan.broadcast_hash = Some(if broadcast_hash.is_empty() {
        expected_hash.clone()
    } else {
        broadcast_hash
    });
    plan.status = PlanStatus::Broadcast;
    save_plan(&args.state_path, &plan)?;

    wait_for_confirmation(
        &verifier,
        &expected_hash,
        Duration::from_secs(args.confirmation_timeout_seconds),
    )
    .await?;
    plan.status = PlanStatus::Confirmed;
    save_plan(&args.state_path, &plan)?;
    print_result(&plan, true)?;
    Ok(())
}

fn validate_args(args: &Args) -> Result<(), Box<dyn Error>> {
    if args.network != GAS_SWEEP_NETWORK_MAGIC {
        return Err("the production sweeper only supports Neo N3 MainNet".into());
    }
    if args.reserve != ONE_GAS_FRACTIONS {
        return Err("the production sweeper must retain exactly 1 GAS".into());
    }
    if args.valid_for_blocks <= args.max_height_skew
        || args.valid_for_blocks > args.max_valid_until_delta
    {
        return Err("valid-for-blocks must exceed height skew and fit the gateway window".into());
    }
    validate_private_gateway_endpoint(&args.gateway_endpoint)?;
    Ok(())
}

fn validate_private_gateway_endpoint(raw: &str) -> Result<(), Box<dyn Error>> {
    let endpoint = Url::parse(raw)?;
    if endpoint.scheme() != "http" {
        return Err("signer gateway must use private-network HTTP".into());
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("signer gateway URL must not contain credentials".into());
    }
    let host = endpoint
        .host_str()
        .ok_or("signer gateway host is required")?;
    let allowed = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| match ip {
                IpAddr::V4(value) => value.is_private() || value.is_loopback(),
                IpAddr::V6(value) => {
                    value.is_unique_local() || value.is_unicast_link_local() || value.is_loopback()
                }
            })
            .unwrap_or(false);
    if !allowed {
        return Err("signer gateway must be a loopback or private-network address".into());
    }
    Ok(())
}

async fn build_plan(
    args: &Args,
    verifier: &DualRpcVerifier,
    public_key: &[u8],
    day: &str,
) -> Result<SweepPlan, Box<dyn Error>> {
    let source = script_hash_from_public_key(public_key)?;
    let destination = parse_neo3_address_to_script_hash(&args.destination)?;
    let idempotency_key = format!("gas-sweep/{day}");
    let policy = build_deploy_policy(
        args.network,
        true,
        public_key.to_vec(),
        Some(&args.destination),
        None,
    )?;

    for _ in 0..5 {
        let chain = verifier.read_chain_state(&source).await?;
        if chain.safe_balance <= args.reserve {
            return Ok(no_op_plan(args, day, &source, &destination));
        }

        let valid_until = chain
            .min_height
            .checked_add(args.valid_for_blocks)
            .ok_or("valid-until height overflow")?;
        let nonce = random_nonce()?;
        let mut system_fee = 0u64;
        let mut network_fee = 0u64;

        for _ in 0..6 {
            let fee_total = system_fee.checked_add(network_fee).ok_or("fee overflow")?;
            let Some(amount) = chain
                .safe_balance
                .checked_sub(args.reserve)
                .and_then(|value| value.checked_sub(fee_total))
                .filter(|value| *value > 0)
            else {
                return Ok(no_op_plan(args, day, &source, &destination));
            };
            let script = build_gas_transfer_script(&source, &destination, amount);
            let raw = encode_unsigned_transaction(
                nonce,
                system_fee,
                network_fee,
                valid_until,
                &source,
                &script,
            );
            let tx = decode_unsigned_transaction(&raw)?;
            let estimate = verifier.estimate_transaction(&tx, public_key).await?;
            if estimate.safe_balance < chain.safe_balance {
                break;
            }
            let estimated_total = estimate
                .system_fee
                .checked_add(estimate.network_fee)
                .ok_or("estimated fee overflow")?;
            if estimated_total > FEE_CAP_FRACTIONS {
                return Err("dual-RPC fee estimate exceeds the signer fee cap".into());
            }
            if system_fee == estimate.system_fee && network_fee == estimate.network_fee {
                let verified = verifier.verify_transaction(&tx, public_key).await?;
                if verified.safe_balance < chain.safe_balance {
                    break;
                }
                policy.validate_sign_transaction(GasSweepValidationRequest {
                    raw_tx: &raw,
                    public_key,
                    network: args.network,
                    idempotency_key: &idempotency_key,
                    expected_amount: amount,
                    expected_fee_total: estimated_total,
                    asserted_safe_balance: Some(verified.safe_balance),
                })?;
                return Ok(SweepPlan {
                    version: PLAN_VERSION,
                    day: day.to_owned(),
                    created_at: Utc::now().to_rfc3339(),
                    network: args.network,
                    source_script_hash: source.to_string(),
                    destination_script_hash: destination.to_string(),
                    unsigned_tx_base64: BASE64.encode(&raw),
                    expected_amount: amount,
                    expected_fee_total: estimated_total,
                    transaction_hash: transaction_hash(&tx),
                    signature_base64: None,
                    broadcast_hash: None,
                    status: PlanStatus::Planned,
                });
            }
            system_fee = estimate.system_fee;
            network_fee = estimate.network_fee;
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    Err("chain state changed repeatedly while constructing the sweep".into())
}

fn no_op_plan(
    args: &Args,
    day: &str,
    source: &secure_sign_core::h160::H160,
    destination: &secure_sign_core::h160::H160,
) -> SweepPlan {
    SweepPlan {
        version: PLAN_VERSION,
        day: day.to_owned(),
        created_at: Utc::now().to_rfc3339(),
        network: args.network,
        source_script_hash: source.to_string(),
        destination_script_hash: destination.to_string(),
        unsigned_tx_base64: String::new(),
        expected_amount: 0,
        expected_fee_total: 0,
        transaction_hash: String::new(),
        signature_base64: None,
        broadcast_hash: None,
        status: PlanStatus::NoOp,
    }
}

async fn request_signature(
    args: &Args,
    plan: &SweepPlan,
    public_key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let endpoint = Endpoint::from_shared(args.gateway_endpoint.clone())?
        .connect_timeout(Duration::from_millis(args.gateway_timeout_ms))
        .timeout(Duration::from_millis(args.gateway_timeout_ms));
    let channel = endpoint.connect().await?;
    let mut client = SecureSignClient::new(channel);
    let response = client
        .sign_transaction(SignTransactionRequest {
            raw_tx: BASE64.decode(plan.unsigned_tx_base64.as_bytes())?,
            public_key: public_key.to_vec(),
            network: args.network,
            idempotency_key: format!("gas-sweep/{}", plan.day),
            client_dry_run_id: format!("daily/{}", plan.day),
            expected_amount: plan.expected_amount,
            expected_fee_total: plan.expected_fee_total,
        })
        .await?
        .into_inner();
    if response.signature.len() != ECC256_SIGN_SIZE {
        return Err("signer returned an invalid signature length".into());
    }
    let expected_tx_hash = tx_hash_le_from_string(&plan.transaction_hash)?;
    if response.tx_hash != expected_tx_hash {
        return Err("signer returned a transaction hash mismatch".into());
    }
    Ok(response.signature)
}

fn verify_signature(
    public_key: &[u8],
    network: u32,
    tx: &UnsignedTransaction,
    signature: &[u8],
) -> Result<(), Box<dyn Error>> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| "signer public key is not a valid P-256 point")?;
    let signature =
        Signature::from_slice(signature).map_err(|_| "signer returned invalid P-256 signature")?;
    verifying_key
        .verify(&tx.hash_data.to_sign_data(network), &signature)
        .map_err(|_| "signer signature failed local verification")?;
    Ok(())
}

async fn wait_for_confirmation(
    verifier: &DualRpcVerifier,
    transaction_hash: &str,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let started = tokio::time::Instant::now();
    loop {
        if let Some(log) = verifier.application_log(transaction_hash).await? {
            validate_confirmation(&log, transaction_hash)?;
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err("timed out waiting for on-chain application log".into());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn confirm_plan_from_log(
    plan: &mut SweepPlan,
    log: Option<&Value>,
) -> Result<bool, Box<dyn Error>> {
    let Some(log) = log else {
        return Ok(false);
    };
    validate_confirmation(log, &plan.transaction_hash)?;
    plan.broadcast_hash = Some(plan.transaction_hash.clone());
    plan.status = PlanStatus::Confirmed;
    Ok(true)
}

fn validate_confirmation(log: &Value, expected_hash: &str) -> Result<(), Box<dyn Error>> {
    let hash = log
        .get("txid")
        .and_then(Value::as_str)
        .ok_or("application log has no transaction ID")?;
    if tx_hash_le_from_string(hash)? != tx_hash_le_from_string(expected_hash)? {
        return Err("application log transaction ID does not match the sweep".into());
    }
    let executions = log
        .get("executions")
        .and_then(Value::as_array)
        .ok_or("application log has no executions")?;
    if executions.is_empty() {
        return Err("application log has no executions".into());
    }
    for execution in executions {
        if execution
            .get("vmstate")
            .or_else(|| execution.get("state"))
            .and_then(Value::as_str)
            != Some("HALT")
        {
            return Err("sweep transaction entered a non-HALT VM state".into());
        }
        let stack = execution
            .get("stack")
            .and_then(Value::as_array)
            .ok_or("application log has no transfer result")?;
        if stack.len() != 1
            || stack[0].get("type").and_then(Value::as_str) != Some("Boolean")
            || stack[0].get("value").and_then(Value::as_bool) != Some(true)
        {
            return Err("sweep transfer did not return true".into());
        }
    }
    Ok(())
}

fn shanghai_day() -> String {
    let offset = FixedOffset::east_opt(8 * 60 * 60).expect("valid fixed UTC offset");
    Utc::now()
        .with_timezone(&offset)
        .format("%Y-%m-%d")
        .to_string()
}

fn random_nonce() -> Result<u32, Box<dyn Error>> {
    let mut bytes = [0u8; 4];
    EnvCryptRandom
        .try_fill_bytes(&mut bytes)
        .map_err(|err| format!("operating-system randomness unavailable: {err}"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn transaction_hash(tx: &UnsignedTransaction) -> String {
    let mut bytes = tx.tx_hash_le();
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}

fn tx_hash_le_from_string(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = hex::decode(value.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        return Err("transaction hash must be 32 bytes".into());
    }
    bytes.reverse();
    Ok(bytes)
}

fn normalize_hash(value: &str) -> String {
    value.trim_start_matches("0x").to_ascii_lowercase()
}

fn validate_saved_plan(
    plan: &SweepPlan,
    args: &Args,
    source: &str,
    destination: &str,
) -> Result<(), Box<dyn Error>> {
    if plan.version != PLAN_VERSION
        || plan.network != args.network
        || plan.source_script_hash != source
        || plan.destination_script_hash != destination
    {
        return Err("saved sweep plan does not match the active signer configuration".into());
    }
    if plan.status == PlanStatus::NoOp {
        return Ok(());
    }
    let raw = BASE64.decode(plan.unsigned_tx_base64.as_bytes())?;
    let tx = decode_unsigned_transaction(&raw)?;
    if transaction_hash(&tx) != plan.transaction_hash
        || tx.fee_total() != Some(plan.expected_fee_total)
    {
        return Err("saved sweep plan failed its integrity check".into());
    }
    Ok(())
}

fn load_plan(path: &Path) -> Result<Option<SweepPlan>, Box<dyn Error>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(Some(serde_json::from_slice(&content)?))
}

fn save_plan(path: &Path, plan: &SweepPlan) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or("state path must have a parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("gas-sweep-plan"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    serde_json::to_writer(&mut file, plan)?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn print_result(plan: &SweepPlan, broadcast: bool) -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        serde_json::to_string(&CommandResult {
            status: plan.status,
            day: &plan.day,
            transaction_hash: &plan.transaction_hash,
            amount_fractions: plan.expected_amount,
            fee_fractions: plan.expected_fee_total,
            broadcast,
        })?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn pending_plan(status: PlanStatus) -> SweepPlan {
        SweepPlan {
            version: PLAN_VERSION,
            day: "2026-09-05".to_owned(),
            created_at: "2026-09-05T01:00:00Z".to_owned(),
            network: GAS_SWEEP_NETWORK_MAGIC,
            source_script_hash: format!("0x{}", "11".repeat(20)),
            destination_script_hash: format!("0x{}", "22".repeat(20)),
            unsigned_tx_base64: "AA==".to_owned(),
            expected_amount: 1,
            expected_fee_total: 2,
            transaction_hash: format!("0x{}", "33".repeat(32)),
            signature_base64: Some("signed-bytes-unchanged".to_owned()),
            broadcast_hash: None,
            status,
        }
    }

    fn successful_log(plan: &SweepPlan) -> Value {
        json!({
            "txid": plan.transaction_hash,
            "executions": [{"trigger":"Application", "vmstate":"HALT",
                "stack":[{"type":"Boolean", "value":true}]}]
        })
    }

    #[test]
    fn pending_plan_reconciles_without_changing_signed_transaction() {
        for status in [
            PlanStatus::Planned,
            PlanStatus::Signed,
            PlanStatus::Broadcast,
        ] {
            let mut plan = pending_plan(status);
            let log = successful_log(&plan);
            assert!(confirm_plan_from_log(&mut plan, Some(&log)).unwrap());
            assert_eq!(plan.status, PlanStatus::Confirmed);
            assert_eq!(
                plan.broadcast_hash.as_deref(),
                Some(plan.transaction_hash.as_str())
            );
            assert_eq!(plan.unsigned_tx_base64, "AA==");
            assert_eq!(
                plan.signature_base64.as_deref(),
                Some("signed-bytes-unchanged")
            );
            let dir = tempdir().unwrap();
            let path = dir.path().join("plan.json");
            save_plan(&path, &plan).unwrap();
            let saved = load_plan(&path).unwrap().unwrap();
            assert_eq!(saved.status, PlanStatus::Confirmed);
            assert_eq!(saved.broadcast_hash, plan.broadcast_hash);
        }
    }

    #[test]
    fn missing_log_leaves_plan_pending() {
        let mut plan = pending_plan(PlanStatus::Signed);
        assert!(!confirm_plan_from_log(&mut plan, None).unwrap());
        assert_eq!(plan.status, PlanStatus::Signed);
        assert!(plan.broadcast_hash.is_none());
    }

    #[test]
    fn invalid_confirmation_never_marks_plan_successful() {
        let original = pending_plan(PlanStatus::Signed);
        let valid = successful_log(&original);
        let mut invalid = Vec::new();
        for txid in [
            Value::Null,
            json!(format!("0x{}", "44".repeat(32))),
            json!("malformed"),
        ] {
            let mut log = valid.clone();
            log["txid"] = txid;
            invalid.push(log);
        }
        for state in ["FAULT", "NONE"] {
            let mut log = valid.clone();
            log["executions"][0]["vmstate"] = json!(state);
            invalid.push(log);
        }
        for stack in [
            json!([]),
            json!([{"type":"Boolean","value":false}]),
            json!([{"type":"Boolean","value":"true"}]),
            json!([{"type":"Integer","value":"1"}]),
        ] {
            let mut log = valid.clone();
            log["executions"][0]["stack"] = stack;
            invalid.push(log);
        }
        let mut empty = valid.clone();
        empty["executions"] = json!([]);
        invalid.push(empty);
        for log in invalid {
            let mut plan = pending_plan(PlanStatus::Signed);
            assert!(confirm_plan_from_log(&mut plan, Some(&log)).is_err());
            assert_eq!(plan.status, PlanStatus::Signed);
            assert!(plan.broadcast_hash.is_none());
        }
    }

    #[test]
    fn gateway_must_be_private_http() {
        assert!(validate_private_gateway_endpoint("http://10.78.0.1:9991").is_ok());
        assert!(validate_private_gateway_endpoint("http://127.0.0.1:9991").is_ok());
        assert!(validate_private_gateway_endpoint("https://10.78.0.1:9991").is_err());
        assert!(validate_private_gateway_endpoint("http://203.0.113.10:9991").is_err());
    }

    #[test]
    fn plan_file_is_compact_private_and_round_trips() {
        let dir = tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("plan.json");
        let _lock = ProcessLock::acquire(&path).unwrap();
        let plan = SweepPlan {
            version: PLAN_VERSION,
            day: "2026-09-04".to_owned(),
            created_at: "2026-09-04T00:00:00Z".to_owned(),
            network: GAS_SWEEP_NETWORK_MAGIC,
            source_script_hash: "0x11".to_owned(),
            destination_script_hash: "0x22".to_owned(),
            unsigned_tx_base64: "AA==".to_owned(),
            expected_amount: 1,
            expected_fee_total: 2,
            transaction_hash: "0x33".to_owned(),
            signature_base64: None,
            broadcast_hash: None,
            status: PlanStatus::Planned,
        };
        save_plan(&path, &plan).unwrap();
        let loaded = load_plan(&path).unwrap().unwrap();
        assert_eq!(loaded.day, plan.day);
        assert_eq!(loaded.status, plan.status);
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let parent_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o755);
    }

    #[test]
    fn hash_conversion_preserves_neo_endianness() {
        let text = format!("0x{}", "01".repeat(32));
        assert_eq!(tx_hash_le_from_string(&text).unwrap(), vec![1u8; 32]);
    }

    #[test]
    fn transaction_id_matches_neo_display_order() {
        let raw = hex::decode(
            "0001000000010000000000000001000000000000006400000001\
             000000000000000000000000000000000000000001000140",
        )
        .unwrap();
        let tx = decode_unsigned_transaction(&raw).unwrap();
        assert_eq!(
            transaction_hash(&tx),
            "0x95a18dd27030bfe4d794844797b970796446196da4f9588d120487c915ac6f16"
        );
    }
}
