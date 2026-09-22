//! Repo hygiene gate: no wallet material may ever be tracked by git.
//!
//! Provenance: `secure-sign/config/nep6_wallet.json` was tracked on this
//! repository - a NEP-6 test fixture with 2 accounts and scrypt cost
//! `n=64, r=2, p=2`. Both accounts decrypt with the passphrase `xyz` that the
//! crate's own unit tests publish, and account 1's private key is the test key
//! `0x01` x 32, so it never held a secret. It was untracked anyway, because the
//! README pointed operators at that exact path: a signer started from it signs
//! with publicly known keys. This test keeps it, and anything shaped like it,
//! out of the index.
//!
//! What the gate inspects, and why each part exists:
//!
//! * **Staged blobs, not working-tree files.** Content comes from
//!   `git cat-file --batch` over `git ls-files -s`. Reading the working tree let
//!   a staged wallet pass once the file on disk was overwritten with `{}`.
//! * **Every tracked file, whatever its extension.** A NEP-2 encrypted key
//!   (`6P` + 56 base58 characters) is detected in any blob. Content rules that
//!   only looked at `.json` let `.txt` and `.wallet` copies through.
//! * **Any JSON document, at any depth.** Wallet structure (`scrypt{n}`,
//!   `nep2`, `crypto{ciphertext|cipher}`) is searched recursively, so a wallet
//!   wrapped in a top-level array or nested inside another object is still
//!   found.
//! * **Name rules** for archives and keystores that are opaque to content rules.
//!
//! Two NEP-2 strings are tracked on purpose: they are published test vectors,
//! and each is allowlisted by the SHA-256 of the key string, with its reason.
//! Any other NEP-2 key anywhere in the index fails the gate.
//!
//! Failure output names the PATH and the rule that matched. It must never print
//! file contents: a hit is key material.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

/// Published NEP-2 test vectors that this repository tracks deliberately,
/// keyed by the SHA-256 (hex) of the 58-character key string.
const ALLOWLISTED_NEP2_TEST_VECTORS: &[(&str, &str)] = &[
    (
        "5d1da8d4b5ef877473f7ca0cfa731fc7d97e8305bfbd31a783f61c980a44adaa",
        "NEP-2 test vector: passphrase `xyz`, scrypt n=64 r=2 p=2, private key 0x01 x 32 \
         (secure-sign-core/src/neo/nep2.rs test_nep2_key_simplified; \
         secure-sign-rpc/src/startup.rs wallet fixture)",
    ),
    (
        "2eb97e8bc6279365c4b0d198bca8473fa0ce49375a3cdeb60a7b4fa560017262",
        "NEP-2 test vector: passphrase `city of zion`, default scrypt params \
         (secure-sign-core/src/neo/nep2.rs test_nep2_key_default_params)",
    ),
];

/// Top of the repository this test lives in (`secure-sign-core/..`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secure-sign-core must live in the workspace root")
        .to_path_buf()
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|err| {
            format!(
                "failed to run `git {}` (fail-closed): {err}",
                args.join(" ")
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "`git {}` exited with {} (fail-closed): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

/// Every tracked path with the object id of its STAGED blob.
///
/// Gitlinks (submodules, mode 160000) point at commits, not blobs, and carry
/// no content of their own here.
fn staged_entries(root: &Path) -> Result<Vec<(String, String)>, String> {
    let raw = git(root, &["ls-files", "-s", "-z"])?;
    let text = String::from_utf8(raw)
        .map_err(|_| "`git ls-files` returned non-UTF-8 paths".to_string())?;
    let mut entries = Vec::new();
    for record in text.split('\0').filter(|record| !record.is_empty()) {
        let (meta, path) = record.split_once('\t').ok_or_else(|| {
            format!("unparseable `git ls-files -s` record (fail-closed): {record:?}")
        })?;
        let mut fields = meta.split_whitespace();
        let mode = fields.next().unwrap_or_default();
        let object = fields.next().unwrap_or_default().to_string();
        if mode == "160000" {
            continue;
        }
        if object.is_empty() {
            return Err(format!(
                "`git ls-files -s` gave no object id for {path} (fail-closed)"
            ));
        }
        entries.push((path.to_string(), object));
    }
    Ok(entries)
}

/// Content of each object id, read from the object database in one batch.
fn blob_contents(root: &Path, objects: &[String]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run `git cat-file --batch` (fail-closed): {err}"))?;

    let mut stdin = child.stdin.take().expect("piped stdin");
    let requests: Vec<String> = objects.to_vec();
    // Written from a thread so a large response can never deadlock against a
    // full input pipe.
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        for object in requests {
            stdin.write_all(object.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        Ok(())
    });

    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut contents = BTreeMap::new();
    for object in objects {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|err| format!("reading `git cat-file` header failed (fail-closed): {err}"))?;
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() != 3 || parts[1] == "missing" {
            return Err(format!(
                "`git cat-file` could not read {object} (fail-closed): {header:?}"
            ));
        }
        let size: usize = parts[2]
            .parse()
            .map_err(|_| format!("`git cat-file` gave a bad size for {object} (fail-closed)"))?;
        let mut body = vec![0u8; size];
        reader
            .read_exact(&mut body)
            .map_err(|err| format!("reading blob {object} failed (fail-closed): {err}"))?;
        let mut newline = [0u8; 1];
        reader
            .read_exact(&mut newline)
            .map_err(|err| format!("reading blob terminator failed (fail-closed): {err}"))?;
        contents.insert(object.clone(), body);
    }
    writer
        .join()
        .map_err(|_| "`git cat-file` writer thread panicked (fail-closed)".to_string())?
        .map_err(|err| format!("writing to `git cat-file` failed (fail-closed): {err}"))?;
    let status = child
        .wait()
        .map_err(|err| format!("waiting for `git cat-file` failed (fail-closed): {err}"))?;
    if !status.success() {
        return Err(format!(
            "`git cat-file --batch` exited with {status} (fail-closed)"
        ));
    }
    Ok(contents)
}

/// Name-level rules. Returns the rule text when the path alone is wallet material.
fn wallet_rule_by_name(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();

    if name.ends_with(".neopkg") {
        return Some("NeoPkg package archive (.neopkg)");
    }
    if name.ends_with(".keystore")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || name.ends_with(".jks")
        || name.contains("keystore")
        // geth/ethereum keystores carry no "keystore" in the name at all:
        // they are `UTC--<timestamp>--<address>`.
        || name.starts_with("utc--")
    {
        return Some("keystore file (name)");
    }
    if name.ends_with(".nep6.json")
        || name == "nep6_wallet.json"
        || name == "nep6-wallet.json"
        || name == "nep6wallet.json"
    {
        return Some("NEP-6 wallet file (name)");
    }
    None
}

fn is_base58(byte: u8) -> bool {
    matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

/// Every NEP-2 encrypted key in `bytes`: `6P` followed by exactly 56 base58
/// characters, not embedded in a longer base58 run.
fn nep2_keys(bytes: &[u8]) -> Vec<String> {
    const LEN: usize = 58;
    let mut keys = Vec::new();
    let mut index = 0;
    while index + LEN <= bytes.len() {
        let starts = bytes[index] == b'6' && bytes[index + 1] == b'P';
        let bounded_left = index == 0 || !is_base58(bytes[index - 1]);
        if starts && bounded_left {
            let candidate = &bytes[index..index + LEN];
            let bounded_right = index + LEN == bytes.len() || !is_base58(bytes[index + LEN]);
            if bounded_right && candidate.iter().all(|byte| is_base58(*byte)) {
                keys.push(String::from_utf8_lossy(candidate).into_owned());
                index += LEN;
                continue;
            }
        }
        index += 1;
    }
    keys
}

fn fingerprint(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_allowlisted_test_vector(key: &str) -> bool {
    let print = fingerprint(key);
    ALLOWLISTED_NEP2_TEST_VECTORS
        .iter()
        .any(|(allowed, _)| *allowed == print)
}

/// Wallet structure anywhere inside a JSON value.
fn wallet_rule_in_json(value: &serde_json::Value) -> Option<&'static str> {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(scrypt) = object.get("scrypt").and_then(|s| s.as_object()) {
                if scrypt.get("n").is_some_and(serde_json::Value::is_number) {
                    return Some("JSON wallet with scrypt cost fields (NEP-6)");
                }
            }
            if object.contains_key("nep2") {
                return Some("JSON wallet with nep2 field");
            }
            for crypto_key in ["crypto", "Crypto"] {
                if let Some(crypto) = object.get(crypto_key).and_then(|c| c.as_object()) {
                    let cipher_text = crypto
                        .get("ciphertext")
                        .is_some_and(serde_json::Value::is_string);
                    let cipher = crypto
                        .get("cipher")
                        .is_some_and(serde_json::Value::is_string);
                    if cipher_text || cipher {
                        return Some("keystore JSON (encrypted key material)");
                    }
                }
            }
            object.values().find_map(wallet_rule_in_json)
        }
        serde_json::Value::Array(items) => items.iter().find_map(wallet_rule_in_json),
        _ => None,
    }
}

/// The single classification entry point the gate runs over every staged blob.
/// Returns every rule that matched (a file can break more than one).
fn wallet_rules(path: &str, contents: &[u8]) -> Vec<&'static str> {
    let mut rules = Vec::new();
    if let Some(rule) = wallet_rule_by_name(path) {
        rules.push(rule);
    }
    if nep2_keys(contents)
        .iter()
        .any(|key| !is_allowlisted_test_vector(key))
    {
        rules.push("NEP-2 encrypted private key (not an allowlisted test vector)");
    }
    if let Ok(text) = std::str::from_utf8(contents) {
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(rule) = wallet_rule_in_json(&value) {
                    rules.push(rule);
                }
            }
        }
    }
    rules
}

/// Tracked wallet material in the git index of `root`, as `"<path> - <rule>"`.
/// Empty means the index is clean.
fn staged_wallet_violations(root: &Path) -> Result<Vec<String>, String> {
    let entries = staged_entries(root)?;
    let objects: Vec<String> = entries.iter().map(|(_, object)| object.clone()).collect();
    let contents = blob_contents(root, &objects)?;
    let mut violations = Vec::new();
    for (path, object) in entries {
        let blob = contents
            .get(&object)
            .ok_or_else(|| format!("no content read for {path} (fail-closed)"))?;
        for rule in wallet_rules(&path, blob) {
            violations.push(format!("{path} - {rule}"));
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A NEP-2-shaped key that is NOT an allowlisted vector. Built at runtime so
    /// this file never contains a contiguous key string of its own.
    fn fresh_nep2_key() -> String {
        format!("6P{}", "Zb".repeat(28))
    }

    fn synthetic_wallet() -> String {
        format!(
            r#"{{"name":"synthetic","version":"1.0","scrypt":{{"n":64,"r":2,"p":2}},"accounts":[{{"address":"x","key":"{}"}}]}}"#,
            fresh_nep2_key()
        )
    }

    #[test]
    fn detects_a_wallet_by_structure_and_key() {
        let rules = wallet_rules("any/place/w.json", synthetic_wallet().as_bytes());
        assert!(
            rules.contains(&"JSON wallet with scrypt cost fields (NEP-6)"),
            "{rules:?}"
        );
        assert!(
            rules.contains(&"NEP-2 encrypted private key (not an allowlisted test vector)"),
            "{rules:?}"
        );
    }

    /// Evasion 1 and 2: the old gate only content-scanned `.json`.
    #[test]
    fn detects_a_wallet_whatever_its_extension() {
        for path in ["notes/w.txt", "ops/signer.wallet", "no_extension"] {
            let rules = wallet_rules(path, synthetic_wallet().as_bytes());
            assert!(!rules.is_empty(), "{path} must be flagged");
        }
        let bare_key = format!("backup: {}\n", fresh_nep2_key());
        assert!(!wallet_rules("notes/key.txt", bare_key.as_bytes()).is_empty());
    }

    /// Evasion 3: a wallet wrapped in a top-level array.
    #[test]
    fn detects_a_wallet_inside_a_top_level_array() {
        let wrapped = format!(r#"[{}]"#, synthetic_wallet());
        let rules = wallet_rules("w.json", wrapped.as_bytes());
        assert!(
            rules.contains(&"JSON wallet with scrypt cost fields (NEP-6)"),
            "{rules:?}"
        );
    }

    /// Evasion 4: a wallet nested inside another object.
    #[test]
    fn detects_a_wallet_nested_inside_an_object() {
        let nested = format!(
            r#"{{"deploy":{{"signer":{{"wallet":{}}}}}}}"#,
            synthetic_wallet()
        );
        let rules = wallet_rules("config/deploy.json", nested.as_bytes());
        assert!(
            rules.contains(&"JSON wallet with scrypt cost fields (NEP-6)"),
            "{rules:?}"
        );

        let keystore = r#"{"outer":[{"crypto":{"cipher":"aes-128-ctr","ciphertext":"00"}}]}"#;
        assert!(wallet_rules("k.json", keystore.as_bytes())
            .contains(&"keystore JSON (encrypted key material)"));
    }

    #[test]
    fn allowlists_only_the_published_test_vectors() {
        // A key embedded in a longer base58 run is not a key.
        let embedded = format!("x{}y", fresh_nep2_key());
        assert!(nep2_keys(embedded.as_bytes()).is_empty());
        // A fresh key is never on the allowlist.
        assert!(!is_allowlisted_test_vector(&fresh_nep2_key()));
        assert_eq!(ALLOWLISTED_NEP2_TEST_VECTORS.len(), 2);
    }

    #[test]
    fn clean_files_are_not_flagged() {
        let schema = r#"{"schema":"signing-recovery.v1","scrypt":{"n":{"type":"integer"}},"scrypt_note":"docs only"}"#;
        assert!(wallet_rules("docs/api/x.json", schema.as_bytes()).is_empty());
        assert!(wallet_rules("secure-sign-core/src/lib.rs", b"pub mod neo;").is_empty());
        assert_eq!(
            wallet_rules("packages/game.neopkg", b""),
            vec!["NeoPkg package archive (.neopkg)"]
        );
        assert_eq!(
            wallet_rules("wallets/UTC--synthetic--x", b"{}"),
            vec!["keystore file (name)"]
        );
    }

    /// Evasion 5: stage a wallet, then overwrite the working-tree file with
    /// `{}`. The index still carries the wallet, and the gate must see it.
    #[test]
    fn reads_the_staged_blob_not_the_working_tree() {
        let dir = std::env::temp_dir().join(format!(
            "no-tracked-wallet-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("temp repo dir");
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .status()
                .expect("git runs");
            assert!(status.success(), "git {args:?} failed");
        };
        run(&["init", "-q"]);
        std::fs::write(dir.join("innocent.txt"), synthetic_wallet()).expect("write wallet");
        run(&["add", "innocent.txt"]);
        std::fs::write(dir.join("innocent.txt"), "{}").expect("overwrite working tree");

        let violations = staged_wallet_violations(&dir).expect("gate reads the temp index");
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            violations
                .iter()
                .any(|violation| violation.starts_with("innocent.txt - ")),
            "a staged wallet must be caught even when the working tree is clean: {violations:?}"
        );
    }

    /// The gate itself: this repository's index must contain no wallet
    /// material. Fails with the offending paths (never their contents).
    #[test]
    fn no_wallet_material_is_tracked_by_git() {
        let root = repo_root();
        let violations = staged_wallet_violations(&root)
            .expect("wallet-tracking gate must be able to read the git index (fail-closed)");
        assert!(
            violations.is_empty(),
            "wallet material must never be tracked by git. \
             Untrack these paths (`git rm --cached <path>`) and add them to .gitignore; \
             history is rewritten by the owner only. Violations (path - rule):\n{}",
            violations.join("\n")
        );
    }
}
