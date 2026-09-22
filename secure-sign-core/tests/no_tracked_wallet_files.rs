//! Repo hygiene gate: no wallet material may ever be tracked by git.
//!
//! Provenance: `secure-sign/config/nep6_wallet.json` was committed on this
//! repository — a NEP-6 wallet with 2 accounts and scrypt cost `n=64, r=2, p=2`
//! (`NEP-2` default is `n=16384, r=8, p=8`, roughly 256x stronger). That is a
//! live custody credential sitting in history. It is now untracked and ignored;
//! this test is the regression gate that keeps it, and anything shaped like it,
//! out of the index.
//!
//! Scope of the rule, per category:
//!
//! * `*.neopkg` — NeoPkg package archives can embed key material.
//! * keystore files (`*keystore*`, `.keystore`, `.p12`, `.pfx`, `.jks`, and
//!   keystore-shaped JSON) — encrypted private-key containers.
//! * `.json` wallet documents with scrypt/NEP-2 fields — NEP-6 wallets and any
//!   other JSON keystore carrying an encrypted private key.
//!
//! Failure output names the PATH and the rule that matched. It must never print
//! file contents: a hit is key material.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Top of the repository this test lives in (`secure-sign-core/..`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secure-sign-core must live in the workspace root")
        .to_path_buf()
}

/// Every path git currently tracks, as repo-relative strings with `/` separators.
///
/// Fail-closed: if git cannot answer, the gate cannot claim the index is clean.
fn tracked_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .map_err(|err| format!("failed to run `git ls-files` (fail-closed): {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "`git ls-files` exited with {} (fail-closed): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| "`git ls-files` returned non-UTF-8 paths".to_string())?
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Name-level rules. Returns the rule text when the path alone is wallet material.
fn wallet_rule_by_name(path: &str) -> Option<&'static str> {
    let name = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();

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

/// Content rules for tracked JSON: a wallet/keystore document, not a config or
/// schema that merely talks about wallets.
///
/// Matches:
/// * a `scrypt` parameter object with an `n` cost field (NEP-6 wallet header);
/// * a NEP-2 encrypted private key (`nep2` field, or a `key` value with the
///   NEP-2 `6P` prefix);
/// * a keystore JSON (`crypto`/`Crypto` carrying `ciphertext`/`cipher`).
fn wallet_rule_by_json_content(text: &str) -> Option<&'static str> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return None;
    };
    let Some(object) = value.as_object() else {
        return None;
    };

    if let Some(scrypt) = object.get("scrypt").and_then(|s| s.as_object()) {
        if scrypt.contains_key("n") {
            return Some(".json wallet with scrypt cost fields (NEP-6)");
        }
    }

    if object.contains_key("nep2") {
        return Some(".json wallet with nep2 field");
    }

    if let Some(accounts) = object.get("accounts").and_then(|a| a.as_array()) {
        for account in accounts {
            let Some(key) = account.get("key").and_then(|k| k.as_str()) else {
                continue;
            };
            // NEP-2 encrypted keys are base58 and start with "6P".
            if key.starts_with("6P") && key.len() >= 50 {
                return Some(".json wallet with NEP-2 encrypted private key");
            }
            if account.get("nep2").is_some() {
                return Some(".json wallet with nep2 field");
            }
        }
    }

    for crypto_key in ["crypto", "Crypto"] {
        let Some(crypto) = object.get(crypto_key).and_then(|c| c.as_object()) else {
            continue;
        };
        if crypto.contains_key("ciphertext") || crypto.contains_key("cipher") {
            return Some("keystore JSON (encrypted key material)");
        }
    }

    None
}

/// The single classification entry point the gate runs over every tracked path.
fn wallet_rule(path: &str, contents: Option<&str>) -> Option<&'static str> {
    if let Some(rule) = wallet_rule_by_name(path) {
        return Some(rule);
    }
    if path.to_ascii_lowercase().ends_with(".json") {
        return wallet_rule_by_json_content(contents.unwrap_or_default());
    }
    None
}

/// Tracked wallet material, as `"<path> — <rule>"`. Empty means the index is clean.
fn tracked_wallet_violations(root: &Path) -> Result<Vec<String>, String> {
    let mut violations = Vec::new();
    for path in tracked_files(root)? {
        let contents = if path.to_ascii_lowercase().ends_with(".json") {
            match std::fs::read_to_string(root.join(&path)) {
                Ok(text) => Some(text),
                // Unreadable on disk but tracked: only name rules can apply, and
                // a JSON we cannot read cannot be proven clean. Treat as a hit
                // so the gate never passes on data it did not inspect.
                Err(_) => {
                    violations.push(format!("{path} — tracked .json that cannot be read"));
                    continue;
                }
            }
        } else {
            None
        };
        if let Some(rule) = wallet_rule(&path, contents.as_deref()) {
            violations.push(format!("{path} — {rule}"));
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic NEP-6 header only — no key material, obviously fake cost fields.
    #[test]
    fn detects_scrypt_wallet_json() {
        let text = r#"{"name":"synthetic","version":"1.0","scrypt":{"n":64,"r":2,"p":2},"accounts":[]}"#;
        assert_eq!(
            wallet_rule("any/place/w.json", Some(text)),
            Some(".json wallet with scrypt cost fields (NEP-6)")
        );
    }

    #[test]
    fn detects_neop2_key_field_by_name_and_value() {
        let text = r#"{"accounts":[{"key":"6PFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1"}]}"#;
        assert_eq!(
            wallet_rule("any/place/w.json", Some(text)),
            Some(".json wallet with NEP-2 encrypted private key")
        );
    }

    #[test]
    fn detects_keystore_json_and_filenames() {
        let text = r#"{"crypto":{"cipher":"aes-128-ctr","ciphertext":"00"}}"#;
        assert_eq!(
            wallet_rule("wallets/a.json", Some(text)),
            Some("keystore JSON (encrypted key material)")
        );
        assert_eq!(
            wallet_rule("wallets/UTC--synthetic--x.json", Some("{}")),
            Some("keystore file (name)")
        );
        assert_eq!(
            wallet_rule("somewhere/nep6_wallet.json", Some("{}")),
            Some("NEP-6 wallet file (name)")
        );
        assert_eq!(
            wallet_rule("packages/game.neopkg", None),
            Some("NeoPkg package archive (.neopkg)")
        );
    }

    #[test]
    fn clean_files_are_not_flagged() {
        let clean = r#"{"schema":"signing-recovery.v1","fields":{"scrypt_note":"docs only"}}"#;
        assert_eq!(wallet_rule("docs/api/x.json", Some(clean)), None);
        assert_eq!(wallet_rule("secure-sign-core/src/neo/nep2.rs", None), None);
        assert_eq!(wallet_rule("docs/api/signing-recovery.v1.json", Some("{}")), None);
    }

    /// The gate itself: the git index must contain no wallet material. Fails
    /// with the offending paths (never their contents) when it does.
    #[test]
    fn no_wallet_material_is_tracked_by_git() {
        let root = repo_root();
        let violations = tracked_wallet_violations(&root)
            .expect("wallet-tracking gate must be able to read the git index (fail-closed)");
        assert!(
            violations.is_empty(),
            "wallet material must never be tracked by git. \
             Untrack these paths (`git rm --cached <path>`) and add them to .gitignore; \
             history is rewritten by the owner only. Violations (path — rule):\n{}",
            violations.join("\n")
        );
    }
}
