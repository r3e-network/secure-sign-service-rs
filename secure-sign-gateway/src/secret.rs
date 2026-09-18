// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;

/// Load a secret from exactly one of: file descriptor, secret file, or env.
/// Command-line argv is intentionally not a source.
pub fn load_secret(
    fd: Option<i32>,
    file: Option<&Path>,
    env_value: Option<String>,
    env_name: &str,
) -> Result<String, String> {
    let sources = u8::from(fd.is_some())
        + u8::from(file.is_some())
        + u8::from(
            env_value
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        );
    if sources == 0 {
        return Err(format!(
            "{env_name}, {env_name}_FILE, or {env_name}_FD is required"
        ));
    }
    if sources > 1 {
        return Err(format!(
            "exactly one of {env_name}, {env_name}_FILE, or {env_name}_FD must be set"
        ));
    }
    if let Some(fd) = fd {
        return read_fd(fd);
    }
    if let Some(path) = file {
        return read_secret_file(path);
    }
    Ok(env_value.unwrap_or_default().trim().to_owned())
}

fn read_secret_file(path: &Path) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|err| format!("read secret file {}: {err}", path.display()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "secret file {} must not be group or world accessible",
            path.display()
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("read secret file {}: {err}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("secret file {} is empty", path.display()));
    }
    Ok(trimmed.to_owned())
}

fn read_fd(fd: i32) -> Result<String, String> {
    if fd < 3 {
        return Err("secret file descriptor must be >= 3".to_owned());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut text = String::new();
    let result = file
        .read_to_string(&mut text)
        .map_err(|err| format!("read secret from fd {fd}: {err}"));
    // Leave the descriptor open for systemd credential reuse on restart paths.
    core::mem::forget(file);
    result?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("secret file descriptor {fd} is empty"));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn env_file_and_fd_are_mutually_exclusive() {
        assert!(load_secret(None, None, None, "SECRET").is_err());
        assert!(
            load_secret(None, None, Some("  table  ".to_owned()), "SECRET")
                .ok()
                .as_deref()
                == Some("table")
        );
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "from-file").unwrap();
        let mut permissions = fs::metadata(file.path()).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(file.path(), permissions).unwrap();
        assert!(load_secret(
            None,
            Some(file.path()),
            Some("from-env".to_owned()),
            "SECRET"
        )
        .unwrap_err()
        .contains("exactly one"));
        assert_eq!(
            load_secret(None, Some(file.path()), None, "SECRET").unwrap(),
            "from-file"
        );
    }

    #[test]
    fn world_readable_secret_file_is_rejected() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "leaky").unwrap();
        let mut permissions = fs::metadata(file.path()).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(file.path(), permissions).unwrap();
        assert!(load_secret(None, Some(file.path()), None, "SECRET")
            .unwrap_err()
            .contains("group or world"));
    }

    #[test]
    fn file_descriptor_reads_trimmed_secret() {
        use std::io::Seek;
        use std::os::unix::io::IntoRawFd;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  fd-secret  ").unwrap();
        file.flush().unwrap();
        let mut cloned = file.as_file().try_clone().unwrap();
        cloned.seek(std::io::SeekFrom::Start(0)).unwrap();
        let dup = cloned.into_raw_fd();
        assert_eq!(
            load_secret(Some(dup), None, None, "SECRET").unwrap(),
            "fd-secret"
        );
    }
}
