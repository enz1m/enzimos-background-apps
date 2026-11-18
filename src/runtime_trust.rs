// SPDX-License-Identifier: MIT
//! A Root boot record lets ordinary user services verify the initial mount namespace.
use crate::{Result, refused, registry};
use enzimos_platform::files;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub const DIRECTORY: &str = "/run/enzimos-background-trust";
pub const PATH: &str = "/run/enzimos-background-trust/namespace.json";

fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}
fn namespace(pid: &str) -> Result<String> {
    Ok(fs::read_link(format!("/proc/{pid}/ns/mnt"))?
        .to_string_lossy()
        .into_owned())
}

pub fn check_record(path: &Path, owner: u32, namespace: &str, boot: &str) -> Result<()> {
    let unavailable = || refused("native-runtime-trust-unavailable");
    let data = registry::read(path, owner)?;
    let value: Value = serde_json::from_slice(&data).map_err(|_| unavailable())?;
    let object = value
        .as_object()
        .filter(|o| o.len() == 3)
        .ok_or_else(unavailable)?;
    if !object.get("schema").is_some_and(|s| s.is_u64() && *s == 1) {
        return Err(unavailable());
    }
    if object.get("mount_namespace").and_then(Value::as_str) != Some(namespace)
        || object.get("boot_id").and_then(Value::as_str) != Some(boot)
    {
        return Err(refused("initial-native-mount-namespace-required"));
    }
    Ok(())
}

/// The service runs in the mount namespace Root recorded at this boot.
pub fn check() -> Result<()> {
    check_record(Path::new(PATH), 0, &namespace("self")?, &boot_id()?)
}

fn valid(namespace: &str, boot: &str) -> bool {
    let digits = namespace
        .strip_prefix("mnt:[")
        .and_then(|r| r.strip_suffix(']'));
    digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()))
        && boot.len() == 36
        && boot
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase() || c == b'-')
}

/// Root records the initial mount namespace and boot ID before user sessions start.
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn prepare() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || namespace("self")? != namespace("1")? {
        return Err(refused("initial-root-mount-namespace-required"));
    }
    let directory = Path::new(DIRECTORY);
    registry::protected_parents(directory, 0)?;
    let m = fs::symlink_metadata(directory)?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(refused("native-runtime-directory-untrusted"));
    }
    let (namespace, boot) = (namespace("self")?, boot_id()?);
    if !valid(&namespace, &boot) {
        return Err(refused("native-runtime-identity-invalid"));
    }
    let body =
        serde_json::to_vec(&json!({"schema": 1, "mount_namespace": namespace, "boot_id": boot}))?;
    files::atomic(Path::new(PATH), &body, 0o644, Some(0), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::{private_dir, uid, write};
    use std::os::unix::fs::symlink;

    const BOOT: &str = "0f0e0d0c-0b0a-0908-0706-050403020100";
    fn record(ns: &str, boot: &str) -> String {
        json!({"schema": 1, "mount_namespace": ns, "boot_id": boot}).to_string()
    }

    #[test]
    fn current_root_boot_record_can_be_read_by_native_user() {
        let dir = private_dir();
        let path = dir.path().join("namespace.json");
        write(&path, &record("mnt:[4026531841]", BOOT), 0o444);
        check_record(&path, uid(), "mnt:[4026531841]", BOOT).unwrap();
    }

    #[test]
    fn wrong_namespace_or_old_boot_is_refused() {
        let dir = private_dir();
        let path = dir.path().join("namespace.json");
        write(&path, &record("mnt:[4026531841]", BOOT), 0o444);
        assert_eq!(
            check_record(&path, uid(), "mnt:[1]", BOOT).unwrap_err().0,
            "initial-native-mount-namespace-required"
        );
        assert!(check_record(&path, uid(), "mnt:[4026531841]", "other").is_err());
    }

    #[test]
    fn untrusted_or_symlink_record_is_refused() {
        let dir = private_dir();
        let real = dir.path().join("real.json");
        write(&real, &record("mnt:[1]", BOOT), 0o444);
        symlink(&real, dir.path().join("namespace.json")).unwrap();
        assert!(check_record(&dir.path().join("namespace.json"), uid(), "mnt:[1]", BOOT).is_err());
        write(&real, &record("mnt:[1]", BOOT), 0o666);
        assert!(check_record(&real, uid(), "mnt:[1]", BOOT).is_err());
        assert!(check_record(&real, uid() + 1, "mnt:[1]", BOOT).is_err());
        assert!(
            valid("mnt:[4026531841]", BOOT)
                && !valid("mnt:[x]", BOOT)
                && !valid("mnt:[1]", "short")
        );
    }
}
