// SPDX-License-Identifier: MIT
//! Private per-user future activation preferences; never application tool consent.
use crate::{
    Check, Result,
    manifest::{Manifest, SOURCES, app_id},
    model::{Policy, defaults, requested},
    refused,
};
use enzimos_platform::{
    files,
    json::{DecodeFailure, decode_classified},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{File, OpenOptions},
    future::Future,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

const MAX_BYTES: usize = 65536;
const OPERATION_BYTES: usize = 16384;

/// Create or open each component without following links, refusing shared parents.
#[allow(unsafe_code, reason = "Linux syscall ABI (mkdirat, openat).")]
pub fn private_tree(directory: &Path, uid: u32) -> Result<()> {
    let parent = || refused("background-preference-parent");
    if !directory.is_absolute() || directory.components().any(|c| c == Component::ParentDir) {
        return Err(parent());
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = File::open("/").map_err(|_| parent())?;
    for part in directory.components().skip(1) {
        let m = fd.metadata()?;
        if (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o022 != 0 {
            return Err(parent());
        }
        let name = CString::new(part.as_os_str().as_encoded_bytes()).map_err(|_| parent())?;
        unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o700) };
        let child = unsafe { libc::openat(fd.as_raw_fd(), name.as_ptr(), flags) };
        if child < 0 {
            return Err(parent());
        }
        fd = unsafe { File::from_raw_fd(child) };
    }
    let m = fd.metadata()?;
    if m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(refused("background-preference-directory"));
    }
    Ok(())
}

pub struct Store {
    pub directory: PathBuf,
    uid: u32,
}

impl Store {
    pub fn new(directory: PathBuf, uid: u32) -> Self {
        Self { directory, uid }
    }

    pub(crate) fn read_private(
        &self,
        name: &str,
        limit: usize,
        code: &str,
    ) -> Result<Option<Vec<u8>>> {
        private_tree(&self.directory, self.uid)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.directory.join(name))
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(refused(&format!("{code}-file"))),
        };
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != self.uid
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || m.len() > limit as u64
        {
            return Err(refused(&format!("{code}-file")));
        }
        files::read_file(&file, limit, Some(self.uid), true)
            .map(Some)
            .map_err(|_| refused(&format!("{code}-changed")))
    }

    pub fn load(&self) -> Result<BTreeMap<String, Policy>> {
        let Some(data) = self.read_private("policy.json", MAX_BYTES, "background-preference")?
        else {
            return Ok(BTreeMap::new());
        };
        let value = decode_classified(&data, MAX_BYTES).map_err(|e| match e {
            DecodeFailure::Duplicate => refused("background-preference-duplicate"),
            _ => refused("background-preference-invalid"),
        })?;
        let schema = || refused("background-preference-schema");
        let object = value
            .as_object()
            .filter(|o| o.len() == 2)
            .ok_or_else(schema)?;
        let apps = object
            .get("apps")
            .and_then(Value::as_object)
            .filter(|a| a.len() <= 128)
            .ok_or_else(schema)?;
        if !object.get("schema").is_some_and(|s| s.is_u64() && *s == 1) {
            return Err(schema());
        }
        let mut result = BTreeMap::new();
        for (key, row) in apps {
            let row = row
                .as_object()
                .filter(|r| app_id(key) && r.len() <= SOURCES.len())
                .and_then(|r| {
                    r.iter()
                        .map(|(k, v)| {
                            v.as_bool()
                                .filter(|_| SOURCES.contains(&k.as_str()))
                                .map(|b| (k.clone(), b))
                        })
                        .collect::<Option<Policy>>()
                })
                .ok_or_else(|| refused("background-preference-entry"))?;
            if row.get("user") == Some(&false) {
                return Err(refused("background-direct-user-activation-required"));
            }
            result.insert(key.clone(), row);
        }
        Ok(result)
    }

    /// Saved values for declared sources; a newly declared source gets its default
    /// without re-granting an earlier denial of another source.
    pub fn get(&self, manifest: &Manifest) -> Result<Policy> {
        let saved = self.load()?.remove(&manifest.app_id);
        let mut policy = defaults(manifest);
        if let Some(saved) = saved {
            for (key, value) in policy.iter_mut() {
                if let Some(v) = saved.get(key) {
                    *value = *v;
                }
            }
            requested(manifest, &json!(policy))?;
        }
        Ok(policy)
    }

    fn write(&self, name: &str, body: &[u8]) -> Result<()> {
        files::atomic_bounded(
            &self.directory.join(name),
            body,
            0o600,
            Some(self.uid),
            true,
            MAX_BYTES,
        )
    }

    /// Create the private directory if needed, then replace `name` atomically.
    pub(crate) fn write_private(&self, name: &str, body: &[u8]) -> Result<()> {
        private_tree(&self.directory, self.uid)?;
        self.write(name, body)
    }

    /// Remove `name` if present; the directory must still be private.
    pub(crate) fn remove_private(&self, name: &str) -> Result<()> {
        private_tree(&self.directory, self.uid)?;
        match std::fs::remove_file(self.directory.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(refused("background-preference-file"))
            }
            _ => Ok(()),
        }
    }

    /// At the bound, entries of apps `installed` no longer knows are dropped first.
    pub fn put(
        &self,
        manifest: &Manifest,
        value: &Policy,
        installed: impl Fn(&str) -> bool,
    ) -> Result<()> {
        let value = requested(manifest, &json!(value))?;
        let mut apps = self.load()?;
        apps.insert(manifest.app_id.clone(), value);
        let encode = |apps: &BTreeMap<String, Policy>| {
            serde_json::to_vec(&json!({"schema": 1, "apps": apps}))
        };
        let mut data = encode(&apps)?;
        if apps.len() > 128 || data.len() > MAX_BYTES {
            apps.retain(|id, _| *id == manifest.app_id || installed(id));
            data = encode(&apps)?;
        }
        if apps.len() > 128 || data.len() > MAX_BYTES {
            return Err(refused("background-preference-bound"));
        }
        self.write("policy.json", &data)
    }

    pub fn journal(&self, value: &Value) -> Result<()> {
        private_tree(&self.directory, self.uid)?;
        let data = serde_json::to_vec(value)?;
        if data.len() > OPERATION_BYTES {
            return Err(refused("background-policy-journal-bound"));
        }
        self.write("operation.json", &data)
    }

    /// The last policy commit; anything but complete needs a fresh review.
    pub fn operation(&self) -> Result<Option<Value>> {
        let Some(data) =
            self.read_private("operation.json", OPERATION_BYTES, "background-operation")?
        else {
            return Ok(None);
        };
        let invalid = || refused("background-operation-invalid");
        let value = decode_classified(&data, OPERATION_BYTES).map_err(|e| match e {
            DecodeFailure::Duplicate => refused("background-operation-duplicate"),
            _ => invalid(),
        })?;
        let object = value
            .as_object()
            .filter(|o| o.len() == 4)
            .ok_or_else(invalid)?;
        let phase = object
            .get("phase")
            .and_then(Value::as_str)
            .filter(|p| ["pending", "complete", "uncertain"].contains(p))
            .ok_or_else(invalid)?;
        if !object.get("schema").is_some_and(|s| s.is_u64() && *s == 1)
            || object.get("automatic_replay") != Some(&json!(false))
        {
            return Err(invalid());
        }
        let app = object
            .get("plan")
            .and_then(Value::as_object)
            .ok_or_else(invalid)?
            .get("app_id")
            .and_then(Value::as_str)
            .filter(|a| app_id(a))
            .ok_or_else(|| refused("background-operation-app"))?;
        Ok(Some(
            json!({"phase": phase, "app_id": app, "automatic_replay": false, "fresh_review_required": phase != "complete"}),
        ))
    }

    /// After the first autostart mutation, finish recording its outcome despite disconnect.
    pub async fn apply<F: Future<Output = Result<()>>>(
        &self,
        manifest: &Manifest,
        plan: &Value,
        requested: &Policy,
        change_autostart: F,
        installed: impl Fn(&str) -> bool,
        guard: &impl Check,
    ) -> Result<()> {
        guard.check().await?;
        let mut record =
            json!({"schema": 1, "phase": "pending", "plan": plan, "automatic_replay": false});
        self.journal(&record)?;
        let outcome = async {
            change_autostart.await?;
            self.put(manifest, requested, installed)?;
            record["phase"] = json!("complete");
            self.journal(&record)
        }
        .await;
        if outcome.is_err() {
            record["phase"] = json!("uncertain");
            let _ = self.journal(&record);
            return Err(refused("background-policy-outcome-needs-review"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::tests::manifest,
        registry::tests::{private_dir, uid, write},
    };
    use std::{fs, os::unix::fs::symlink};

    struct Pass;
    impl Check for Pass {
        async fn check(&self) -> Result<()> {
            Ok(())
        }
    }
    struct Expired;
    impl Check for Expired {
        async fn check(&self) -> Result<()> {
            Err(refused("request-expired"))
        }
    }
    fn store(dir: &Path) -> Store {
        Store::new(dir.join("state/background-apps"), uid())
    }

    #[test]
    fn default_and_atomic_save_preserve_independent_sources() {
        let dir = private_dir();
        let s = store(dir.path());
        let m = manifest(false);
        assert_eq!(s.get(&m).unwrap(), defaults(&m));
        let mut p = defaults(&m);
        p.insert("agent".into(), false);
        s.put(&m, &p, |_| true).unwrap();
        assert_eq!(s.get(&m).unwrap(), p);
        let mode = fs::metadata(s.directory.join("policy.json"))
            .unwrap()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn new_source_uses_default_without_regranting_old_denial() {
        let dir = private_dir();
        let s = store(dir.path());
        let m = manifest(false);
        let mut p = defaults(&m);
        p.insert("agent".into(), false);
        s.put(&m, &p, |_| true).unwrap();
        let mut grown = m.clone();
        grown.activation_sources.push("ongoing-work".into());
        let policy = s.get(&grown).unwrap();
        assert!(!policy["agent"]);
        assert!(policy["ongoing-work"]);
    }

    #[test]
    fn symlink_fifo_shared_or_duplicate_file_refused() {
        let dir = private_dir();
        let s = store(dir.path());
        s.load().unwrap();
        let path = s.directory.join("policy.json");
        write(
            &dir.path().join("elsewhere"),
            r#"{"schema":1,"apps":{}}"#,
            0o600,
        );
        symlink(dir.path().join("elsewhere"), &path).unwrap();
        assert!(s.load().is_err());
        fs::remove_file(&path).unwrap();
        write(&path, r#"{"schema":1,"apps":{}}"#, 0o644);
        assert_eq!(s.load().unwrap_err().0, "background-preference-file");
        write(&path, r#"{"schema":1,"schema":1,"apps":{}}"#, 0o600);
        assert_eq!(s.load().unwrap_err().0, "background-preference-duplicate");
    }

    #[test]
    fn private_directory_and_direct_user_activation_required() {
        let dir = private_dir();
        let s = store(dir.path());
        s.load().unwrap();
        write(
            &s.directory.join("policy.json"),
            r#"{"schema":1,"apps":{"org.example.Music":{"user":false}}}"#,
            0o600,
        );
        assert_eq!(
            s.load().unwrap_err().0,
            "background-direct-user-activation-required"
        );
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&s.directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(s.load().unwrap_err().0, "background-preference-directory");
    }

    #[test]
    fn safe_creation_refuses_symlink_and_shared_parent_before_mutation() {
        let dir = private_dir();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, dir.path().join("link")).unwrap();
        assert!(private_tree(&dir.path().join("link/apps"), uid()).is_err());
        assert!(!real.join("apps").exists());
        assert!(private_tree(Path::new("relative/apps"), uid()).is_err());
    }

    #[tokio::test]
    async fn expiry_before_commit_does_not_change_autostart_or_preferences() {
        let dir = private_dir();
        let s = store(dir.path());
        let m = manifest(false);
        let changed = std::cell::Cell::new(false);
        let plan = json!({"app_id": m.app_id});
        let err = s
            .apply(
                &m,
                &plan,
                &defaults(&m),
                async {
                    changed.set(true);
                    Ok(())
                },
                |_| true,
                &Expired,
            )
            .await
            .unwrap_err();
        assert_eq!(err.0, "request-expired");
        assert!(!changed.get());
        assert!(s.operation().unwrap().is_none());
    }

    #[tokio::test]
    async fn lost_mutation_response_is_uncertain_and_never_replayed() {
        let dir = private_dir();
        let s = store(dir.path());
        let m = manifest(false);
        let plan = json!({"app_id": m.app_id});
        let err = s
            .apply(
                &m,
                &plan,
                &defaults(&m),
                async { Err(refused("timeout")) },
                |_| true,
                &Pass,
            )
            .await
            .unwrap_err();
        assert_eq!(err.0, "background-policy-outcome-needs-review");
        let op = s.operation().unwrap().unwrap();
        assert_eq!(op["phase"], "uncertain");
        assert_eq!(op["fresh_review_required"], true);
        assert_eq!(op["automatic_replay"], false);
        s.apply(&m, &plan, &defaults(&m), async { Ok(()) }, |_| true, &Pass)
            .await
            .unwrap();
        assert_eq!(s.operation().unwrap().unwrap()["phase"], "complete");
    }

    #[test]
    fn at_the_bound_uninstalled_apps_are_pruned_first() {
        let dir = private_dir();
        let s = store(dir.path());
        s.load().unwrap();
        let apps = (0..128)
            .map(|i| (format!("org.example.Old{i}"), json!({"user": true})))
            .collect::<serde_json::Map<_, _>>();
        write(
            &s.directory.join("policy.json"),
            &json!({"schema": 1, "apps": apps}).to_string(),
            0o600,
        );
        let m = manifest(false);
        let p = defaults(&m);
        assert_eq!(
            s.put(&m, &p, |_| true).unwrap_err().0,
            "background-preference-bound"
        );
        s.put(&m, &p, |id| id != "org.example.Old7").unwrap();
        let saved = s.load().unwrap();
        assert_eq!(saved.len(), 128);
        assert!(saved.contains_key(&m.app_id) && !saved.contains_key("org.example.Old7"));
    }
}
