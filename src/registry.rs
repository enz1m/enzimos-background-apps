// SPDX-License-Identifier: MIT
//! Admission of immutable installed declarations and their native executable identity.
use crate::{
    Result,
    manifest::{self, Manifest},
    refused,
};
use enzimos_platform::{files, json::sha256};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub const MAX_APPS: usize = 128;
/// Framework-neutral declarations, written by enzUI's installed-app tooling.
pub const DIRECTORY: &str = "/usr/share/enzui/background-apps";
/// Deprecated pre-neutral declarations, still read during framework migration.
pub const LEGACY_DIRECTORY: &str = "/usr/share/enzimos/background-apps";
/// Read in this order; the first directory holding `APP_ID.json` decides that app.
pub const DIRECTORIES: [&str; 2] = [DIRECTORY, LEGACY_DIRECTORY];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executable {
    pub path: String,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

impl Executable {
    pub fn of(path: String, m: &fs::Metadata) -> Self {
        Self {
            path,
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            mtime_ns: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            ctime_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
        }
    }
    /// The running image matches by inode and content timestamps, not by path.
    pub fn matches(&self, m: &fs::Metadata) -> bool {
        Self::of(self.path.clone(), m) == *self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    pub executable: Executable,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalogue {
    pub apps: BTreeMap<String, Entry>,
    pub unavailable: Vec<String>,
    pub observation_known: bool,
}

impl Catalogue {
    pub fn unknown() -> Self {
        Self::default()
    }
    pub fn unavailable_value(&self) -> Value {
        self.unavailable
            .iter()
            .map(|name| json!({"declaration": name, "reason": "installed-declaration-unavailable"}))
            .collect()
    }
}

/// Every ancestor is a real directory owned by root or `owner`, not group/other writable.
pub fn protected_parents(path: &Path, owner: u32) -> Result<()> {
    for parent in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let m = fs::symlink_metadata(parent)
            .map_err(|_| refused("installed-registry-parent-unsafe"))?;
        if !m.is_dir() || (m.uid() != 0 && m.uid() != owner) || m.mode() & 0o022 != 0 {
            return Err(refused("installed-registry-parent-unsafe"));
        }
    }
    Ok(())
}

pub fn read(path: &Path, owner: u32) -> Result<Vec<u8>> {
    protected_parents(
        path.parent()
            .ok_or_else(|| refused("installed-manifest-unsafe"))?,
        owner,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| refused("installed-manifest-unsafe"))?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != owner
        || m.mode() & 0o022 != 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > manifest::MAX_BYTES as u64
    {
        return Err(refused("installed-manifest-unsafe"));
    }
    files::read_file(&file, manifest::MAX_BYTES, Some(owner), true)
        .map_err(|_| refused("installed-manifest-changed"))
}

pub fn executable_identity(path: &str, owner: u32) -> Result<Executable> {
    let unsafe_ = || refused("installed-executable-unsafe");
    let path = Path::new(path);
    protected_parents(path.parent().ok_or_else(unsafe_)?, owner)?;
    let link = fs::symlink_metadata(path).map_err(|_| unsafe_())?;
    if link.uid() != owner || (!link.file_type().is_symlink() && link.mode() & 0o022 != 0) {
        return Err(unsafe_());
    }
    let resolved = fs::canonicalize(path).map_err(|_| unsafe_())?;
    protected_parents(resolved.parent().ok_or_else(unsafe_)?, owner)?;
    let m = fs::metadata(&resolved).map_err(|_| unsafe_())?;
    if !m.is_file() || m.uid() != owner || m.mode() & 0o022 != 0 || m.mode() & 0o111 == 0 {
        return Err(unsafe_());
    }
    Ok(Executable::of(resolved.to_string_lossy().into_owned(), &m))
}

pub fn load(
    directory: &Path,
    owner: u32,
    identity: &dyn Fn(&str, u32) -> Result<Executable>,
) -> Result<Catalogue> {
    let mut catalogue = Catalogue {
        observation_known: true,
        ..Default::default()
    };
    if fs::symlink_metadata(directory).is_err() {
        return Ok(catalogue);
    }
    protected_parents(directory, owner)?;
    let mut names = Vec::new();
    for item in fs::read_dir(directory)? {
        names.push(item?.file_name().to_string_lossy().into_owned());
        if names.len() > MAX_APPS * 2 {
            return Err(refused("installed-registry-bound"));
        }
    }
    names.sort();
    for name in names
        .into_iter()
        .filter(|n| Path::new(n).extension().is_some_and(|e| e == "json"))
    {
        if catalogue.apps.len() + catalogue.unavailable.len() >= MAX_APPS {
            return Err(refused("installed-registry-bound"));
        }
        let admitted = read(&directory.join(&name), owner).and_then(|data| {
            let manifest = manifest::decode(&data, &name)?;
            let executable = identity(&manifest.executable, owner)?;
            Ok(Entry {
                manifest_sha256: sha256(&data),
                manifest,
                executable,
            })
        });
        match admitted {
            Ok(entry) => {
                catalogue.apps.insert(entry.manifest.app_id.clone(), entry);
            }
            Err(_) => catalogue.unavailable.push(name),
        }
    }
    Ok(catalogue)
}

/// Load every directory in order of precedence and merge them. A declaration
/// file name (which binds the app id) seen in an earlier directory shadows the
/// same name in later ones, admitted or not, so a broken neutral declaration is
/// never replaced by an older legacy one. Any directory error fails the whole
/// load, and the merged catalogue keeps the [`MAX_APPS`] bound.
pub fn load_all(
    directories: &[&Path],
    owner: u32,
    identity: &dyn Fn(&str, u32) -> Result<Executable>,
) -> Result<Catalogue> {
    let mut merged = Catalogue {
        observation_known: true,
        ..Default::default()
    };
    let mut seen = std::collections::BTreeSet::new();
    for directory in directories {
        let catalogue = load(directory, owner, identity)?;
        let names = catalogue
            .apps
            .keys()
            .map(|id| format!("{id}.json"))
            .chain(catalogue.unavailable.iter().cloned())
            .collect::<Vec<_>>();
        for (id, entry) in catalogue.apps {
            if !seen.contains(&format!("{id}.json")) {
                merged.apps.insert(id, entry);
            }
        }
        merged.unavailable.extend(
            catalogue
                .unavailable
                .into_iter()
                .filter(|name| !seen.contains(name)),
        );
        seen.extend(names);
        if merged.apps.len() + merged.unavailable.len() > MAX_APPS {
            return Err(refused("installed-registry-bound"));
        }
    }
    merged.unavailable.sort();
    Ok(merged)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
    pub fn uid() -> u32 {
        unsafe { libc::getuid() }
    }
    /// A private directory whose ancestors pass protected_parents for this user.
    pub fn private_dir() -> tempfile::TempDir {
        // Not /tmp: its sticky world-writable mode fails protected_parents.
        let base = std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"))
            .join("background-tests");
        fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("bg-")
            .tempdir_in(base)
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    pub fn write(path: &Path, body: &str, mode: u32) {
        let _ = fs::remove_file(path);
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    pub fn manifest_json(id: &str) -> String {
        serde_json::json!({"schema": 1, "app_id": id, "title": "Music", "unit": format!("enzui-agent-{id}.service"),
            "executable": "/usr/bin/music", "purpose": "Plays music",
            "activation_sources": ["user", "agent", "autostart"], "autostart_supported": true})
        .to_string()
    }
    fn fake(path: &str, _: u32) -> Result<Executable> {
        Ok(Executable {
            path: path.into(),
            device: 1,
            inode: 2,
            bytes: 3,
            mtime_ns: 4,
            ctime_ns: 5,
        })
    }

    #[test]
    fn valid_catalogue_and_changed_content_bound() {
        let dir = private_dir();
        write(
            &dir.path().join("org.example.Music.json"),
            &manifest_json("org.example.Music"),
            0o644,
        );
        write(&dir.path().join("org.example.Bad.json"), "{}", 0o644);
        write(&dir.path().join("notes.txt"), "x", 0o644);
        let catalogue = load(dir.path(), uid(), &fake).unwrap();
        assert_eq!(
            catalogue.apps.keys().collect::<Vec<_>>(),
            ["org.example.Music"]
        );
        assert_eq!(catalogue.unavailable, ["org.example.Bad.json"]);
        let first = catalogue.apps["org.example.Music"].manifest_sha256.clone();
        write(
            &dir.path().join("org.example.Music.json"),
            &manifest_json("org.example.Music").replace("Plays", "Streams"),
            0o644,
        );
        assert_ne!(
            load(dir.path(), uid(), &fake).unwrap().apps["org.example.Music"].manifest_sha256,
            first
        );
    }

    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (mkfifo).")]
    fn symlink_fifo_and_writable_declaration_not_admitted() {
        let dir = private_dir();
        let target = dir.path().join("real");
        write(&target, &manifest_json("org.example.Music"), 0o644);
        symlink(&target, dir.path().join("org.example.Music.json")).unwrap();
        write(
            &dir.path().join("org.example.Open.json"),
            &manifest_json("org.example.Open"),
            0o666,
        );
        let path =
            std::ffi::CString::new(dir.path().join("org.example.Fifo.json").to_str().unwrap())
                .unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
        let catalogue = load(dir.path(), uid(), &fake).unwrap();
        assert!(catalogue.apps.is_empty());
        assert_eq!(catalogue.unavailable.len(), 3);
    }

    #[test]
    fn neutral_directory_wins_and_legacy_still_admitted() {
        let dir = private_dir();
        let (neutral, legacy) = (dir.path().join("enzui"), dir.path().join("enzimos"));
        fs::create_dir(&neutral).unwrap();
        fs::create_dir(&legacy).unwrap();
        let music =
            |purpose: &str| manifest_json("org.example.Music").replace("Plays music", purpose);
        write(
            &neutral.join("org.example.Music.json"),
            &music("Neutral"),
            0o644,
        );
        write(
            &legacy.join("org.example.Music.json"),
            &music("Legacy"),
            0o644,
        );
        write(
            &legacy.join("org.example.Old.json"),
            &manifest_json("org.example.Old"),
            0o644,
        );
        // A broken neutral declaration is not replaced by its legacy copy.
        write(&neutral.join("org.example.Broken.json"), "{}", 0o644);
        write(
            &legacy.join("org.example.Broken.json"),
            &manifest_json("org.example.Broken"),
            0o644,
        );
        write(&legacy.join("org.example.Bad.json"), "{}", 0o644);
        let catalogue = load_all(&[neutral.as_path(), legacy.as_path()], uid(), &fake).unwrap();
        assert_eq!(
            catalogue.apps.keys().collect::<Vec<_>>(),
            ["org.example.Music", "org.example.Old"]
        );
        assert_eq!(
            catalogue.apps["org.example.Music"].manifest.purpose,
            "Neutral"
        );
        assert_eq!(
            catalogue.unavailable,
            ["org.example.Bad.json", "org.example.Broken.json"]
        );
        assert!(catalogue.observation_known);
        // Either directory may be absent.
        let only_legacy = load_all(
            &[dir.path().join("missing").as_path(), legacy.as_path()],
            uid(),
            &fake,
        )
        .unwrap();
        assert_eq!(
            only_legacy.apps["org.example.Music"].manifest.purpose,
            "Legacy"
        );
        // An unsafe directory fails the whole load rather than hiding one source.
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            load_all(&[neutral.as_path(), legacy.as_path()], uid(), &fake)
                .unwrap_err()
                .0,
            "installed-registry-parent-unsafe"
        );
    }

    #[test]
    fn merged_catalogue_keeps_the_app_bound() {
        let dir = private_dir();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        for i in 0..MAX_APPS {
            let (target, id) = (
                if i % 2 == 0 { &a } else { &b },
                format!("org.example.App{i}"),
            );
            write(
                &target.join(format!("{id}.json")),
                &manifest_json(&id),
                0o644,
            );
        }
        assert_eq!(
            load_all(&[a.as_path(), b.as_path()], uid(), &fake)
                .unwrap()
                .apps
                .len(),
            MAX_APPS
        );
        write(
            &b.join("org.example.Extra.json"),
            &manifest_json("org.example.Extra"),
            0o644,
        );
        assert_eq!(
            load_all(&[a.as_path(), b.as_path()], uid(), &fake)
                .unwrap_err()
                .0,
            "installed-registry-bound"
        );
    }

    #[test]
    fn writable_ancestor_refused() {
        let dir = private_dir();
        let open = dir.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let inner = open.join("apps");
        fs::create_dir(&inner).unwrap();
        assert_eq!(
            load(&inner, uid(), &fake).unwrap_err().0,
            "installed-registry-parent-unsafe"
        );
        assert!(
            load(&dir.path().join("missing"), uid(), &fake)
                .unwrap()
                .apps
                .is_empty()
        );
    }

    #[test]
    fn native_identity_requires_protected_regular_executable() {
        let dir = private_dir();
        let tool = dir.path().join("tool");
        write(&tool, "#!/bin/sh\n", 0o755);
        let identity = executable_identity(tool.to_str().unwrap(), uid()).unwrap();
        assert!(identity.matches(&fs::metadata(&tool).unwrap()));
        write(&tool, "#!/bin/sh\n", 0o644);
        assert!(executable_identity(tool.to_str().unwrap(), uid()).is_err());
        write(&tool, "#!/bin/sh\n", 0o775);
        assert!(executable_identity(tool.to_str().unwrap(), uid()).is_err());
    }

    #[test]
    fn protected_executable_alias_resolves_to_exact_identity() {
        let dir = private_dir();
        let tool = dir.path().join("tool");
        write(&tool, "#!/bin/sh\n", 0o755);
        symlink(&tool, dir.path().join("alias")).unwrap();
        let identity =
            executable_identity(dir.path().join("alias").to_str().unwrap(), uid()).unwrap();
        assert_eq!(identity.path, tool.to_str().unwrap());
    }
}
