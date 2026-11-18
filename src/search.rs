// SPDX-License-Identifier: MIT
//! Search cold activation: start an installed native provider's fixed unit for
//! the desktop's Search, only behind its verified declarations and the separate
//! `search` activation source.
//!
//! A query is never a user launch or an agent grant. The broker proves the
//! app's protected search declarations, checks the saved `search` source,
//! starts exactly the manifest's unit once (no retry) and waits briefly for the
//! app's bus name. It never makes a name D-Bus activatable and never starts a
//! name through the bus itself.
use crate::{
    Check, Result,
    manifest::{Manifest, app_id as valid_app_id},
    model::{Policy, Windows},
    process_identity::Unit,
    refused,
    registry::{Entry, Executable},
};
use enzimos_platform::json::{DecodeFailure, decode_classified, sha256};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::Mutex;

/// Enables the optional search adapter when built with `ENZIMOS_SEARCH_ADAPTER_QUALIFIED=1`.
pub const ADAPTER_QUALIFIED: bool = match option_env!("ENZIMOS_SEARCH_ADAPTER_QUALIFIED") {
    Some(value) => value.len() == 1 && value.as_bytes()[0] == b'1',
    None => false,
};
/// How long a cold start may take to own the app's bus name, from `StartUnit`.
pub const START_DEADLINE: Duration = Duration::from_millis(1000);
/// Each declaration is at most this large.
pub const MAX_BYTES: usize = 4096;
pub const PROVIDERS: &str = "/usr/share/enzui/search-providers";
pub const DESKTOPS: &str = "/usr/share/applications";
pub const SERVICES: &str = "/usr/share/dbus-1/services";
/// Data directories that would shadow `/usr/share` for the shell or the bus.
const SYSTEM_SHADOWS: [&str; 2] = ["/usr/local/share", "/var/lib/flatpak/exports/share"];
const HOME_SHADOWS: [&str; 2] = [".local/share", ".local/share/flatpak/exports/share"];
/// Marker files under `$XDG_RUNTIME_DIR`.
pub const MARKER_DIRECTORY: &str = "enzimos/search-activation";
const MARKER_BYTES: usize = 1024;
const RUNNING: [&str; 4] = ["active", "activating", "reloading", "refreshing"];

/// The keys of one `[name]` section. Strict: no keys outside a section, no
/// duplicate keys or sections, no continuation lines, no `[DEFAULT]`.
pub fn section(data: &[u8], name: &str) -> Result<BTreeMap<String, String>> {
    if data.is_empty() || data.len() > MAX_BYTES {
        return Err(refused("search-declaration-bound"));
    }
    let invalid = || refused("search-declaration-invalid");
    let text = std::str::from_utf8(data).map_err(|_| invalid())?;
    if text
        .chars()
        .any(|c| (c < ' ' && !matches!(c, '\t' | '\r' | '\n')) || c == '\x7f')
    {
        return Err(invalid());
    }
    let (mut sections, mut keys) = (BTreeSet::new(), BTreeSet::new());
    let mut current: Option<&str> = None;
    let mut found: Option<BTreeMap<String, String>> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            return Err(invalid());
        }
        if let Some(header) = trimmed.strip_prefix('[') {
            let header = header
                .strip_suffix(']')
                .filter(|h| !h.is_empty() && *h != "DEFAULT")
                .ok_or_else(invalid)?;
            if !sections.insert(header) {
                return Err(invalid());
            }
            keys.clear();
            current = Some(header);
            if header == name {
                found = Some(BTreeMap::new());
            }
            continue;
        }
        let section = current.ok_or_else(invalid)?;
        let (key, value) = trimmed.split_once('=').ok_or_else(invalid)?;
        let key = key.trim();
        if key.is_empty() || !keys.insert(key) {
            return Err(invalid());
        }
        if section == name {
            found
                .as_mut()
                .unwrap()
                .insert(key.into(), value.trim().into());
        }
    }
    found.ok_or_else(invalid)
}

/// The program of a desktop-entry or D-Bus `Exec` line must be the admitted executable.
pub fn executable(value: &str, expected: &str) -> Result<()> {
    let value = value.trim();
    let first = match value.strip_prefix('"') {
        Some(rest) => rest
            .split_once('"')
            .filter(|(p, _)| !p.contains('\\'))
            .map(|(p, _)| p),
        None => value.split_whitespace().next(),
    };
    match first {
        Some(program) if program == expected => Ok(()),
        Some(_) => Err(refused("search-executable-binding")),
        None => Err(refused("search-executable-invalid")),
    }
}

fn object_path(path: &str) -> bool {
    path == "/"
        || (path.len() <= 256
            && path.strip_prefix('/').is_some_and(|rest| {
                rest.split('/').all(|p| {
                    !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                })
            }))
}

/// One installed app's verified native search declarations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub app_id: String,
    pub desktop_id: String,
    pub bus_name: String,
    pub object_path: String,
    pub unit: String,
    pub executable: Executable,
    pub min_query_length: u32,
    pub declarations_sha256: BTreeMap<&'static str, String>,
}

pub fn paths(app_id: &str) -> [(&'static str, PathBuf); 3] {
    [
        (
            "provider",
            Path::new(PROVIDERS).join(format!("{app_id}.ini")),
        ),
        (
            "desktop",
            Path::new(DESKTOPS).join(format!("{app_id}.desktop")),
        ),
        (
            "service",
            Path::new(SERVICES).join(format!("{app_id}.service")),
        ),
    ]
}

/// Bind the Root-installed provider, desktop entry and session service files to
/// the admitted manifest unit and a fresh executable identity. A proof grants
/// no launch or stop authority by itself.
pub fn verify(
    entry: &Entry,
    read: &dyn Fn(&Path) -> Result<Vec<u8>>,
    identity: &dyn Fn(&str) -> Result<Executable>,
) -> Result<Proof> {
    let manifest = &entry.manifest;
    let app = &manifest.app_id;
    if !valid_app_id(app) || !manifest.activation_sources.iter().any(|s| s == "search") {
        return Err(refused("search-installed-source-required"));
    }
    let mut raw = BTreeMap::new();
    for (key, path) in paths(app) {
        raw.insert(
            key,
            read(&path).map_err(|_| refused("search-declaration-unsafe"))?,
        );
    }
    let provider = section(&raw["provider"], "enzUI Search Provider")?;
    let desktop = section(&raw["desktop"], "Desktop Entry")?;
    let service = section(&raw["service"], "D-BUS Service")?;
    let desktop_id = format!("{app}.desktop");
    let get = |map: &BTreeMap<String, String>, key: &str| map.get(key).cloned();
    if get(&provider, "DesktopId").as_ref() != Some(&desktop_id)
        || get(&provider, "BusName").as_ref() != Some(app)
        || get(&provider, "Version").as_deref() != Some("1")
    {
        return Err(refused("search-provider-binding"));
    }
    let path = get(&provider, "ObjectPath").unwrap_or_default();
    if !object_path(&path) {
        return Err(refused("search-object-path"));
    }
    let minimum = get(&provider, "MinQueryLength").unwrap_or_else(|| "2".into());
    let minimum = minimum
        .parse::<u32>()
        .ok()
        .filter(|m| minimum.bytes().all(|c| c.is_ascii_digit()) && (1..=256).contains(m))
        .ok_or_else(|| refused("search-query-bound"))?;
    if get(&desktop, "Type").as_deref() != Some("Application")
        || get(&desktop, "DBusActivatable").as_deref() != Some("true")
        || ["Hidden", "NoDisplay"]
            .iter()
            .any(|k| get(&desktop, k).is_some_and(|v| v != "false"))
    {
        return Err(refused("search-desktop-unavailable"));
    }
    if get(&service, "Name").as_ref() != Some(app)
        || get(&service, "SystemdService").as_ref() != Some(&manifest.unit)
    {
        return Err(refused("search-service-binding"));
    }
    executable(
        &get(&desktop, "Exec").unwrap_or_default(),
        &manifest.executable,
    )?;
    executable(
        &get(&service, "Exec").unwrap_or_default(),
        &manifest.executable,
    )?;
    let observed = identity(&manifest.executable)
        .map_err(|_| refused("search-installed-executable-changed"))?;
    if observed != entry.executable {
        return Err(refused("search-installed-executable-changed"));
    }
    Ok(Proof {
        app_id: app.clone(),
        desktop_id,
        bus_name: app.clone(),
        object_path: path,
        unit: manifest.unit.clone(),
        executable: observed,
        min_query_length: minimum,
        declarations_sha256: raw.iter().map(|(k, v)| (*k, sha256(v))).collect(),
    })
}

/// Declarations under a user, local or Flatpak data directory with the same
/// name would be what the shell or the bus actually reads: refuse them.
pub fn overridden(app_id: &str, home: &Path, exists: &dyn Fn(&Path) -> bool) -> Result<()> {
    let roots = SYSTEM_SHADOWS
        .iter()
        .map(PathBuf::from)
        .chain(HOME_SHADOWS.iter().map(|d| home.join(d)));
    for root in roots {
        for relative in [
            format!("enzui/search-providers/{app_id}.ini"),
            format!("applications/{app_id}.desktop"),
            format!("dbus-1/services/{app_id}.service"),
        ] {
            if exists(&root.join(relative)) {
                return Err(refused("search-declaration-overridden"));
            }
        }
    }
    Ok(())
}

/// The activation-origin record the app can read: `invocation_id` is null
/// while the broker's start is in flight and then names the systemd invocation
/// it started. Informational for the app; never an authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    pub app_id: String,
    pub unit: String,
    pub invocation_id: Option<String>,
    pub requested_realtime_us: u64,
}

impl Marker {
    pub fn value(&self) -> Value {
        json!({"schema": 1, "origin": "search", "app_id": self.app_id, "unit": self.unit,
               "invocation_id": self.invocation_id, "requested_realtime_us": self.requested_realtime_us})
    }
    pub fn decode(data: &[u8], app_id: &str) -> Result<Self> {
        let invalid = || refused("search-marker-invalid");
        let value = decode_classified(data, MARKER_BYTES).map_err(|e| match e {
            DecodeFailure::Duplicate => refused("search-marker-duplicate"),
            _ => invalid(),
        })?;
        let object = value
            .as_object()
            .filter(|o| o.len() == 6)
            .ok_or_else(invalid)?;
        let marker = Marker {
            app_id: object
                .get("app_id")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .into(),
            unit: object
                .get("unit")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .into(),
            invocation_id: match object.get("invocation_id") {
                Some(Value::Null) => None,
                Some(Value::String(id)) if invocation(id) => Some(id.clone()),
                _ => return Err(invalid()),
            },
            requested_realtime_us: object
                .get("requested_realtime_us")
                .and_then(Value::as_u64)
                .ok_or_else(invalid)?,
        };
        if marker.value() != value || marker.app_id != app_id {
            return Err(invalid());
        }
        Ok(marker)
    }
}

/// systemd's `$INVOCATION_ID`: 128 bits as 32 lowercase hex digits.
pub fn invocation(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && id.bytes().any(|c| c != b'0')
}

/// One observation of the app's unit for search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub unit: Unit,
    pub invocation_id: String,
    pub windows: Windows,
}

/// What the activation needs from systemd, the bus and the installed files.
pub trait Host {
    fn entry(&self, app_id: &str) -> Result<Entry>;
    /// The declaration proof, including the override check.
    fn verify(&self, entry: &Entry) -> Result<Proof>;
    /// The saved policy; refuses while a policy commit for this app needs review.
    fn policy(&self, manifest: &Manifest) -> Result<Policy>;
    fn instance(&mut self, entry: &Entry) -> impl Future<Output = Result<Instance>> + Send;
    fn name_owned(&self, name: &str) -> impl Future<Output = Result<bool>> + Send;
    /// Load the unit and require its fragment and drop-ins to be Root-installed.
    fn trusted_unit(&mut self, entry: &Entry) -> impl Future<Output = Result<()>> + Send;
    fn start_unit(&mut self, unit: &str) -> impl Future<Output = Result<()>> + Send;
    /// The bus name's owner is this instance's verified main process.
    fn owner_is_main(&self, name: &str, unit: &Unit) -> impl Future<Output = bool> + Send;
    fn marker(&self, app_id: &str) -> Result<Option<Marker>>;
    fn mark(&self, marker: &Marker) -> Result<()>;
    fn unmark(&self, app_id: &str) -> Result<()>;
    fn lifecycle_query(
        &self,
        app_id: &str,
        unit: &Unit,
    ) -> impl Future<Output = Result<Value>> + Send;
    fn lifecycle_stop<G: Check + Sync>(
        &self,
        app_id: &str,
        unit: &Unit,
        review: &Value,
        guard: &G,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// The first half, under the provider lock: every check, then one `StartUnit`.
pub enum Prepared {
    Running,
    Started(Box<Entry>),
}

pub async fn prepare<H: Host>(
    host: &mut H,
    app_id: &str,
    adapter: bool,
    now_us: u64,
) -> Result<Prepared> {
    if !adapter {
        return Err(refused("search-policy-adapter-unavailable"));
    }
    let entry = host.entry(app_id)?;
    let proof = host.verify(&entry)?;
    if host.policy(&entry.manifest)?.get("search") != Some(&true) {
        return Err(refused("search-activation-disabled"));
    }
    let instance = host.instance(&entry).await?;
    match instance.unit.state.as_str() {
        state if RUNNING.contains(&state) => {
            return if instance.unit.identity_verified {
                Ok(Prepared::Running)
            } else {
                Err(refused("search-running-instance-unverified"))
            };
        }
        "inactive" | "failed" => {}
        "deactivating" => return Err(refused("search-unit-busy")),
        _ => return Err(refused("application-unit-unavailable")),
    }
    if host.name_owned(&proof.bus_name).await? {
        return Err(refused("search-bus-name-owned-outside-unit"));
    }
    host.trusted_unit(&entry).await?;
    let marker = Marker {
        app_id: app_id.into(),
        unit: proof.unit.clone(),
        invocation_id: None,
        requested_realtime_us: now_us,
    };
    host.mark(&marker)?;
    if host.start_unit(&proof.unit).await.is_err() {
        let _ = host.unmark(app_id);
        return Err(refused("search-unit-start-failed"));
    }
    Ok(Prepared::Started(Box::new(entry)))
}

/// The second half, after the wait: bind the marker to the started invocation.
pub async fn finish<H: Host>(
    host: &mut H,
    entry: &Entry,
    owned: bool,
    now_us: u64,
) -> Result<&'static str> {
    let app_id = &entry.manifest.app_id;
    let instance = host.instance(entry).await;
    let invocation_id = instance
        .as_ref()
        .ok()
        .map(|i| i.invocation_id.clone())
        .filter(|id| invocation(id));
    // A late start that may still come up stays recorded as search-started, so
    // a revocation can find it; anything else drops the pending record.
    match &invocation_id {
        Some(id) => host.mark(&Marker {
            app_id: app_id.clone(),
            unit: entry.manifest.unit.clone(),
            invocation_id: Some(id.clone()),
            requested_realtime_us: now_us,
        })?,
        None => host.unmark(app_id)?,
    }
    if !owned {
        return Err(refused("search-activation-timeout"));
    }
    let instance = instance?;
    if !instance.unit.identity_verified || invocation_id.is_none() {
        return Err(refused("search-started-instance-unverified"));
    }
    if !host.owner_is_main(app_id, &instance.unit).await {
        return Err(refused("search-bus-owner-mismatch"));
    }
    Ok("started")
}

/// `ActivateForSearch`: `(true, "started" | "already-running")` or `(false, code)`.
/// `wait` resolves true once the bus name is owned, false at its deadline; it
/// runs without the provider lock. `StartUnit` is never retried.
pub async fn activate<H, W, F>(
    host: &Mutex<H>,
    app_id: &str,
    adapter: bool,
    now_us: u64,
    wait: W,
) -> (bool, String)
where
    H: Host,
    W: FnOnce(String) -> F,
    F: Future<Output = bool>,
{
    let prepared = {
        let mut host = host.lock().await;
        prepare(&mut *host, app_id, adapter, now_us).await
    };
    let entry = match prepared {
        Err(e) => return (false, e.0),
        Ok(Prepared::Running) => return (true, "already-running".into()),
        Ok(Prepared::Started(entry)) => entry,
    };
    let owned = wait(app_id.to_owned()).await;
    let mut host = host.lock().await;
    match finish(&mut *host, &entry, owned, now_us).await {
        Ok(reason) => (true, reason.into()),
        Err(e) => (false, e.0),
    }
}

/// After the `search` source was revoked: stop the instance the broker started
/// for search, only while it is still that invocation, verified, windowless,
/// and its own lifecycle reports nothing it would interrupt. Promotion and
/// agent use are not otherwise observable, so without the lifecycle contract
/// the instance is left to its own idle exit. Returns what happened.
pub async fn revoke<H: Host, G: Check + Sync>(
    host: &mut H,
    app_id: &str,
    guard: &G,
) -> &'static str {
    let Ok(Some(marker)) = host.marker(app_id) else {
        return "not-search-started";
    };
    let Ok(entry) = host.entry(app_id) else {
        return "instance-unobservable";
    };
    let Some(recorded) = marker
        .invocation_id
        .filter(|_| marker.unit == entry.manifest.unit)
    else {
        return "not-search-started";
    };
    let Ok(instance) = host.instance(&entry).await else {
        return "instance-unobservable";
    };
    if !RUNNING.contains(&instance.unit.state.as_str()) {
        let _ = host.unmark(app_id);
        return "not-running";
    }
    if instance.invocation_id != recorded {
        let _ = host.unmark(app_id);
        return "not-search-started";
    }
    if !instance.unit.identity_verified || !instance.windows.known {
        return "instance-unobservable";
    }
    if instance.windows.count > 0 {
        // Promoted to a window: never stopped for search again.
        let _ = host.unmark(app_id);
        return "promoted";
    }
    if !entry.manifest.graceful() {
        return "left-to-idle-exit";
    }
    let Ok(review) = host.lifecycle_query(app_id, &instance.unit).await else {
        return "left-to-idle-exit";
    };
    if review["consequences"]
        .as_array()
        .is_none_or(|c| !c.is_empty())
    {
        return "work-in-progress";
    }
    match host
        .lifecycle_stop(app_id, &instance.unit, &review, guard)
        .await
    {
        Ok(()) => {
            let _ = host.unmark(app_id);
            "stop-requested"
        }
        Err(_) => "left-to-idle-exit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        manifest::GRACEFUL,
        model::tests::{manifest, unit},
    };
    use std::{cell::RefCell, sync::Mutex as StdMutex};

    const APP: &str = "org.example.Music";
    const UNIT: &str = "enzui-agent-org.example.Music.service";
    const EXE: &str = "/usr/bin/music";
    const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

    fn exe() -> Executable {
        Executable {
            path: EXE.into(),
            device: 1,
            inode: 2,
            bytes: 3,
            mtime_ns: 4,
            ctime_ns: 5,
        }
    }
    fn entry(graceful: bool) -> Entry {
        let mut m = manifest(graceful);
        m.activation_sources.push("search".into());
        Entry {
            manifest: m,
            manifest_sha256: "m".into(),
            executable: exe(),
        }
    }
    fn files() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "provider",
                format!(
                    "[enzUI Search Provider]\nDesktopId={APP}.desktop\nBusName={APP}\nObjectPath=/org/example/Music\nVersion=1\n"
                ),
            ),
            (
                "desktop",
                format!(
                    "[Desktop Entry]\nType=Application\nDBusActivatable=true\nExec={EXE} %U\nName=Music\n\n[Desktop Action new]\nName=New\nExec={EXE} --new\n"
                ),
            ),
            (
                "service",
                format!(
                    "# Generated\n[D-BUS Service]\nName={APP}\nExec={EXE} --agent-background\nSystemdService={UNIT}\n"
                ),
            ),
        ])
    }
    fn verify_with(
        entry: &Entry,
        files: &BTreeMap<&'static str, String>,
        identity: Executable,
    ) -> Result<Proof> {
        let read = |path: &Path| -> Result<Vec<u8>> {
            let key = paths(APP)
                .into_iter()
                .find(|(_, p)| p == path)
                .map(|(k, _)| k)
                .unwrap();
            Ok(files[key].clone().into_bytes())
        };
        verify(entry, &read, &|_| Ok(identity.clone()))
    }

    #[test]
    fn declarations_bind_to_the_admitted_unit_and_executable() {
        let proof = verify_with(&entry(false), &files(), exe()).unwrap();
        assert_eq!(
            (
                proof.unit.as_str(),
                proof.bus_name.as_str(),
                proof.min_query_length
            ),
            (UNIT, APP, 2)
        );
        assert_eq!(
            proof
                .declarations_sha256
                .values()
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        let mut changed = files();
        changed
            .get_mut("provider")
            .unwrap()
            .push_str("MinQueryLength=3\n");
        let again = verify_with(&entry(false), &changed, exe()).unwrap();
        assert_eq!(again.min_query_length, 3);
        assert_ne!(again.declarations_sha256, proof.declarations_sha256);
        let mut moved = exe();
        moved.inode = 9;
        assert_eq!(
            verify_with(&entry(false), &files(), moved).unwrap_err().0,
            "search-installed-executable-changed"
        );
    }

    #[test]
    fn cross_app_hidden_and_malformed_declarations_cannot_bind() {
        let changes = [
            (
                "provider",
                format!("BusName={APP}"),
                "BusName=org.example.Other".to_string(),
                "search-provider-binding",
            ),
            (
                "provider",
                "Version=1".into(),
                "Version=2".into(),
                "search-provider-binding",
            ),
            (
                "provider",
                "ObjectPath=/org/example/Music".into(),
                "ObjectPath=/invalid-path".into(),
                "search-object-path",
            ),
            (
                "provider",
                "Version=1".into(),
                "Version=1\nVersion=1".into(),
                "search-declaration-invalid",
            ),
            (
                "provider",
                "Version=1".into(),
                "Version=1\nMinQueryLength=257".into(),
                "search-query-bound",
            ),
            (
                "service",
                UNIT.into(),
                "enzui-agent-org.example.Other.service".into(),
                "search-service-binding",
            ),
            (
                "service",
                format!("Exec={EXE}"),
                "Exec=/usr/bin/sh".into(),
                "search-executable-binding",
            ),
            (
                "desktop",
                "DBusActivatable=true".into(),
                "DBusActivatable=false".into(),
                "search-desktop-unavailable",
            ),
            (
                "desktop",
                "Name=Music\n".into(),
                "Name=Music\nNoDisplay=true\n".into(),
                "search-desktop-unavailable",
            ),
        ];
        for (key, old, new, code) in changes {
            let mut f = files();
            let text = f[key].replacen(&old, &new, 1);
            f.insert(key, text);
            assert_eq!(
                verify_with(&entry(false), &f, exe()).unwrap_err().0,
                code,
                "{new}"
            );
        }
        let mut undeclared = entry(false);
        undeclared
            .manifest
            .activation_sources
            .retain(|s| s != "search");
        assert_eq!(
            verify_with(&undeclared, &files(), exe()).unwrap_err().0,
            "search-installed-source-required"
        );
        for data in [
            &b""[..],
            &[b'x'; 4097][..],
            b"[enzUI Search Provider]\nValue=\0",
            b"\xff",
            b"Version=1\n[enzUI Search Provider]\n",
            b"[DEFAULT]\nVersion=1\n[enzUI Search Provider]\n",
            b"[enzUI Search Provider]\nA=1\n  continued\n",
            b"[a]\n[a]\n",
        ] {
            assert!(section(data, "enzUI Search Provider").is_err(), "{data:?}");
        }
    }

    #[test]
    fn user_local_and_flatpak_overrides_refuse_the_proof() {
        let home = Path::new("/home/u");
        assert!(overridden(APP, home, &|_| false).is_ok());
        for shadow in [
            format!("/home/u/.local/share/enzui/search-providers/{APP}.ini"),
            format!("/home/u/.local/share/applications/{APP}.desktop"),
            format!("/usr/local/share/dbus-1/services/{APP}.service"),
            format!("/var/lib/flatpak/exports/share/applications/{APP}.desktop"),
            format!("/home/u/.local/share/flatpak/exports/share/enzui/search-providers/{APP}.ini"),
        ] {
            assert_eq!(
                overridden(APP, home, &|p| p == Path::new(&shadow))
                    .unwrap_err()
                    .0,
                "search-declaration-overridden",
                "{shadow}"
            );
        }
    }

    /// systemd, the bus and the installed files, in memory.
    struct Fake {
        entry: Entry,
        verified: Result<()>,
        policy: Policy,
        state: String,
        identity_verified: bool,
        invocation: String,
        windows: Windows,
        foreign_owner: bool,
        start_fails: bool,
        /// The unit's state after a start.
        starts_to: String,
        consequences: Value,
        starts: StdMutex<u32>,
        stops: StdMutex<u32>,
        markers: StdMutex<BTreeMap<String, Marker>>,
    }

    impl Fake {
        fn new() -> Self {
            let entry = entry(true);
            let mut policy = crate::model::defaults(&entry.manifest);
            policy.insert("search".into(), true);
            Self {
                entry,
                verified: Ok(()),
                policy,
                state: "inactive".into(),
                identity_verified: false,
                invocation: String::new(),
                windows: crate::model::UNKNOWN_WINDOWS,
                foreign_owner: false,
                start_fails: false,
                starts_to: "active".into(),
                consequences: json!([]),
                starts: StdMutex::new(0),
                stops: StdMutex::new(0),
                markers: StdMutex::new(BTreeMap::new()),
            }
        }
        fn running(mut self) -> Self {
            (self.state, self.identity_verified, self.invocation) =
                ("active".into(), true, INVOCATION.into());
            self.windows = Windows {
                known: true,
                count: 0,
                minimized: 0,
            };
            self
        }
        fn starts(&self) -> u32 {
            *self.starts.lock().unwrap()
        }
        fn marker_of(&self) -> Option<Marker> {
            self.markers.lock().unwrap().get(APP).cloned()
        }
    }

    impl Host for Fake {
        fn entry(&self, app_id: &str) -> Result<Entry> {
            (app_id == APP)
                .then(|| self.entry.clone())
                .ok_or_else(|| refused("installed-application-unavailable"))
        }
        fn verify(&self, _: &Entry) -> Result<Proof> {
            if let Err(e) = &self.verified {
                return Err(refused(&e.0));
            }
            verify_with(&self.entry, &files(), exe())
        }
        fn policy(&self, _: &Manifest) -> Result<Policy> {
            Ok(self.policy.clone())
        }
        async fn instance(&mut self, _: &Entry) -> Result<Instance> {
            let mut u = unit(&self.state, self.identity_verified);
            u.unit = UNIT.into();
            Ok(Instance {
                unit: u,
                invocation_id: self.invocation.clone(),
                windows: self.windows,
            })
        }
        async fn name_owned(&self, _: &str) -> Result<bool> {
            Ok(self.foreign_owner)
        }
        async fn trusted_unit(&mut self, _: &Entry) -> Result<()> {
            Ok(())
        }
        async fn start_unit(&mut self, unit: &str) -> Result<()> {
            assert_eq!(unit, UNIT);
            *self.starts.lock().unwrap() += 1;
            if self.start_fails {
                return Err(refused("start"));
            }
            (self.state, self.identity_verified, self.invocation) =
                (self.starts_to.clone(), true, INVOCATION.into());
            Ok(())
        }
        async fn owner_is_main(&self, _: &str, _: &Unit) -> bool {
            true
        }
        fn marker(&self, app_id: &str) -> Result<Option<Marker>> {
            Ok(self.markers.lock().unwrap().get(app_id).cloned())
        }
        fn mark(&self, marker: &Marker) -> Result<()> {
            self.markers
                .lock()
                .unwrap()
                .insert(marker.app_id.clone(), marker.clone());
            Ok(())
        }
        fn unmark(&self, app_id: &str) -> Result<()> {
            self.markers.lock().unwrap().remove(app_id);
            Ok(())
        }
        async fn lifecycle_query(&self, _: &str, _: &Unit) -> Result<Value> {
            Ok(json!({"revision": "r1", "consequences": self.consequences}))
        }
        async fn lifecycle_stop<G: Check + Sync>(
            &self,
            _: &str,
            _: &Unit,
            _: &Value,
            guard: &G,
        ) -> Result<()> {
            guard.check().await?;
            *self.stops.lock().unwrap() += 1;
            Ok(())
        }
    }

    struct Pass;
    impl Check for Pass {
        async fn check(&self) -> Result<()> {
            Ok(())
        }
    }

    async fn run(fake: Fake, adapter: bool, owned: bool) -> ((bool, String), Fake) {
        let host = Mutex::new(fake);
        let waited = RefCell::new(0);
        let outcome = activate(&host, APP, adapter, 42, |name| {
            assert_eq!(name, APP);
            *waited.borrow_mut() += 1;
            async move { owned }
        })
        .await;
        (outcome, host.into_inner())
    }

    #[tokio::test]
    async fn cold_start_runs_the_fixed_unit_once_and_records_the_invocation() {
        let (outcome, fake) = run(Fake::new(), true, true).await;
        assert_eq!(outcome, (true, "started".into()));
        assert_eq!(fake.starts(), 1);
        let marker = fake.marker_of().unwrap();
        assert_eq!(
            (
                marker.unit.as_str(),
                marker.invocation_id.as_deref(),
                marker.requested_realtime_us
            ),
            (UNIT, Some(INVOCATION), 42)
        );
    }

    #[tokio::test]
    async fn already_running_starts_nothing() {
        let (outcome, fake) = run(Fake::new().running(), true, false).await;
        assert_eq!(outcome, (true, "already-running".into()));
        assert_eq!(fake.starts(), 0);
        assert!(fake.marker_of().is_none());
        // A running process the broker cannot verify is not reported as a provider.
        let mut unverified = Fake::new().running();
        unverified.identity_verified = false;
        assert_eq!(
            run(unverified, true, true).await.0,
            (false, "search-running-instance-unverified".into())
        );
    }

    #[tokio::test]
    async fn source_disabled_by_default_or_denied_refuses_without_starting() {
        let mut fake = Fake::new();
        fake.policy = crate::model::defaults(&fake.entry.manifest);
        assert!(!fake.policy["search"]);
        let (outcome, fake) = run(fake, true, true).await;
        assert_eq!(outcome, (false, "search-activation-disabled".into()));
        assert_eq!(fake.starts(), 0);
        // A saved denial, with every other source allowed.
        let mut denied = Fake::new();
        denied.policy.insert("search".into(), false);
        denied.policy.insert("agent".into(), true);
        let (outcome, denied) = run(denied, true, true).await;
        assert_eq!(outcome, (false, "search-activation-disabled".into()));
        assert_eq!(denied.starts(), 0);
        // And nothing at all while the adapter is not qualified.
        let (outcome, fake) = run(Fake::new(), false, true).await;
        assert_eq!(outcome, (false, "search-policy-adapter-unavailable".into()));
        assert_eq!(fake.starts(), 0);
    }

    #[tokio::test]
    async fn unverified_declaration_or_unknown_app_refuses_without_starting() {
        let mut fake = Fake::new();
        fake.verified = Err(refused("search-declaration-overridden"));
        let (outcome, fake) = run(fake, true, true).await;
        assert_eq!(outcome, (false, "search-declaration-overridden".into()));
        assert_eq!(fake.starts(), 0);
        let host = Mutex::new(Fake::new());
        let outcome = activate(&host, "org.flatpak.Music", true, 1, |_| async { true }).await;
        assert_eq!(outcome, (false, "installed-application-unavailable".into()));
        // A bus name owned outside the unit is not started over.
        let mut foreign = Fake::new();
        foreign.foreign_owner = true;
        let (outcome, foreign) = run(foreign, true, true).await;
        assert_eq!(
            outcome,
            (false, "search-bus-name-owned-outside-unit".into())
        );
        assert_eq!(foreign.starts(), 0);
    }

    #[tokio::test]
    async fn timeout_is_a_typed_refusal_without_retry() {
        let (outcome, fake) = run(Fake::new(), true, false).await;
        assert_eq!(outcome, (false, "search-activation-timeout".into()));
        assert_eq!(fake.starts(), 1);
        // The late instance stays recorded so a revocation can still find it.
        assert_eq!(
            fake.marker_of().unwrap().invocation_id.as_deref(),
            Some(INVOCATION)
        );
        // A failed StartUnit is not retried and leaves no pending record.
        let mut failing = Fake::new();
        failing.start_fails = true;
        let (outcome, failing) = run(failing, true, true).await;
        assert_eq!(outcome, (false, "search-unit-start-failed".into()));
        assert_eq!(failing.starts(), 1);
        assert!(failing.marker_of().is_none());
        // A unit that exited before owning its name leaves no record either.
        let mut exited = Fake::new();
        exited.starts_to = "failed".into();
        let host = Mutex::new(exited);
        let outcome = activate(&host, APP, true, 1, |_| async { false }).await;
        assert!(!outcome.0);
        let mut exited = host.into_inner();
        exited.invocation.clear();
        let entry = exited.entry.clone();
        exited
            .mark(&Marker {
                app_id: APP.into(),
                unit: UNIT.into(),
                invocation_id: None,
                requested_realtime_us: 1,
            })
            .unwrap();
        assert_eq!(
            finish(&mut exited, &entry, false, 1).await.unwrap_err().0,
            "search-activation-timeout"
        );
        assert!(exited.marker_of().is_none());
    }

    #[tokio::test]
    async fn revocation_stops_only_an_idle_unpromoted_search_instance() {
        let (_, mut fake) = run(Fake::new(), true, true).await;
        fake.windows = Windows {
            known: true,
            count: 0,
            minimized: 0,
        };
        assert_eq!(revoke(&mut fake, APP, &Pass).await, "stop-requested");
        assert_eq!(*fake.stops.lock().unwrap(), 1);
        assert!(fake.marker_of().is_none());

        // Promoted to a window: kept, and never considered search-started again.
        let (_, mut promoted) = run(Fake::new(), true, true).await;
        promoted.windows = Windows {
            known: true,
            count: 1,
            minimized: 0,
        };
        assert_eq!(revoke(&mut promoted, APP, &Pass).await, "promoted");
        assert!(promoted.marker_of().is_none());
        assert_eq!(*promoted.stops.lock().unwrap(), 0);

        // Agent or app work in progress: kept.
        let (_, mut busy) = run(Fake::new(), true, true).await;
        busy.windows = Windows {
            known: true,
            count: 0,
            minimized: 0,
        };
        busy.consequences = json!([{"kind": "agent-call", "title": "Agent call", "detail": ""}]);
        assert_eq!(revoke(&mut busy, APP, &Pass).await, "work-in-progress");

        // A later invocation (the user launched it again) is not the search one.
        let (_, mut relaunched) = run(Fake::new(), true, true).await;
        relaunched.windows = Windows {
            known: true,
            count: 0,
            minimized: 0,
        };
        relaunched.invocation = "fedcba9876543210fedcba9876543210".into();
        assert_eq!(
            revoke(&mut relaunched, APP, &Pass).await,
            "not-search-started"
        );

        // Unknown windows or no lifecycle contract: left to idle exit.
        let (_, mut unknown) = run(Fake::new(), true, true).await;
        assert_eq!(
            revoke(&mut unknown, APP, &Pass).await,
            "instance-unobservable"
        );
        let mut plain = Fake::new();
        plain.entry.manifest.graceful_stop = "unavailable".into();
        let (_, mut plain) = run(plain, true, true).await;
        plain.windows = Windows {
            known: true,
            count: 0,
            minimized: 0,
        };
        assert_eq!(revoke(&mut plain, APP, &Pass).await, "left-to-idle-exit");
        assert_eq!(*plain.stops.lock().unwrap(), 0);

        // Started by the user, never by search: nothing recorded, nothing stopped.
        let mut user = Fake::new().running();
        assert_eq!(revoke(&mut user, APP, &Pass).await, "not-search-started");
        assert_eq!(GRACEFUL, "application-lifecycle-v1");
    }
}
