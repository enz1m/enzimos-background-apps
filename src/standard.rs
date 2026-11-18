// SPDX-License-Identifier: MIT
//! Background sources every Linux desktop shares, beside registered native
//! units: Flatpak apps the xdg-desktop-portal background monitor reports
//! (`org.freedesktop.background.Monitor`, the list GNOME Shell shows) and XDG
//! Autostart entries (`~/.config/autostart` over `/etc/xdg/autostart`).
//!
//! These are observations of ordinary user state. Disabling autostart writes
//! the spec's own user override (`Hidden=true`); stopping a portal app does
//! what `flatpak kill` does, for exactly the reported, still-running instance.
use crate::{Result, bounded, process_identity::same_user, refused};
use enzimos_platform::files;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
};
use zbus::{Connection, zvariant::OwnedValue};

/// xdg-desktop-portal owns this name on its own connection for the monitor.
pub const PORTAL: &str = "org.freedesktop.background.Monitor";
pub const MONITOR_PATH: &str = "/org/freedesktop/background/monitor";
const MONITOR: &str = "org.freedesktop.background.Monitor";
pub const SYSTEM_AUTOSTART: &str = "/etc/xdg/autostart";
const MAX_ENTRIES: usize = 256;
const MAX_ENTRY_BYTES: usize = 65536;
/// Marks an override this service wrote for a system entry; enabling removes it.
const OVERRIDE_KEY: &str = "X-enzimOS-Autostart-Override";

/// One Flatpak instance the portal reports as running without windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortalApp {
    pub app_id: String,
    pub instance: String,
    pub message: String,
}

fn flatpak_id(id: &str) -> bool {
    id.len() <= 255
        && id.split('.').count() >= 3
        && id.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
}

fn instance_id(id: &str) -> bool {
    (1..=20).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_digit())
}

/// Display text only: controls and bidi overrides removed, bounded.
fn plain(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control()
                && !('\u{202a}'..='\u{202e}').contains(c)
                && !('\u{2066}'..='\u{2069}').contains(c)
        })
        .take(max)
        .collect()
}

fn string(row: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    row.get(key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| String::try_from(v).ok())
}

/// Validated monitor rows; malformed rows are dropped, never guessed.
pub fn portal_rows(rows: &[HashMap<String, OwnedValue>]) -> Vec<PortalApp> {
    rows.iter()
        .take(MAX_ENTRIES)
        .filter_map(|row| {
            let app_id = string(row, "app_id").filter(|a| flatpak_id(a))?;
            let instance = string(row, "instance").filter(|i| instance_id(i))?;
            Some(PortalApp {
                app_id,
                instance,
                message: string(row, "message")
                    .map(|m| plain(&m, 96))
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// The portal's current list, or `None` when no portal answers (unknown, not empty).
pub async fn portal_apps(bus: &Connection) -> Option<Vec<PortalApp>> {
    let proxy = zbus::proxy::Builder::<zbus::Proxy<'_>>::new(bus)
        .destination(PORTAL)
        .ok()?
        .path(MONITOR_PATH)
        .ok()?
        .interface(MONITOR)
        .ok()?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build();
    let proxy = bounded(proxy, 2, "portal-unavailable").await.ok()?;
    let rows: Vec<HashMap<String, OwnedValue>> = bounded(
        proxy.get_property("BackgroundApps"),
        2,
        "portal-unavailable",
    )
    .await
    .ok()?;
    Some(portal_rows(&rows))
}

/// The Flatpak app a live instance runs, from its own instance record.
pub fn instance_app(runtime: &Path, instance: &str) -> Option<String> {
    if !instance_id(instance) {
        return None;
    }
    let info = files::read_optional(
        &runtime.join(".flatpak").join(instance).join("info"),
        65536,
        None,
        true,
    )
    .ok()??;
    let entries = keyfile(&String::from_utf8_lossy(&info));
    entries
        .get("Application")
        .and_then(|g| g.get("name"))
        .cloned()
        .filter(|a| flatpak_id(a))
}

/// Whether one Flatpak instance is running, decided as flatpak decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceState {
    /// The sandbox's first process (`child-pid`), verified as this instance.
    Running(u32),
    /// Its record is gone or unlocked, or its process exited or was replaced.
    Gone,
    /// Not observable now (starting up, unreadable record or process).
    Unknown,
}

impl InstanceState {
    /// `instance_running` on the wire: `null` when it cannot be observed.
    pub fn value(self) -> Value {
        match self {
            Self::Running(_) => json!(true),
            Self::Gone => json!(false),
            Self::Unknown => Value::Null,
        }
    }
}

fn read_small(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = read_only(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut body)?;
    if body.len() > limit {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(body)
}

/// A running sandbox holds a lock on the instance's `.ref` (bwrap
/// `--lock-file`); flatpak treats an unlocked record as stale.
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn ref_locked(path: &Path) -> Option<bool> {
    let file = match read_only(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } != 0 {
        return None;
    }
    Some(lock.l_type != libc::F_UNLCK as libc::c_short)
}

fn read_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

/// `bwrapinfo.json`'s `child-pid`, the first process inside the sandbox.
fn child_pid(dir: &Path) -> Option<u32> {
    let info = read_small(&dir.join("bwrapinfo.json"), 4096).ok()?;
    let info: Value = serde_json::from_slice(&info).ok()?;
    info.get("child-pid")?
        .as_u64()
        .filter(|p| (2..=i32::MAX as u64).contains(p))
        .map(|p| p as u32)
}

/// The process runs as `uid` and its own `/.flatpak-info` names this app and instance.
fn sandbox_process(proc: &Path, pid: u32, uid: u32, app_id: &str, instance: &str) -> InstanceState {
    let base = proc.join(pid.to_string());
    match std::fs::symlink_metadata(&base) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return InstanceState::Gone,
        Err(_) => return InstanceState::Unknown,
    }
    if !same_user(proc, pid, uid) {
        return InstanceState::Gone;
    }
    let info = match read_small(&base.join("root/.flatpak-info"), 65536) {
        Ok(info) => info,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return InstanceState::Gone,
        Err(_) => return InstanceState::Unknown,
    };
    let groups = keyfile(&String::from_utf8_lossy(&info));
    let field = |group: &str, key: &str| {
        groups
            .get(group)
            .and_then(|g| g.get(key))
            .map(String::as_str)
    };
    if field("Application", "name") == Some(app_id)
        && field("Instance", "instance-id") == Some(instance)
    {
        InstanceState::Running(pid)
    } else {
        InstanceState::Gone
    }
}

/// Cross-check one portal row against the instance itself: its record under
/// `$XDG_RUNTIME_DIR/.flatpak`, the record's lock, and the sandbox process.
/// Nothing is scanned or matched by name.
pub fn instance_state(
    runtime: &Path,
    proc: &Path,
    uid: u32,
    app_id: &str,
    instance: &str,
) -> InstanceState {
    if !instance_id(instance) || !flatpak_id(app_id) {
        return InstanceState::Gone;
    }
    let dir = runtime.join(".flatpak").join(instance);
    match ref_locked(&dir.join(".ref")) {
        Some(true) => {}
        Some(false) => return InstanceState::Gone,
        None => return InstanceState::Unknown,
    }
    // Locked but no bwrap info yet: the sandbox is still starting.
    let Some(pid) = child_pid(&dir) else {
        return InstanceState::Unknown;
    };
    sandbox_process(proc, pid, uid, app_id, instance)
}

/// Stop a reported instance: it must still be in the portal list, its own
/// instance record must name the same app, and its sandbox process must be
/// verified as that instance. Like `flatpak kill`, SIGKILL goes to the
/// sandbox's first process, which takes the whole sandbox with it; here it is
/// sent through a pidfd taken before the final identity check.
///
/// (`flatpak kill` itself finds instances under `$XDG_RUNTIME_DIR`, which a
/// child of this service would not inherit, so it reported "not running".)
pub async fn stop_portal_app(
    bus: &Connection,
    runtime: &Path,
    uid: u32,
    app_id: &str,
    instance: &str,
    caller: &impl crate::Check,
) -> Result<Value> {
    let listed = portal_apps(bus)
        .await
        .ok_or_else(|| refused("portal-unavailable"))?;
    if !listed
        .iter()
        .any(|a| a.app_id == app_id && a.instance == instance)
    {
        return Err(refused("portal-app-not-running-in-background"));
    }
    if instance_app(runtime, instance).as_deref() != Some(app_id) {
        return Err(refused("portal-app-identity-changed"));
    }
    kill_checked(runtime, Path::new("/proc"), uid, app_id, instance, caller).await
}

async fn kill_checked(
    runtime: &Path,
    proc: &Path,
    uid: u32,
    app_id: &str,
    instance: &str,
    caller: &impl crate::Check,
) -> Result<Value> {
    caller.check().await?;
    kill_instance(runtime, proc, uid, app_id, instance)
}

#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
fn kill_instance(
    runtime: &Path,
    proc: &Path,
    uid: u32,
    app_id: &str,
    instance: &str,
) -> Result<Value> {
    let pid = match instance_state(runtime, proc, uid, app_id, instance) {
        InstanceState::Running(pid) => pid,
        InstanceState::Gone => return Err(refused("portal-app-instance-not-running")),
        InstanceState::Unknown => return Err(refused("portal-app-instance-unobservable")),
    };
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0) };
    if fd < 0 {
        return Err(stop_failed());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    // The pidfd now pins the process; the same PID must still be this instance.
    if instance_state(runtime, proc, uid, app_id, instance) != InstanceState::Running(pid) {
        return Err(refused("portal-app-identity-changed"));
    }
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if sent != 0 {
        return Err(stop_failed());
    }
    Ok(json!({"schema": 1, "app_id": app_id, "instance": instance, "state": "stop-requested"}))
}

/// A fixed code that still says why: `portal-app-stop-failed-errno-N`.
fn stop_failed() -> crate::Error {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    refused(&format!("portal-app-stop-failed-errno-{errno}"))
}

/// Minimal desktop-entry key file: group -> key -> value. A repeated key keeps
/// its last value, as GLib and systemd-xdg-autostart-generator do.
pub fn keyfile(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = Some(name.to_owned());
            groups.entry(name.to_owned()).or_default();
            continue;
        }
        if let (Some(group), Some((key, value))) = (&current, line.split_once('=')) {
            groups
                .get_mut(group)
                .unwrap()
                .insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    groups
}

fn list(value: Option<&String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(';')
                .filter(|s| !s.is_empty())
                .map(|s| plain(s, 64))
                .take(16)
                .collect()
        })
        .unwrap_or_default()
}

/// GLib key-file booleans accept true/false and 1/0.
fn truthy(value: Option<&String>) -> bool {
    value.is_some_and(|v| v == "true" || v == "1")
}

/// Autostart file names: ASCII desktop-file IDs only.
pub fn entry_id(name: &str) -> bool {
    name.len() <= 255
        && name.strip_suffix(".desktop").is_some_and(|stem| {
            !stem.is_empty()
                && !stem.starts_with('.')
                && stem
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-+@".contains(&c))
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    User,
    System,
    UserOverride,
}

#[derive(Clone, Debug)]
pub struct Autostart {
    pub id: String,
    pub origin: Origin,
    pub text: String,
    /// The system file's enabled state, when one exists.
    pub system_enabled: Option<bool>,
    /// The system file this row shadows or is, when one exists.
    pub system_text: Option<String>,
}

/// What decides whether an entry actually starts in this session.
pub struct Session {
    pub desktops: Vec<String>,
    /// Where a relative TryExec is looked up: the service runs with a cleared
    /// PATH, so this is a fixed list instead of the login shell's PATH.
    pub bin_dirs: Vec<PathBuf>,
}

impl Session {
    pub fn current(home: &Path) -> Self {
        // The enzUI session file declares DesktopNames=enzUI;Hyprland;.
        let desktops = std::env::var("XDG_CURRENT_DESKTOP")
            .ok()
            .map(|v| {
                v.split(':')
                    .filter(|d| !d.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| vec!["enzUI".into(), "Hyprland".into()]);
        let bin_dirs = vec![
            home.join(".local/bin"),
            "/usr/local/bin".into(),
            "/usr/bin".into(),
            "/usr/sbin".into(),
            home.join(".local/share/flatpak/exports/bin"),
            "/var/lib/flatpak/exports/bin".into(),
        ];
        Self { desktops, bin_dirs }
    }
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn enabled(text: &str) -> bool {
    let groups = keyfile(text);
    let Some(entry) = groups.get("Desktop Entry") else {
        return false;
    };
    !truthy(entry.get("Hidden"))
        && entry
            .get("X-GNOME-Autostart-enabled")
            .is_none_or(|v| v != "false" && v != "0")
}

fn directory_entries(directory: &Path) -> (BTreeMap<String, Option<String>>, bool) {
    let mut found = BTreeMap::new();
    let mut listing = match std::fs::read_dir(directory) {
        Ok(listing) => listing,
        Err(error) => return (found, error.kind() == std::io::ErrorKind::NotFound),
    };
    let mut complete = true;
    for _ in 0..4 * MAX_ENTRIES {
        let item = match listing.next() {
            None => return (found, complete),
            Some(Ok(item)) => item,
            Some(Err(_)) => {
                complete = false;
                continue;
            }
        };
        let Some(name) = item
            .file_name()
            .to_str()
            .map(str::to_owned)
            .filter(|n| entry_id(n))
        else {
            continue;
        };
        if found.len() >= MAX_ENTRIES {
            return (found, false);
        }
        found.insert(name.clone(), read_entry(&directory.join(name)));
    }
    (found, false)
}

fn read_entry(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_ENTRY_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .ok()?;
    (body.len() <= MAX_ENTRY_BYTES).then(|| String::from_utf8_lossy(&body).into_owned())
}

/// XDG Autostart resolution: a user file replaces a system file of the same name.
pub fn autostart(user: &Path, system: &Path) -> Vec<Autostart> {
    autostart_inventory(user, system).0
}

pub fn autostart_inventory(user: &Path, system: &Path) -> (Vec<Autostart>, bool) {
    let (system, system_complete) = directory_entries(system);
    let (mut user, user_complete) = directory_entries(user);
    let mut rows = Vec::new();
    for (id, text) in system {
        let system_enabled = text.as_ref().map(|text| enabled(text));
        let override_text = user.remove(&id);
        let overridden = override_text.is_some() || !user_complete;
        let selected = if overridden {
            override_text.flatten()
        } else {
            text.clone()
        };
        rows.push(Autostart {
            id,
            origin: if overridden {
                Origin::UserOverride
            } else {
                Origin::System
            },
            text: selected.unwrap_or_default(),
            system_enabled,
            system_text: text,
        });
    }
    rows.extend(user.into_iter().map(|(id, text)| Autostart {
        id,
        origin: Origin::User,
        text: text.unwrap_or_default(),
        system_enabled: None,
        system_text: None,
    }));
    let readable = rows
        .iter()
        .all(|row| keyfile(&row.text).contains_key("Desktop Entry"));
    (rows, system_complete && user_complete && readable)
}

/// `enabled` is the user's setting; `runs_here` also applies the spec's
/// OnlyShowIn/NotShowIn and TryExec, as the session's autostart does.
pub fn autostart_value(row: &Autostart, session: &Session) -> Value {
    let groups = keyfile(&row.text);
    let empty = BTreeMap::new();
    let entry = groups.get("Desktop Entry").unwrap_or(&empty);
    let try_exec = entry.get("TryExec").filter(|t| !t.is_empty());
    let missing = try_exec.is_some_and(|t| {
        if t.starts_with('/') {
            !executable(Path::new(t))
        } else {
            t.contains('/') || !session.bin_dirs.iter().any(|d| executable(&d.join(t)))
        }
    });
    let names = |key: &str| {
        entry
            .get(key)
            .map(|v| v.split(';').filter(|s| !s.is_empty()).collect::<Vec<_>>())
    };
    let here = |list: &[&str]| session.desktops.iter().any(|d| list.contains(&d.as_str()));
    let shown = names("OnlyShowIn").is_none_or(|l| here(&l))
        && !names("NotShowIn").is_some_and(|l| here(&l));
    let observable = groups.contains_key("Desktop Entry");
    let enabled = enabled(&row.text);
    json!({
        "id": row.id,
        "name": plain(entry.get("Name").map(String::as_str).unwrap_or(row.id.trim_end_matches(".desktop")), 96),
        "origin": match row.origin { Origin::User => "user", Origin::System => "system", Origin::UserOverride => "user-override" },
        "observable": observable,
        "enabled": observable.then_some(enabled),
        "runs_here": observable.then_some(enabled && shown && !missing),
        "flatpak_app_id": entry.get("X-Flatpak").filter(|a| flatpak_id(a)),
        "only_show_in": list(entry.get("OnlyShowIn")),
        "not_show_in": list(entry.get("NotShowIn")),
        "program_missing": missing,
    })
}

/// The user file that gives `row` the requested state, or `None` to delete the
/// user file (an override this service wrote, when the system file already
/// has the requested state).
pub fn override_text(row: &Autostart, wanted: bool) -> Option<String> {
    let groups = keyfile(&row.text);
    let ours = groups
        .get("Desktop Entry")
        .is_some_and(|e| truthy(e.get(OVERRIDE_KEY)));
    // A stub override (no Exec, typically just Hidden=true) only exists to hide
    // the system entry; when the system entry already has the wanted state,
    // removing the stub is what restores it.
    let stub = groups
        .get("Desktop Entry")
        .is_none_or(|e| !e.contains_key("Exec"));
    if row.origin == Origin::UserOverride && (ours || stub) && row.system_enabled == Some(wanted) {
        return None;
    }
    // Overriding a system entry starts from the system file itself: a stub has
    // no Exec, and the session ignores an enabled entry without one.
    let (base, marker) = match (&row.origin, &row.system_text) {
        (Origin::System, _) => (&row.text, true),
        (Origin::UserOverride, Some(system)) if ours || stub => (system, true),
        _ => (&row.text, false),
    };
    let mut out = String::new();
    let mut in_entry = false;
    let mut inserted = false;
    for line in base.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if in_entry && !inserted {
                out.push_str(&state_lines(wanted, marker));
                inserted = true;
            }
            in_entry = trimmed == "[Desktop Entry]";
        } else if in_entry {
            let key = trimmed.split_once('=').map(|(k, _)| k.trim());
            if matches!(key, Some("Hidden" | "X-GNOME-Autostart-enabled"))
                || key == Some(OVERRIDE_KEY)
            {
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_entry && !inserted {
        out.push_str(&state_lines(wanted, marker));
    }
    Some(out)
}

fn state_lines(wanted: bool, marker: bool) -> String {
    let mut lines = format!("Hidden={}\n", if wanted { "false" } else { "true" });
    if marker {
        lines.push_str(OVERRIDE_KEY);
        lines.push_str("=true\n");
    }
    lines
}

/// Apply an enable/disable in the user's own autostart directory.
pub fn set_autostart(
    user: &Path,
    system: &Path,
    uid: u32,
    id: &str,
    wanted: bool,
) -> Result<Value> {
    if !entry_id(id) {
        return Err(refused("autostart-entry-unknown"));
    }
    let row = autostart(user, system)
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| refused("autostart-entry-unknown"))?;
    if !keyfile(&row.text).contains_key("Desktop Entry") {
        return Err(refused("autostart-entry-invalid"));
    }
    if enabled(&row.text) == wanted {
        return Ok(json!({"schema": 1, "id": id, "enabled": wanted, "changed": false}));
    }
    ensure_directory(user, uid)?;
    let path = user.join(id);
    let failed = |_| refused("autostart-write-failed");
    match override_text(&row, wanted) {
        None => std::fs::remove_file(&path).map_err(failed)?,
        Some(text) => {
            // A linked entry was read through its link; writes never follow
            // one, so the link is replaced by a standalone copy.
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                replace_link(user, uid, id, &text)
                    .map_err(|_| refused("autostart-write-failed"))?;
            } else {
                files::atomic_bounded(
                    &path,
                    text.as_bytes(),
                    0o644,
                    Some(uid),
                    true,
                    MAX_ENTRY_BYTES,
                )
                .map_err(|_| refused("autostart-write-failed"))?;
            }
        }
    }
    Ok(json!({"schema": 1, "id": id, "enabled": wanted, "changed": true}))
}

fn replace_link(user: &Path, uid: u32, id: &str, text: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = files::directory(user, Some(uid))?;
    let retained = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
    let target = retained.join(id);
    let original = std::fs::symlink_metadata(&target)?;
    if !original.file_type().is_symlink() || original.uid() != uid {
        return Err(refused("autostart-write-failed"));
    }
    let temporary = format!(".autostart-{}", files::random_hex(16)?);
    files::atomic_relative(
        &parent,
        Path::new(&temporary),
        text.as_bytes(),
        0o644,
        Some(uid),
        false,
        MAX_ENTRY_BYTES,
    )?;
    let result = (|| -> Result<()> {
        let current = std::fs::symlink_metadata(&target)?;
        if (current.dev(), current.ino()) != (original.dev(), original.ino()) {
            return Err(refused("autostart-entry-changed"));
        }
        std::fs::rename(retained.join(&temporary), &target)?;
        parent.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(retained.join(temporary));
    result.map_err(|_| refused("autostart-write-failed"))
}

fn ensure_directory(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && m.uid() == uid && m.mode() & 0o022 == 0 => Ok(()),
        Ok(_) => Err(refused("autostart-directory-unsafe")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o755)
            .create(path)
            .map_err(|_| refused("autostart-write-failed")),
        Err(_) => Err(refused("autostart-write-failed")),
    }
}

pub fn user_config(home: &Path) -> PathBuf {
    // Dotfile managers often make ~/.config a symlink; resolve it once so reads
    // and writes use the same real directory.
    std::fs::canonicalize(home.join(".config")).unwrap_or_else(|_| home.join(".config"))
}

/// ~/.config/autostart, resolved when it is a link to the user's own private
/// directory (dotfile managers again); any other link stays unresolved, so
/// reads follow it but writes refuse it.
pub fn user_autostart(home: &Path, uid: u32) -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    let path = user_config(home).join("autostart");
    if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return path;
    }
    match std::fs::canonicalize(&path) {
        Ok(real)
            if std::fs::symlink_metadata(&real)
                .is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o022 == 0) =>
        {
            real
        }
        _ => path,
    }
}

#[cfg(test)]
mod tests;
