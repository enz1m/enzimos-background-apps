// SPDX-License-Identifier: MIT
//! On-demand user service with coalesced unit, window and installed-catalogue events.
use crate::{
    Result,
    authority::Authority,
    dispatch::{self, Guard},
    provider::{Provider, UnitEvent},
    refused, runtime_trust, search, standard, window_observation,
};
use enzimos_system_backend::authority::Authority as SystemAuthority;
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{io::unix::AsyncFd, sync::Mutex};
use zbus::{
    Connection, MatchRule, MessageStream,
    message::{Header, Type},
    object_server::SignalEmitter,
};

pub const NAME: &str = "org.enzimos.Background1";
pub const PATH: &str = "/org/enzimos/Background1";
const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";
const IDLE: Duration = Duration::from_secs(60);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.enzimos.Background1")]
pub enum Refusal {
    #[zbus(error)]
    ZBus(zbus::Error),
    Refused(String),
}

/// Only fixed lowercase codes cross the bus; anything else is generic.
pub fn public(error: crate::Error) -> Refusal {
    let code = &error.0;
    let fixed = code.len() <= 96
        && code.starts_with(|c: char| c.is_ascii_lowercase())
        && code
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    Refusal::Refused(if fixed {
        code.clone()
    } else {
        "operation-unavailable-or-outcome-unknown".into()
    })
}

/// `search_policy_adapter` needs both the qualified adapter and the matched MCP
/// reader: the default-false source cannot be enabled without the latter.
pub fn capabilities(agent_policy_adapter: bool, search_adapter: bool) -> Value {
    json!({"schema": 1, "registered_native_units": true, "unknown_windows_preserved": true,
        "unknown_work_preserved": true, "graceful_lifecycle_adapter": true, "window_adapter": true,
        "work_adapter": false, "flatpak_background_adapter": true, "xdg_autostart_adapter": true, "scheduled_adapter": false,
        "search_policy_adapter": search_adapter && agent_policy_adapter, "ongoing_work_policy_adapter": false,
        "stopping_revokes_future_activation": false, "agent_policy_requires_qualified_mcp_gate": true,
        "agent_policy_adapter": agent_policy_adapter, "idle_exit_seconds": IDLE.as_secs()})
}

struct Activity {
    active: AtomicUsize,
    last: std::sync::Mutex<Instant>,
}

impl Activity {
    fn begin(self: &Arc<Self>) -> ActiveCall {
        self.active.fetch_add(1, Ordering::SeqCst);
        ActiveCall(self.clone())
    }
    fn idle_for(&self) -> Option<Duration> {
        (self.active.load(Ordering::SeqCst) == 0).then(|| self.last.lock().unwrap().elapsed())
    }
}

struct ActiveCall(Arc<Activity>);
impl Drop for ActiveCall {
    fn drop(&mut self) {
        *self.0.last.lock().unwrap() = Instant::now();
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Service {
    bus: Connection,
    provider: Arc<Mutex<Provider>>,
    authority: Arc<Authority>,
    activity: Arc<Activity>,
    /// One search activation at a time: a second call sees the first's outcome.
    search_gate: Mutex<()>,
}

/// The bus code of a refusal, as `public` would send it.
fn code(error: crate::Error) -> String {
    match public(error) {
        Refusal::Refused(code) => code,
        Refusal::ZBus(_) => "operation-unavailable-or-outcome-unknown".into(),
    }
}

/// Whether `name` gets an owner before `deadline`. Subscribes first, then
/// asks, so an owner appearing in between is not missed. Never starts a name.
async fn name_owned_by(bus: &Connection, name: &str, deadline: Duration) -> bool {
    let wait = async {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender("org.freedesktop.DBus")?
            .interface("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .arg(0, name)?
            .build();
        let mut stream = MessageStream::for_match_rule(rule, bus, Some(8)).await?;
        let daemon = zbus::fdo::DBusProxy::new(bus).await?;
        if daemon
            .name_has_owner(zbus::names::BusName::try_from(name)?)
            .await?
        {
            return Ok::<bool, zbus::Error>(true);
        }
        while let Some(message) = stream.next().await {
            if let Ok((changed, _, new)) = message?.body().deserialize::<(String, String, String)>()
                && changed == name
                && !new.is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    matches!(tokio::time::timeout(deadline, wait).await, Ok(Ok(true)))
}

impl Service {
    fn sender(header: &Header<'_>) -> std::result::Result<String, Refusal> {
        header
            .sender()
            .map(|s| s.to_string())
            .filter(|s| dispatch::sender(s))
            .ok_or_else(|| public(refused("unique-user-bus-sender-required")))
    }

    async fn review(&self, header: &Header<'_>, body: &str, stop: bool) -> Result<Value> {
        let sender =
            Self::sender(header).map_err(|_| refused("unique-user-bus-sender-required"))?;
        dispatch::trusted_peer(&self.authority, &sender).await?;
        let field = if stop { "mode" } else { "policy" };
        let request = dispatch::decode(body, &["app_id", field])?;
        let app = request["app_id"].as_str().unwrap_or_default();
        let mut provider = self.provider.lock().await;
        let review = if stop {
            provider
                .review_stop(
                    app,
                    request["mode"]
                        .as_str()
                        .ok_or_else(|| refused("background-stop-unavailable"))?,
                )
                .await?
        } else {
            provider.review_policy(app, &request["policy"]).await?
        };
        Ok(review.value())
    }

    async fn commit(&self, header: &Header<'_>, body: &str, stop: bool) -> Result<Value> {
        let arrived = Instant::now();
        let field = if stop { "mode" } else { "policy" };
        let (request, digest, valid) = dispatch::commit_request(body, field)?;
        let sender =
            Self::sender(header).map_err(|_| refused("unique-user-bus-sender-required"))?;
        let guard = Guard {
            authority: &self.authority,
            peer: dispatch::trusted_peer(&self.authority, &sender).await?,
            sender,
            deadline: arrived + Duration::from_millis(valid),
        };
        let app = request["app_id"].as_str().unwrap_or_default();
        let mut provider = self.provider.lock().await;
        if stop {
            let mode = request["mode"]
                .as_str()
                .ok_or_else(|| refused("background-stop-unavailable"))?;
            let result = provider.stop(app, mode, &digest, &guard).await?;
            if result["result"]["mode"] != mode {
                return Err(refused("application-stop-outcome-unknown"));
            }
            Ok(result)
        } else {
            let result = provider
                .set_policy(app, &request["policy"], &digest, &guard)
                .await?;
            drop(provider);
            // Readers holding a provider (the shell's Search) re-check it.
            let _ = self
                .bus
                .emit_signal(None::<()>, PATH, NAME, "PolicyChanged", &(app,))
                .await;
            Ok(result)
        }
    }
}

fn reply(value: Result<Value>) -> std::result::Result<String, Refusal> {
    value.map(|v| v.to_string()).map_err(public)
}

#[zbus::interface(name = "org.enzimos.Background1")]
impl Service {
    async fn get_capabilities(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        Self::sender(&header)?;
        let mut provider = self.provider.lock().await;
        let available = provider.agent_policy_available().await;
        Ok(capabilities(available, provider.search_adapter).to_string())
    }

    async fn query(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        let sender = Self::sender(&header)?;
        reply(
            async {
                dispatch::trusted_peer(&self.authority, &sender).await?;
                self.provider.lock().await.query().await
            }
            .await,
        )
    }

    async fn review_stop(
        &self,
        #[zbus(header)] header: Header<'_>,
        body: String,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        reply(self.review(&header, &body, true).await)
    }

    async fn stop(
        &self,
        #[zbus(header)] header: Header<'_>,
        body: String,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        reply(self.commit(&header, &body, true).await)
    }

    async fn review_policy(
        &self,
        #[zbus(header)] header: Header<'_>,
        body: String,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        reply(self.review(&header, &body, false).await)
    }

    async fn set_policy(
        &self,
        #[zbus(header)] header: Header<'_>,
        body: String,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        reply(self.commit(&header, &body, false).await)
    }

    /// Stop one Flatpak instance the portal reports as running in the background.
    async fn stop_portal_app(
        &self,
        #[zbus(header)] header: Header<'_>,
        body: String,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        let sender = Self::sender(&header)?;
        reply(
            async {
                let arrived = Instant::now();
                let guard = Guard {
                    authority: &self.authority,
                    peer: dispatch::trusted_peer(&self.authority, &sender).await?,
                    sender,
                    deadline: arrived + Duration::from_secs(30),
                };
                let request = dispatch::decode(&body, &["app_id", "instance"])?;
                let instance = request["instance"]
                    .as_str()
                    .ok_or_else(|| refused("request-fields"))?;
                // Portal reads and `flatpak kill` take seconds; never hold the provider
                // lock (queries, bus events) across them.
                let (bus, runtime, uid) = self.provider.lock().await.portal_handles();
                let result = standard::stop_portal_app(
                    &bus,
                    &runtime,
                    uid,
                    request["app_id"].as_str().unwrap_or_default(),
                    instance,
                    &guard,
                )
                .await;
                self.provider.lock().await.standard_changed();
                result
            }
            .await,
        )
    }

    /// Enable or disable one XDG Autostart entry through the user's own override.
    async fn set_autostart(
        &self,
        #[zbus(header)] header: Header<'_>,
        body: String,
    ) -> std::result::Result<String, Refusal> {
        let _call = self.activity.begin();
        let sender = Self::sender(&header)?;
        reply(
            async {
                dispatch::trusted_peer(&self.authority, &sender).await?;
                let request = dispatch::decode(&body, &["id", "enabled"])?;
                let (Some(id), Some(enabled)) =
                    (request["id"].as_str(), request["enabled"].as_bool())
                else {
                    return Err(refused("request-fields"));
                };
                self.provider.lock().await.set_autostart(id, enabled)
            }
            .await,
        )
    }

    /// Start an installed native search provider for the desktop's Search.
    /// `(true, "started" | "already-running")`, or `(false, code)` within about
    /// a second; the unit is started at most once per call.
    async fn activate_for_search(
        &self,
        #[zbus(header)] header: Header<'_>,
        app_id: String,
    ) -> (bool, String) {
        let _call = self.activity.begin();
        let _serial = self.search_gate.lock().await;
        let admitted = async {
            let sender =
                Self::sender(&header).map_err(|_| refused("unique-user-bus-sender-required"))?;
            if !dispatch::trusted_peer(&self.authority, &sender)
                .await?
                .shell
            {
                return Err(refused("search-caller-not-shell"));
            }
            if !crate::manifest::app_id(&app_id) {
                return Err(refused("request-app-identity"));
            }
            Ok(())
        }
        .await;
        if let Err(error) = admitted {
            return (false, code(error));
        }
        let adapter = self.provider.lock().await.search_adapter;
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as u64);
        let bus = self.bus.clone();
        let (started, reason) = search::activate(
            &*self.provider,
            &app_id,
            adapter,
            now_us,
            |name| async move { name_owned_by(&bus, &name, search::START_DEADLINE).await },
        )
        .await;
        (started, code(refused(&reason)))
    }

    #[zbus(signal)]
    async fn changed(emitter: &SignalEmitter<'_>, generation: u64) -> zbus::Result<()>;

    /// A committed activation policy change for `app_id`.
    #[zbus(signal)]
    async fn policy_changed(emitter: &SignalEmitter<'_>, app_id: &str) -> zbus::Result<()>;
}

/// Refuse unless running as an ordinary user in the Root-recorded namespace with
/// a private runtime directory; then reset the process environment.
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
/// # Safety
/// Call only during single-threaded startup, with no outstanding native
/// environment borrows. This function replaces the process environment.
///
/// # Errors
/// Rejects an invalid caller identity, unsafe runtime context or unavailable account data.
pub unsafe fn runtime_guard() -> Result<String> {
    let uid = unsafe { libc::getuid() };
    if uid < 1000 || uid != unsafe { libc::geteuid() } {
        return Err(refused("isolated-local-user-service-required"));
    }
    runtime_trust::check()?;
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let m = fs::symlink_metadata(&runtime)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(refused("private-user-runtime-required"));
    }
    let bus = runtime.join("bus");
    let m = fs::symlink_metadata(&bus)?;
    if !m.file_type().is_socket() || m.uid() != uid {
        return Err(refused("private-user-bus-required"));
    }
    let home = enzimos_platform::accounts::lookup_uid(uid)
        .map(|a| a.home)
        .map_err(|_| refused("isolated-local-user-service-required"))?;
    std::env::set_current_dir("/")?;
    for (key, _) in std::env::vars_os() {
        unsafe { std::env::remove_var(key) };
    }
    unsafe {
        std::env::set_var("PATH", "/usr/bin");
        std::env::set_var("LANG", "C.UTF-8");
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }
    Ok(format!("unix:path={}", bus.display()))
}

/// The fixed local system bus, never one named by the environment.
fn system_bus_guard() -> Result<()> {
    let socket = Path::new(SYSTEM_BUS);
    if fs::canonicalize(socket)? != socket {
        return Err(refused("unsafe-system-bus-path"));
    }
    for parent in socket.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(refused("unsafe-system-bus-parent"));
        }
    }
    let m = fs::symlink_metadata(socket)?;
    if !m.file_type().is_socket() || m.uid() != 0 {
        return Err(refused("unsafe-system-bus-socket"));
    }
    Ok(())
}

/// Directory change notifications for the installed catalogue and preferences.
struct Watch {
    fd: AsyncFd<std::os::fd::OwnedFd>,
    /// Watch on ~/.config, where only `autostart` itself appearing matters.
    parent: std::sync::atomic::AtomicI32,
}

impl Watch {
    #[allow(unsafe_code, reason = "Linux syscall ABI (inotify_init1).")]
    fn new() -> Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(refused("catalogue-watch-unavailable"));
        }
        let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            parent: i32::MIN.into(),
        })
    }
    /// ~/.config/autostart may not exist yet; learn when it is created.
    #[allow(unsafe_code, reason = "Linux syscall ABI (inotify_add_watch).")]
    fn add_parent(&self, path: &Path) {
        use std::os::fd::AsRawFd;
        let mask = libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_ONLYDIR | libc::IN_DONT_FOLLOW;
        if let Ok(name) = CString::new(path.as_os_str().as_encoded_bytes()) {
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), mask) };
            if wd >= 0 {
                self.parent.store(wd, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    /// Read every queued event; whether any of them should trigger a refresh.
    #[allow(unsafe_code, reason = "Linux syscall ABI (read).")]
    fn drain(&self) -> bool {
        use std::os::fd::AsRawFd;
        let parent = self.parent.load(std::sync::atomic::Ordering::Relaxed);
        let mut buffer = [0u8; 4096];
        let mut relevant = false;
        loop {
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n <= 0 {
                return relevant;
            }
            let events = &buffer[..n as usize];
            let mut at = 0;
            while at + 16 <= events.len() {
                let field =
                    |o: usize| u32::from_ne_bytes(events[at + o..at + o + 4].try_into().unwrap());
                let (wd, mask, len) = (field(0) as i32, field(4), field(12) as usize);
                let name = events.get(at + 16..at + 16 + len).unwrap_or_default();
                relevant |= wd != parent
                    || mask & libc::IN_Q_OVERFLOW != 0
                    || name.split(|b| *b == 0).next() == Some(b"autostart");
                at += 16 + len;
            }
        }
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (inotify_add_watch).")]
    fn add(&self, paths: &[PathBuf]) {
        use std::os::fd::AsRawFd;
        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_CLOSE_WRITE
            | libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_ONLYDIR
            | libc::IN_DONT_FOLLOW;
        for path in paths {
            if let Ok(name) = CString::new(path.as_os_str().as_encoded_bytes()) {
                unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), mask) };
            }
        }
    }
    async fn changed(&self) -> Result<()> {
        loop {
            let mut guard = self.fd.readable().await?;
            let relevant = self.drain();
            guard.clear_ready();
            if relevant {
                return Ok(());
            }
        }
    }
}

async fn signal_stream(bus: &Connection, rule: MatchRule<'static>) -> Result<MessageStream> {
    MessageStream::for_match_rule(rule, bus, Some(64))
        .await
        .map_err(|_| refused("bus-subscription-unavailable"))
}

fn rule(
    sender: Option<&'static str>,
    interface: &'static str,
    member: &'static str,
) -> Result<MatchRule<'static>> {
    let mut builder = MatchRule::builder().msg_type(Type::Signal);
    if let Some(sender) = sender {
        builder = builder
            .sender(sender)
            .map_err(|_| refused("bus-subscription-unavailable"))?;
    }
    Ok(builder
        .interface(interface)
        .and_then(|b| b.member(member))
        .map_err(|_| refused("bus-subscription-unavailable"))?
        .build())
}

/// Window changes only from the shell's object path; the sender is checked on apply.
fn window_rule() -> Result<MatchRule<'static>> {
    MatchRule::builder()
        .msg_type(Type::Signal)
        .path(window_observation::PATH)
        .and_then(|b| b.interface(window_observation::INTERFACE))
        .and_then(|b| b.member("Changed"))
        .map(|b| b.build())
        .map_err(|_| refused("bus-subscription-unavailable"))
}

/// The portal's background list changes (sender filtered by name).
fn portal_rule() -> Result<MatchRule<'static>> {
    MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(standard::PORTAL)
        .and_then(|b| b.path(standard::MONITOR_PATH))
        .and_then(|b| b.interface("org.freedesktop.DBus.Properties"))
        .and_then(|b| b.member("PropertiesChanged"))
        .map(|b| b.build())
        .map_err(|_| refused("bus-subscription-unavailable"))
}

/// Pending events are bounded; past this, they collapse into one full invalidation.
const EVENT_QUEUE: usize = 256;

/// One bus event that may invalidate cached observations.
enum Event {
    NameOwner(String),
    Unit(String),
    Windows(Option<String>),
    /// `UnitNew`/`UnitRemoved` for this unit name.
    UnitLoad(String),
    /// `UnitFilesChanged` or `Reloading`.
    UnitFiles,
    Standard,
}

/// Drain the signal streams without ever waiting on the provider lock: a method
/// call may hold that lock while awaiting a systemd reply, and a stalled stream
/// would stop zbus from reading that reply.
async fn events(
    bus: Connection,
    sink: tokio::sync::mpsc::Sender<Event>,
    overflow: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let streams = vec![
        signal_stream(
            &bus,
            rule(
                Some("org.freedesktop.DBus"),
                "org.freedesktop.DBus",
                "NameOwnerChanged",
            )?,
        )
        .await?,
        signal_stream(
            &bus,
            rule(
                Some("org.freedesktop.systemd1"),
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
            )?,
        )
        .await?,
        signal_stream(
            &bus,
            rule(
                Some("org.freedesktop.systemd1"),
                "org.freedesktop.systemd1.Manager",
                "UnitNew",
            )?,
        )
        .await?,
        signal_stream(
            &bus,
            rule(
                Some("org.freedesktop.systemd1"),
                "org.freedesktop.systemd1.Manager",
                "UnitRemoved",
            )?,
        )
        .await?,
        signal_stream(
            &bus,
            rule(
                Some("org.freedesktop.systemd1"),
                "org.freedesktop.systemd1.Manager",
                "UnitFilesChanged",
            )?,
        )
        .await?,
        signal_stream(
            &bus,
            rule(
                Some("org.freedesktop.systemd1"),
                "org.freedesktop.systemd1.Manager",
                "Reloading",
            )?,
        )
        .await?,
        signal_stream(&bus, window_rule()?).await?,
        signal_stream(&bus, portal_rule()?).await?,
    ];
    let mut merged = futures_util::stream::select_all(streams);
    while let Some(message) = merged.next().await {
        let Ok(message) = message else { continue };
        let header = message.header();
        let event = match header.member().map(|m| m.as_str()).unwrap_or_default() {
            "NameOwnerChanged" => match message.body().deserialize::<(String, String, String)>() {
                Ok((name, _, _)) => Event::NameOwner(name),
                Err(_) => continue,
            },
            "PropertiesChanged"
                if header
                    .path()
                    .is_some_and(|p| p.as_str() == standard::MONITOR_PATH) =>
            {
                Event::Standard
            }
            "PropertiesChanged" => {
                Event::Unit(header.path().map(|p| p.to_string()).unwrap_or_default())
            }
            "Changed"
                if header
                    .path()
                    .is_some_and(|p| p.as_str() == window_observation::PATH) =>
            {
                Event::Windows(header.sender().map(|s| s.to_string()))
            }
            "Changed" => continue,
            "UnitNew" | "UnitRemoved" => match message
                .body()
                .deserialize::<(String, zbus::zvariant::OwnedObjectPath)>()
            {
                Ok((unit, _)) => Event::UnitLoad(unit),
                Err(_) => continue,
            },
            _ => Event::UnitFiles,
        };
        match sink.try_send(event) {
            Ok(()) => {}
            // A peer flooding signals cannot grow memory: remember that
            // something was dropped and invalidate everything instead.
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                overflow.store(true, Ordering::Relaxed)
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
    Ok(())
}

async fn apply(
    provider: Arc<Mutex<Provider>>,
    mut events: tokio::sync::mpsc::Receiver<Event>,
    overflow: Arc<std::sync::atomic::AtomicBool>,
) {
    while let Some(event) = events.recv().await {
        let mut provider = provider.lock().await;
        if overflow.swap(false, Ordering::Relaxed) {
            provider.windows.invalidate();
            provider.changed(None);
        }
        match event {
            Event::NameOwner(name) if name == window_observation::NAME => {
                provider.windows.owner_lost();
                provider.changed(None);
            }
            Event::NameOwner(name) => {
                if provider.catalogue.apps.contains_key(&name) {
                    provider.changed(Some(&name));
                }
            }
            Event::Unit(path) => {
                if let Some(app) = provider.app_for_path(&path) {
                    provider.changed(Some(&app));
                }
            }
            Event::Windows(sender) => {
                if sender.is_some() && sender == provider.windows.owner {
                    provider.windows.invalidate();
                    provider.changed(None);
                }
            }
            // Loading a unit only to read it, and its garbage collection, are
            // not changes: only units behind a row invalidate anything.
            Event::UnitLoad(unit) => match provider.unit_event(&unit) {
                UnitEvent::App(app) => provider.changed(Some(&app)),
                UnitEvent::Flatpak => provider.standard_changed(),
                UnitEvent::Ignore => {}
            },
            Event::UnitFiles => provider.unit_files_changed(),
            Event::Standard => provider.standard_changed(),
        }
    }
}

#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
pub async fn serve(address: String) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let home = PathBuf::from(
        std::env::var_os("HOME").ok_or_else(|| refused("isolated-local-user-service-required"))?,
    );
    let bus = zbus::connection::Builder::address(address.as_str())
        .map_err(|_| refused("private-user-bus-required"))?
        .build()
        .await
        .map_err(|_| refused("private-user-bus-required"))?;
    system_bus_guard()?;
    let system = zbus::connection::Builder::address(format!("unix:path={SYSTEM_BUS}").as_str())
        .map_err(|_| refused("unsafe-system-bus-socket"))?
        .build()
        .await
        .map_err(|_| refused("unsafe-system-bus-socket"))?;
    let authority = Arc::new(Authority::new(
        bus.clone(),
        SystemAuthority::sessions(system).await?,
        uid,
    ));
    let provider = Provider::new(bus.clone(), uid, &home)?;
    provider.subscribe().await?;
    let notify = provider.notify.clone();
    let (watched, autostart_parent) = (provider.watched(), provider.autostart_parent());
    let provider = Arc::new(Mutex::new(provider));
    let activity = Arc::new(Activity {
        active: AtomicUsize::new(0),
        last: std::sync::Mutex::new(Instant::now()),
    });
    let service = Service {
        bus: bus.clone(),
        provider: provider.clone(),
        authority: authority.clone(),
        activity: activity.clone(),
        search_gate: Mutex::new(()),
    };
    bus.object_server()
        .at(PATH, service)
        .await
        .map_err(|_| refused("service-registration-failed"))?;
    bus.request_name_with_flags(NAME, zbus::fdo::RequestNameFlags::DoNotQueue.into())
        .await
        .map_err(|_| refused("service-name-unavailable"))?;

    let (sink, queue) = tokio::sync::mpsc::channel(EVENT_QUEUE);
    let overflow = Arc::new(std::sync::atomic::AtomicBool::new(false));
    tokio::spawn(events(bus.clone(), sink, overflow.clone()));
    tokio::spawn(apply(provider.clone(), queue, overflow));
    let emitter_bus = bus.clone();
    let emitter_provider = provider.clone();
    tokio::spawn(async move {
        let mut signalled = 0;
        loop {
            notify.notified().await;
            // Coalesce a burst of events into one re-read.
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Signal only a snapshot that differs from the last one signalled; a
            // reader's own Query may already have observed it first.
            let generation = emitter_provider.lock().await.observe_generation().await;
            if generation != signalled {
                signalled = generation;
                let _ = emitter_bus
                    .emit_signal(None::<()>, PATH, NAME, "Changed", &(generation,))
                    .await;
            }
        }
    });
    let watch = Watch::new()?;
    watch.add(&watched);
    watch.add_parent(&autostart_parent);
    let catalogue = provider.clone();
    tokio::spawn(async move {
        while watch.changed().await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            watch.drain();
            // Re-resolve: the autostart directory (or its link) may be new.
            let watched = {
                let mut provider = catalogue.lock().await;
                provider.refresh();
                provider.watched()
            };
            watch.add(&watched);
        }
    });
    loop {
        let wait = match activity.idle_for() {
            Some(idle) if idle >= IDLE => return Ok(()),
            // A restarted logind/polkit is never trusted by this process again;
            // exit so bus activation starts a fresh one.
            Some(_) if authority.stale() => return Ok(()),
            Some(idle) => IDLE - idle,
            None => IDLE,
        };
        tokio::time::sleep(wait.min(Duration::from_secs(2))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fixed_codes_cross_the_bus() {
        let Refusal::Refused(code) = public(refused("background-stop-review-stale")) else {
            panic!()
        };
        assert_eq!(code, "background-stop-review-stale");
        for leaked in [
            "filesystem or process operation failed",
            "/home/user/secret",
            "Upper-case",
        ] {
            let Refusal::Refused(code) = public(refused(leaked)) else {
                panic!()
            };
            assert_eq!(code, "operation-unavailable-or-outcome-unknown");
        }
    }

    #[test]
    fn capabilities_never_claim_unbuilt_adapters() {
        let value = capabilities(false, search::ADAPTER_QUALIFIED);
        for key in [
            "work_adapter",
            "search_policy_adapter",
            "scheduled_adapter",
            "agent_policy_adapter",
        ] {
            assert_eq!(value[key], false, "{key}");
        }
        // Built: the portal background monitor and XDG Autostart sources.
        assert_eq!(
            (
                value["flatpak_background_adapter"].as_bool(),
                value["xdg_autostart_adapter"].as_bool()
            ),
            (Some(true), Some(true))
        );
        assert_eq!(value["idle_exit_seconds"], 60);
        // Advertised exactly as the installed acceptance gate says.
        assert_eq!(
            capabilities(true, search::ADAPTER_QUALIFIED)["search_policy_adapter"],
            search::ADAPTER_QUALIFIED
        );
        // With the gate forced on, it still needs the matched MCP reader.
        assert_eq!(capabilities(true, true)["search_policy_adapter"], true);
        assert_eq!(capabilities(false, true)["search_policy_adapter"], false);
    }
}
