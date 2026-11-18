// SPDX-License-Identifier: MIT
//! Observe installed user units and control only a freshly verified app process.
use crate::{
    Check, Result, agent_policy, bounded, lifecycle,
    manifest::Manifest,
    model::{self, Policy, Review, Windows},
    preferences::{Store, private_tree},
    process_identity::{Unit, UnitProperties, installed_unit, observe, trusted_unit},
    refused,
    registry::{self, Catalogue, Entry},
    search, standard, window_observation,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};
use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue},
};

/// Which unit-file change a reviewed policy needs, after every refusal check.
/// `Some(true)` enables autostart, `Some(false)` disables it.
pub fn policy_change(
    manifest: &Manifest,
    previous: &Policy,
    requested: &Policy,
    agent_policy_available: bool,
    search_adapter: bool,
    actual_autostart: Option<&str>,
    reviewed_autostart: &Value,
) -> Result<Option<bool>> {
    if requested.contains_key("search") && !agent_policy_available {
        return Err(refused("background-policy-schema-adapter-unavailable"));
    }
    if requested.get("agent") != previous.get("agent") && !agent_policy_available {
        return Err(refused("agent-activation-policy-adapter-unavailable"));
    }
    let unbuilt: &[&str] = if search_adapter {
        &["scheduled", "ongoing-work"]
    } else {
        &["scheduled", "ongoing-work", "search"]
    };
    if unbuilt
        .iter()
        .any(|k| requested.get(*k) != previous.get(*k))
    {
        return Err(refused("activation-source-adapter-unavailable"));
    }
    if json!(actual_autostart) != *reviewed_autostart {
        return Err(refused("background-policy-review-stale"));
    }
    let Some(actual) = actual_autostart.filter(|_| manifest.autostart_supported) else {
        return Ok(None);
    };
    let wanted = requested.get("autostart").copied().unwrap_or(false);
    if wanted == (actual == "enabled") {
        return Ok(None);
    }
    if !["enabled", "disabled"].contains(&actual) {
        return Err(refused("application-autostart-state-unavailable"));
    }
    Ok(Some(wanted))
}

/// Force stop only kills a unit that will not restart it and owns its whole cgroup.
pub fn force_ready(properties: &UnitProperties) -> Result<()> {
    if properties.restart != "no" || properties.kill_mode != "control-group" {
        return Err(refused("application-unit-restarts-automatically"));
    }
    Ok(())
}

/// What a systemd `UnitNew`/`UnitRemoved` means for the observed snapshot.
/// Systemd announces every unit it loads or garbage-collects, including ones
/// loaded only to be read; only units behind a catalogue row matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitEvent {
    /// The unit, or an app scope, of this registered app.
    App(String),
    /// A Flatpak instance scope: portal rows' `instance_running` may change.
    Flatpak,
    Ignore,
}

fn app_scope(unit: &str, prefix: &str, app: &str) -> bool {
    unit.strip_prefix(prefix)
        .and_then(|r| r.strip_prefix(app))
        .and_then(|r| r.strip_prefix('-'))
        .and_then(|r| r.strip_suffix(".scope"))
        .is_some_and(|id| !id.is_empty() && !id.contains('-'))
}

/// `apps` yields (app_id, declared unit) for every registered app.
pub fn unit_event<'a>(apps: impl IntoIterator<Item = (&'a str, &'a str)>, unit: &str) -> UnitEvent {
    for (app, declared) in apps {
        if unit == declared
            || app_scope(unit, "app-enzui-", app)
            || app_scope(unit, "app-flatpak-", app)
        {
            return UnitEvent::App(app.into());
        }
    }
    if unit.starts_with("app-flatpak-") && unit.ends_with(".scope") {
        return UnitEvent::Flatpak;
    }
    UnitEvent::Ignore
}

/// Generations count distinct observable snapshots: re-reading an unchanged
/// inventory (as every reader does after `Changed`) never advances it, so a
/// read can never cause another `Changed`.
#[derive(Clone, Debug, Default)]
pub struct Generations {
    pub value: u64,
    observed: Option<String>,
}

impl Generations {
    /// The generation for this snapshot (`generation` itself is not part of it).
    pub fn observe(&mut self, snapshot: &Value) -> u64 {
        let digest = model::digest(snapshot);
        if digest.is_empty() || self.observed.as_ref() != Some(&digest) {
            self.value += 1;
            self.observed = (!digest.is_empty()).then_some(digest);
        }
        self.value
    }
    /// The inventory could not be read: whatever comes next is a new generation.
    pub fn failed(&mut self) -> u64 {
        if self.observed.take().is_some() {
            self.value += 1;
        }
        self.value
    }
}

fn text(raw: &HashMap<String, OwnedValue>, key: &str) -> String {
    raw.get(key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| String::try_from(v).ok())
        .unwrap_or_default()
}

pub struct Provider {
    bus: Connection,
    uid: u32,
    home: PathBuf,
    pub catalogue: Catalogue,
    pub preferences: Store,
    lifecycle: lifecycle::Adapter,
    pub windows: window_observation::Adapter,
    /// systemd unit object path -> app, for PropertiesChanged events.
    pub paths: HashMap<String, String>,
    cache: BTreeMap<String, Value>,
    pub generations: Generations,
    /// The agent broker unit as last loaded while systemd had not loaded it;
    /// cleared when unit files or the catalogue change.
    agent_unit_unloaded: Option<UnitProperties>,
    /// Search activation-origin records under `$XDG_RUNTIME_DIR`.
    search_markers: Store,
    /// [`search::ADAPTER_QUALIFIED`]; changing the search source and search
    /// activation need it.
    pub search_adapter: bool,
    /// Coalesced Changed signal request for the service loop.
    pub notify: std::sync::Arc<tokio::sync::Notify>,
}

impl Provider {
    pub fn new(bus: Connection, uid: u32, home: &Path) -> Result<Self> {
        let state = home.join(".local/state/enzimos");
        private_tree(&state, uid)?;
        let preferences = Store::new(state.join("background-apps"), uid);
        private_tree(&preferences.directory, uid)?;
        let mut provider = Self {
            lifecycle: lifecycle::Adapter::new(bus.clone(), uid),
            windows: window_observation::Adapter::new(bus.clone(), uid),
            bus,
            uid,
            home: home.to_path_buf(),
            catalogue: Catalogue::unknown(),
            preferences,
            paths: HashMap::new(),
            cache: BTreeMap::new(),
            generations: Generations::default(),
            agent_unit_unloaded: None,
            search_markers: Store::new(
                PathBuf::from(format!("/run/user/{uid}")).join(search::MARKER_DIRECTORY),
                uid,
            ),
            search_adapter: search::ADAPTER_QUALIFIED,
            notify: Default::default(),
        };
        provider.refresh();
        Ok(provider)
    }

    pub fn watched(&self) -> Vec<PathBuf> {
        // Each declaration directory and its parent, so a directory created
        // after start is noticed (the next refresh re-adds its own watch).
        let mut watched = registry::DIRECTORIES
            .iter()
            .flat_map(|d| [PathBuf::from(d), Path::new(d).parent().unwrap().into()])
            .collect::<Vec<_>>();
        watched.extend([
            self.preferences.directory.clone(),
            standard::user_autostart(&self.home, self.uid),
            PathBuf::from(standard::SYSTEM_AUTOSTART),
        ]);
        watched
    }

    /// Watched only for `autostart` appearing in it.
    pub fn autostart_parent(&self) -> PathBuf {
        standard::user_config(&self.home)
    }

    /// Reload installed declarations; a failure is reported, never an empty success.
    pub fn refresh(&mut self) {
        let directories = registry::DIRECTORIES.map(Path::new);
        self.catalogue = registry::load_all(&directories, 0, &registry::executable_identity)
            .unwrap_or_else(|_| Catalogue::unknown());
        self.paths.clear();
        self.agent_unit_unloaded = None;
        self.changed(None);
    }

    /// Invalidate observations; the service loop re-reads and signals `Changed`
    /// only if the snapshot differs.
    pub fn changed(&mut self, app: Option<&str>) {
        match app {
            Some(app) => {
                self.cache.remove(app);
            }
            None => self.cache.clear(),
        }
        self.notify.notify_one();
    }

    /// Standard sources changed: re-read them without re-observing native apps.
    pub fn standard_changed(&mut self) {
        self.notify.notify_one();
    }

    /// Unit files were enabled, disabled, added or removed.
    pub fn unit_files_changed(&mut self) {
        self.agent_unit_unloaded = None;
        self.changed(None);
    }

    pub fn unit_event(&self, unit: &str) -> UnitEvent {
        unit_event(
            self.catalogue
                .apps
                .iter()
                .map(|(id, e)| (id.as_str(), e.manifest.unit.as_str())),
            unit,
        )
    }

    fn runtime(&self) -> PathBuf {
        PathBuf::from(format!("/run/user/{}", self.uid))
    }

    /// What a portal stop needs, so the caller can run it without the provider lock.
    pub fn portal_handles(&self) -> (Connection, PathBuf, u32) {
        (self.bus.clone(), self.runtime(), self.uid)
    }

    pub fn set_autostart(&mut self, id: &str, enabled: bool) -> Result<Value> {
        let result = standard::set_autostart(
            &standard::user_autostart(&self.home, self.uid),
            Path::new(standard::SYSTEM_AUTOSTART),
            self.uid,
            id,
            enabled,
        )?;
        self.standard_changed();
        Ok(result)
    }

    pub fn app_for_path(&self, path: &str) -> Option<String> {
        self.paths.get(path).cloned()
    }

    async fn manager(&self) -> Result<Proxy<'static>> {
        bounded(
            Proxy::new_owned(
                self.bus.clone(),
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            ),
            3,
            "application-unit-unavailable",
        )
        .await
    }

    pub async fn subscribe(&self) -> Result<()> {
        let manager = self.manager().await?;
        bounded(
            manager.call::<_, _, ()>("Subscribe", &()),
            3,
            "application-unit-unavailable",
        )
        .await
    }

    /// Read a unit without loading it: loading (and systemd's later garbage
    /// collection) announces `UnitNew`/`UnitRemoved` to every subscriber. A unit
    /// systemd has not loaded is inactive, with only its unit-file state known.
    pub async fn unit_properties(
        &mut self,
        unit: &str,
        app: Option<&str>,
    ) -> Result<UnitProperties> {
        let code = "application-unit-unavailable";
        let manager = self.manager().await?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            manager.call::<_, _, OwnedObjectPath>("GetUnit", &(unit,)),
        )
        .await
        {
            Ok(Ok(path)) => self.properties_at(path, app).await,
            Ok(Err(e)) if no_such_unit(&e) => {
                let state = match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    manager.call::<_, _, String>("GetUnitFileState", &(unit,)),
                )
                .await
                {
                    Ok(Ok(state)) => state,
                    // No unit file: what a loaded "not-found" unit reports.
                    Ok(Err(e)) if no_such_unit(&e) => String::new(),
                    _ => return Err(refused(code)),
                };
                Ok(UnitProperties {
                    id: unit.into(),
                    active_state: "inactive".into(),
                    unit_file_state: state,
                    transient: true,
                    ..Default::default()
                })
            }
            _ => Err(refused(code)),
        }
    }

    /// Commits need the fragment and drop-ins, which only a loaded unit reports.
    pub async fn load_unit_properties(
        &mut self,
        unit: &str,
        app: Option<&str>,
    ) -> Result<UnitProperties> {
        let manager = self.manager().await?;
        let path: OwnedObjectPath = bounded(
            manager.call("LoadUnit", &(unit,)),
            3,
            "application-unit-unavailable",
        )
        .await?;
        self.properties_at(path, app).await
    }

    async fn properties_at(
        &mut self,
        path: OwnedObjectPath,
        app: Option<&str>,
    ) -> Result<UnitProperties> {
        let code = "application-unit-unavailable";
        if let Some(app) = app {
            self.paths.insert(path.to_string(), app.into());
        }
        let properties = bounded(
            Proxy::new_owned(
                self.bus.clone(),
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
            ),
            3,
            code,
        )
        .await?;
        let mut raw: HashMap<String, OwnedValue> = bounded(
            properties.call("GetAll", &("org.freedesktop.systemd1.Unit",)),
            3,
            code,
        )
        .await?;
        let service: HashMap<String, OwnedValue> = bounded(
            properties.call("GetAll", &("org.freedesktop.systemd1.Service",)),
            3,
            code,
        )
        .await?;
        raw.extend(service);
        let get = |key: &str| raw.get(key).and_then(|v| v.try_clone().ok());
        Ok(UnitProperties {
            id: text(&raw, "Id"),
            fragment_path: text(&raw, "FragmentPath"),
            drop_in_paths: get("DropInPaths")
                .and_then(|v| Vec::<String>::try_from(v).ok())
                .unwrap_or_default(),
            active_state: text(&raw, "ActiveState"),
            control_group: text(&raw, "ControlGroup"),
            restart: text(&raw, "Restart"),
            unit_file_state: text(&raw, "UnitFileState"),
            kill_mode: text(&raw, "KillMode"),
            main_pid: get("MainPID")
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            transient: get("Transient")
                .and_then(|v| bool::try_from(v).ok())
                .unwrap_or(true),
            invocation_id: get("InvocationID")
                .and_then(|v| Vec::<u8>::try_from(v).ok())
                .filter(|id| id.len() == 16)
                .map(|id| id.iter().map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default(),
        })
    }

    /// A loaded broker unit is read as it is. An unloaded one must be loaded
    /// once to see its fragment and drop-ins; those are kept until unit files
    /// change, so repeated reads do not keep loading it. The descriptor is
    /// always read fresh.
    pub async fn agent_policy_available(&mut self) -> bool {
        let properties = match self.unit_properties(agent_policy::UNIT, None).await {
            // Not loaded: only an unloaded read has no fragment and is transient.
            Ok(p) if p.fragment_path.is_empty() && p.transient => match &self.agent_unit_unloaded {
                Some(loaded) => loaded.clone(),
                None => match self.load_unit_properties(agent_policy::UNIT, None).await {
                    Ok(loaded) => {
                        self.agent_unit_unloaded = Some(loaded.clone());
                        loaded
                    }
                    Err(_) => return false,
                },
            },
            Ok(p) => p,
            Err(_) => return false,
        };
        agent_policy::available(&properties, self.uid)
    }

    fn entry(&self, app_id: &str) -> Result<Entry> {
        self.catalogue
            .apps
            .get(app_id)
            .cloned()
            .ok_or_else(|| refused("installed-application-unavailable"))
    }

    fn observe(&self, entry: &Entry, properties: &UnitProperties) -> Unit {
        let m = &entry.manifest;
        observe(
            &m.unit,
            &entry.executable,
            properties,
            self.uid,
            Path::new("/proc"),
            &installed_unit,
        )
    }

    pub async fn observation(&mut self, app_id: &str) -> Result<(Entry, Unit, Windows, Policy)> {
        let entry = self.entry(app_id)?;
        let manifest = &entry.manifest;
        let mut unit = match self.unit_properties(&manifest.unit, Some(app_id)).await {
            Ok(properties) => self.observe(&entry, &properties),
            Err(_) => Unit::unknown(&manifest.unit),
        };
        if manifest.graceful() && unit.identity_verified {
            match self.lifecycle.query(app_id, &unit).await {
                Ok(_) => unit.graceful_adapter_verified = true,
                Err(e) if lifecycle::is_admission_code(&e.0) => {
                    unit.graceful_admission_failure = Some(e.0)
                }
                Err(_) => {}
            }
        }
        let windows = self.windows.query(app_id, &unit).await;
        let settings = self.preferences.get(manifest)?;
        Ok((entry, unit, windows, settings))
    }

    /// The event-invalidated inventory; unchanged apps are not re-observed.
    pub async fn query(&mut self) -> Result<Value> {
        let apps = self.catalogue.apps.keys().cloned().collect::<Vec<_>>();
        if apps.len() > registry::MAX_APPS {
            return Err(refused("background-inventory-bound"));
        }
        self.cache.retain(|k, _| apps.contains(k));
        for app_id in apps {
            if !self.cache.contains_key(&app_id) {
                let (entry, unit, windows, settings) = self.observation(&app_id).await?;
                let snapshot = model::snapshot(&entry.manifest, &unit, &windows, &settings)?;
                self.cache.insert(app_id, snapshot);
            }
        }
        let session = standard::Session::current(&self.home);
        let (autostart, autostart_complete) = standard::autostart_inventory(
            &standard::user_autostart(&self.home, self.uid),
            Path::new(standard::SYSTEM_AUTOSTART),
        );
        let autostart = autostart
            .iter()
            .map(|row| standard::autostart_value(row, &session))
            .collect::<Vec<_>>();
        let runtime = self.runtime();
        let mut body = json!({
            "schema": 1, "apps": self.cache.values().collect::<Vec<_>>(), "autostart_inventory_complete": autostart_complete,
            "catalogue_observation_known": self.catalogue.observation_known,
            "unavailable_declarations": self.catalogue.unavailable_value(),
            "policy_operation": self.preferences.operation()?,
            "window_observation_required": true, "controls_require_fresh_observation": true,
            // Standard sources: null means the portal did not answer (unknown), never empty.
            // `instance_running` cross-checks each row against the instance
            // itself; the portal's list can briefly outlive an exited app.
            "flatpak_background": standard::portal_apps(&self.bus).await.map(|apps| apps.iter()
                .map(|a| json!({"app_id": a.app_id, "instance": a.instance, "message": a.message,
                    "instance_running": standard::instance_state(&runtime, Path::new("/proc"), self.uid, &a.app_id, &a.instance).value()}))
                .collect::<Vec<_>>()),
            "autostart": autostart,
        });
        body["generation"] = json!(self.generations.observe(&body));
        Ok(body)
    }

    /// Re-read after invalidation: the generation, advanced only on a change.
    pub async fn observe_generation(&mut self) -> u64 {
        match self.query().await {
            Ok(_) => self.generations.value,
            Err(_) => self.generations.failed(),
        }
    }

    pub async fn review_stop(&mut self, app_id: &str, mode: &str) -> Result<Review> {
        let (entry, unit, windows, settings) = self.observation(app_id).await?;
        if let Some(code) = unit
            .graceful_admission_failure
            .as_ref()
            .filter(|_| mode != "force")
        {
            return Err(refused(code));
        }
        let mut review = model::stop_review(&entry.manifest, &unit, &windows, mode, &settings)?;
        if mode != "force" {
            review.plan["lifecycle"] = self.lifecycle.query(app_id, &unit).await?;
            review.plan["choice"] = json!(if mode == "cancel-and-exit" {
                "cancel-and-exit"
            } else {
                "finish-then-exit"
            });
            review.plan_sha256 = model::stop_digest(&review.plan);
        }
        Ok(review)
    }

    pub async fn review_policy(&mut self, app_id: &str, value: &Value) -> Result<Review> {
        let (entry, unit, _, settings) = self.observation(app_id).await?;
        let manifest = &entry.manifest;
        let requested = model::requested(manifest, value)?;
        let plan = json!({
            "schema": 1, "app_id": app_id, "manifest_sha256": entry.manifest_sha256,
            "previous": settings, "requested": requested,
            "autostart_state": manifest.autostart_supported.then_some(unit.autostart_state),
            "stops_ongoing_work": false, "grants_agent_tool_consent": false,
        });
        let mut plan = plan;
        if settings.contains_key("search") {
            // Revoking search may stop the windowless instance the broker
            // started for search, only when its lifecycle reports no work.
            plan["revoking_search_may_stop_idle_search_instance"] = json!(
                settings.get("search") == Some(&true) && requested.get("search") == Some(&false)
            );
        }
        Ok(Review {
            plan_sha256: model::digest(&plan),
            plan,
        })
    }

    /// Re-review, then stop exactly the reviewed process. Graceful never escalates to force.
    pub async fn stop(
        &mut self,
        app_id: &str,
        mode: &str,
        reviewed: &str,
        guard: &impl Check,
    ) -> Result<Value> {
        guard.check().await?;
        let fresh = self.review_stop(app_id, mode).await?;
        if fresh.plan_sha256 != reviewed {
            return Err(refused("background-stop-review-stale"));
        }
        guard.check().await?;
        self.refresh();
        let result = if mode != "force" {
            let again = self.review_stop(app_id, mode).await?;
            if model::stop_authorization(&again.plan) != model::stop_authorization(&fresh.plan) {
                return Err(refused("background-stop-review-stale"));
            }
            let (_, unit, _, _) = self.observation(app_id).await?;
            let choice = fresh.plan["choice"].as_str().unwrap_or_default();
            let result = self
                .lifecycle
                .stop(app_id, &unit, &fresh.plan["lifecycle"], choice, guard)
                .await?;
            json!({"state": result["state"], "choice": result["choice"],
                   "application_exit_confirmation_required": true, "force_fallback_used": false, "mode": mode})
        } else {
            self.force(app_id, &fresh.plan, guard).await?
        };
        self.changed(Some(app_id));
        Ok(
            json!({"schema": 1, "result": result, "future_activation_policy_changed": false,
                  "personal_files_removed": false, "force_fallback_used": false}),
        )
    }

    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    async fn force(&mut self, app_id: &str, plan: &Value, guard: &impl Check) -> Result<Value> {
        let (entry, unit, windows, settings) = self.observation(app_id).await?;
        let again = model::stop_review(&entry.manifest, &unit, &windows, "force", &settings)?;
        if model::stop_authorization(&again.plan) != model::stop_authorization(plan) {
            return Err(refused("background-stop-review-stale"));
        }
        let properties = self
            .unit_properties(&entry.manifest.unit, Some(app_id))
            .await?;
        force_ready(&properties)?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, unit.main_pid as libc::c_int, 0) };
        if fd < 0 {
            return Err(refused("application-process-changed"));
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) };
        // The pidfd now pins the process; re-observe before signalling it.
        let current = self
            .unit_properties(&entry.manifest.unit, Some(app_id))
            .await?;
        if self.observe(&entry, &current).identity() != unit.identity() {
            return Err(refused("application-process-changed"));
        }
        guard.check().await?;
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
            return Err(refused("application-stop-outcome-unknown"));
        }
        Ok(json!({"mode": "force", "state": "requested", "unit_exit_confirmation_required": true}))
    }

    /// Re-review, then change autostart and the saved policy. Never stops running work.
    pub async fn set_policy(
        &mut self,
        app_id: &str,
        value: &Value,
        reviewed: &str,
        guard: &(impl Check + Sync),
    ) -> Result<Value> {
        guard.check().await?;
        let fresh = self.review_policy(app_id, value).await?;
        if fresh.plan_sha256 != reviewed {
            return Err(refused("background-policy-review-stale"));
        }
        guard.check().await?;
        self.refresh();
        let plan = &fresh.plan;
        let entry = self.entry(app_id)?;
        if entry.manifest_sha256 != plan["manifest_sha256"] {
            return Err(refused("background-policy-review-stale"));
        }
        let manifest = &entry.manifest;
        let previous = self.preferences.get(manifest)?;
        if json!(previous) != plan["previous"] {
            return Err(refused("background-policy-review-stale"));
        }
        let requested = model::requested(manifest, &plan["requested"])?;
        let agent = if requested.contains_key("search")
            || requested.get("agent") != previous.get("agent")
        {
            self.agent_policy_available().await
        } else {
            false
        };
        let properties = self
            .load_unit_properties(&manifest.unit, Some(app_id))
            .await?;
        trusted_unit(&properties, &manifest.unit, 0)?;
        let actual = manifest
            .autostart_supported
            .then_some(properties.unit_file_state.as_str());
        let change = policy_change(
            manifest,
            &previous,
            &requested,
            agent,
            self.search_adapter,
            actual,
            &plan["autostart_state"],
        )?;
        let manager = self.manager().await?;
        let fragment = properties.fragment_path.clone();
        let unit = manifest.unit.clone();
        let change_autostart = async {
            let code = "application-autostart-change-failed";
            match change {
                None => return Ok(()),
                Some(true) => {
                    bounded(
                        manager.call::<_, _, (bool, Vec<(String, String, String)>)>(
                            "EnableUnitFiles",
                            &(vec![fragment], false, false),
                        ),
                        3,
                        code,
                    )
                    .await?;
                }
                Some(false) => {
                    bounded(
                        manager.call::<_, _, Vec<(String, String, String)>>(
                            "DisableUnitFiles",
                            &(vec![unit], false),
                        ),
                        3,
                        code,
                    )
                    .await?;
                }
            }
            bounded(manager.call::<_, _, ()>("Reload", &()), 3, code).await
        };
        // Saved policies of uninstalled apps may be dropped at the store's bound,
        // but only against a catalogue that was actually read.
        let catalogue = &self.catalogue;
        let installed = |id: &str| !catalogue.observation_known || catalogue.apps.contains_key(id);
        self.preferences
            .apply(
                manifest,
                plan,
                &requested,
                change_autostart,
                installed,
                guard,
            )
            .await?;
        let revoked =
            previous.get("search") == Some(&true) && requested.get("search") == Some(&false);
        let search_instance = if self.search_adapter && revoked {
            Some(search::revoke(self, app_id, guard).await)
        } else {
            None
        };
        self.changed(Some(app_id));
        let mut result = json!({"schema": 1, "activation_policy": requested, "ongoing_work_stopped": false,
                  "agent_tool_consent_granted": false});
        if let Some(outcome) = search_instance {
            result["search_instance"] = json!(outcome);
        }
        Ok(result)
    }
}

impl search::Host for Provider {
    fn entry(&self, app_id: &str) -> Result<Entry> {
        Provider::entry(self, app_id)
    }

    fn verify(&self, entry: &Entry) -> Result<search::Proof> {
        search::overridden(&entry.manifest.app_id, &self.home, &|p| {
            std::fs::symlink_metadata(p).is_ok()
        })?;
        search::verify(entry, &|p| registry::read(p, 0), &|e| {
            registry::executable_identity(e, 0)
        })
    }

    fn policy(&self, manifest: &Manifest) -> Result<Policy> {
        if let Some(op) = self.preferences.operation()?
            && op["app_id"] == manifest.app_id.as_str()
            && op["fresh_review_required"] == true
        {
            return Err(refused("background-policy-outcome-needs-review"));
        }
        self.preferences.get(manifest)
    }

    async fn instance(&mut self, entry: &Entry) -> Result<search::Instance> {
        let app_id = entry.manifest.app_id.clone();
        let properties = self
            .unit_properties(&entry.manifest.unit, Some(&app_id))
            .await?;
        let unit = self.observe(entry, &properties);
        let windows = self.windows.query(&app_id, &unit).await;
        Ok(search::Instance {
            unit,
            invocation_id: properties.invocation_id,
            windows,
        })
    }

    async fn name_owned(&self, name: &str) -> Result<bool> {
        let code = "search-bus-unavailable";
        let daemon = bounded(zbus::fdo::DBusProxy::new(&self.bus), 1, code).await?;
        let name = zbus::names::BusName::try_from(name).map_err(|_| refused(code))?;
        bounded(daemon.name_has_owner(name), 1, code).await
    }

    async fn trusted_unit(&mut self, entry: &Entry) -> Result<()> {
        let app_id = entry.manifest.app_id.clone();
        let properties = self
            .load_unit_properties(&entry.manifest.unit, Some(&app_id))
            .await?;
        trusted_unit(&properties, &entry.manifest.unit, 0)
    }

    async fn start_unit(&mut self, unit: &str) -> Result<()> {
        let manager = self.manager().await?;
        bounded(
            manager.call::<_, _, OwnedObjectPath>("StartUnit", &(unit, "fail")),
            1,
            "search-unit-start-failed",
        )
        .await
        .map(|_| ())
    }

    async fn owner_is_main(&self, name: &str, unit: &Unit) -> bool {
        self.lifecycle.owner(name, unit).await.is_ok()
    }

    fn marker(&self, app_id: &str) -> Result<Option<search::Marker>> {
        self.search_markers
            .read_private(&format!("{app_id}.json"), 1024, "search-marker")?
            .map(|data| search::Marker::decode(&data, app_id))
            .transpose()
    }

    fn mark(&self, marker: &search::Marker) -> Result<()> {
        self.search_markers.write_private(
            &format!("{}.json", marker.app_id),
            marker.value().to_string().as_bytes(),
        )
    }

    fn unmark(&self, app_id: &str) -> Result<()> {
        self.search_markers
            .remove_private(&format!("{app_id}.json"))
    }

    async fn lifecycle_query(&self, app_id: &str, unit: &Unit) -> Result<Value> {
        self.lifecycle.query(app_id, unit).await
    }

    async fn lifecycle_stop<G: Check + Sync>(
        &self,
        app_id: &str,
        unit: &Unit,
        review: &Value,
        guard: &G,
    ) -> Result<()> {
        self.lifecycle
            .stop(app_id, unit, review, "finish-then-exit", guard)
            .await
            .map(|_| ())
    }
}

use std::os::fd::{AsRawFd, FromRawFd};

fn no_such_unit(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit")
}

#[cfg(test)]
mod tests;
