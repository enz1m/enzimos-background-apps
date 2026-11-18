// SPDX-License-Identifier: MIT
//! Revision-bound app shutdown targets a verified current unique bus owner.
use crate::{
    Check, Result, bounded,
    manifest::text,
    process_identity::{Unit, read_start_ticks},
    refused,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use zbus::{Connection, Proxy, fdo::DBusProxy, names::BusName};

/// The framework-neutral lifecycle interface, asked first.
pub const INTERFACE: &str = "org.enzui.ApplicationLifecycle1";
/// The deprecated pre-neutral name, asked only when an app does not serve
/// [`INTERFACE`]. Same methods, signatures and semantics.
pub const LEGACY_INTERFACE: &str = "org.enzimos.ApplicationLifecycle1";
const ADMISSION_PREFIX: &str = "not the OS background-apps service: ";
/// The neutral diagnostic prefix the framework may adopt with descriptor-based
/// admission (docs/LIFECYCLE_CALLER_DESCRIPTOR.md); same check texts follow it.
const NEUTRAL_ADMISSION_PREFIX: &str = "not an admitted lifecycle caller: ";
const ADMISSION_CHECKS: [(&str, &str); 11] = [
    ("the bus could not identify the caller", "caller"),
    ("the caller runs as another user", "user"),
    (
        "the caller does not own the service's bus name",
        "name-owner",
    ),
    ("the caller does not run in the service's unit", "unit"),
    (
        "the user manager could not describe the service's unit",
        "unit-query",
    ),
    ("the caller is not the unit's main process", "main-process"),
    ("the service's unit is not root-controlled", "unit-trust"),
    (
        "the service's executable is not installed root-owned",
        "executable-trust",
    ),
    ("the caller runs another executable", "executable-identity"),
    (
        "the caller's process changed during the check",
        "process-changed",
    ),
    ("the caller check did not finish in time", "deadline"),
];

pub fn is_admission_code(code: &str) -> bool {
    code.strip_prefix("application-lifecycle-admission-")
        .is_some_and(|c| ADMISSION_CHECKS.iter().any(|(_, k)| *k == c))
}

/// Only exact protocol diagnostics become public codes; arbitrary peer text
/// never crosses the broker boundary.
pub fn admission(name: &str, message: Option<&str>) -> Option<String> {
    let message = message?;
    let rest = message
        .strip_prefix(ADMISSION_PREFIX)
        .or_else(|| message.strip_prefix(NEUTRAL_ADMISSION_PREFIX))?;
    if name != "org.freedesktop.DBus.Error.AccessDenied" {
        return None;
    }
    ADMISSION_CHECKS
        .iter()
        .find(|(text, _)| *text == rest)
        .map(|(_, check)| format!("application-lifecycle-admission-{check}"))
}

/// An app built before the rename answers the neutral interface with
/// `UnknownInterface` (or `UnknownMethod`); only then is the legacy name asked.
fn not_served(error: &zbus::Error) -> bool {
    const NAMES: [&str; 2] = [
        "org.freedesktop.DBus.Error.UnknownInterface",
        "org.freedesktop.DBus.Error.UnknownMethod",
    ];
    match error {
        zbus::Error::MethodError(name, _, _) => NAMES.contains(&name.as_str()),
        zbus::Error::FDO(e) => matches!(
            **e,
            zbus::fdo::Error::UnknownInterface(_) | zbus::fdo::Error::UnknownMethod(_)
        ),
        _ => false,
    }
}

/// Run `call` on the neutral interface, then on the legacy one if the app does
/// not serve the neutral name. Any other outcome, including admission refusals,
/// is final. Returns the interface that answered.
async fn either_interface<T, F, Fut>(call: F) -> std::result::Result<(T, &'static str), zbus::Error>
where
    F: Fn(&'static str) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, zbus::Error>>,
{
    match call(INTERFACE).await {
        Err(e) if not_served(&e) => call(LEGACY_INTERFACE).await.map(|v| (v, LEGACY_INTERFACE)),
        other => other.map(|v| (v, INTERFACE)),
    }
}

fn call_error(error: zbus::Error) -> crate::Error {
    match &error {
        zbus::Error::MethodError(name, message, _) => admission(name.as_str(), message.as_deref())
            .map_or_else(
                || refused("application-lifecycle-unavailable"),
                |c| refused(&c),
            ),
        _ => refused("application-lifecycle-unavailable"),
    }
}

pub type Consequence = (String, String, String);

pub fn consequences(revision: &str, rows: &[Consequence]) -> Result<Value> {
    if revision.is_empty()
        || revision.len() > 80
        || !revision
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(refused("application-lifecycle-revision"));
    }
    if rows.len() > 32 {
        return Err(refused("application-lifecycle-consequence-bound"));
    }
    let mut result = Vec::new();
    for (kind, title, detail) in rows {
        if !text(kind, 160) || !text(title, 160) || (!detail.is_empty() && !text(detail, 160)) {
            return Err(refused("application-lifecycle-consequence-text"));
        }
        result.push(json!({"kind": kind, "title": title, "detail": detail}));
    }
    Ok(json!({"revision": revision, "consequences": result}))
}

/// Progress detail is display-only; revision binds exact work membership.
pub fn authorization(review: &Value) -> Value {
    let mut review = review.clone();
    if let Some(rows) = review.get("consequences").and_then(Value::as_array) {
        review["consequences"] = rows
            .iter()
            .map(|r| json!({"kind": r["kind"], "title": r["title"]}))
            .collect();
    }
    review
}

pub fn object_path(app_id: &str) -> String {
    format!("/{}", app_id.replace('.', "/").replace('-', "_"))
}

pub struct Adapter {
    bus: Connection,
    uid: u32,
    proc: PathBuf,
}

impl Adapter {
    pub fn new(bus: Connection, uid: u32) -> Self {
        Self {
            bus,
            uid,
            proc: PathBuf::from("/proc"),
        }
    }

    /// The app's bus name is owned by this verified unit's main process.
    pub async fn owner(&self, app_id: &str, unit: &Unit) -> Result<String> {
        if !unit.identity_verified || unit.main_pid == 0 || unit.start_ticks == 0 {
            return Err(refused("application-lifecycle-process-unverified"));
        }
        let code = "application-lifecycle-unique-owner";
        let daemon = bounded(DBusProxy::new(&self.bus), 1, code).await?;
        let name = BusName::try_from(app_id).map_err(|_| refused(code))?;
        let owner = bounded(daemon.get_name_owner(name), 1, code).await?;
        let unique = || BusName::Unique(owner.inner().clone());
        let uid = bounded(daemon.get_connection_unix_user(unique()), 1, code).await?;
        let pid = bounded(daemon.get_connection_unix_process_id(unique()), 1, code).await?;
        if uid != self.uid || pid != unit.main_pid {
            return Err(refused("application-lifecycle-owner-mismatch"));
        }
        if read_start_ticks(&self.proc, unit.main_pid).ok() != Some(unit.start_ticks) {
            return Err(refused("application-lifecycle-process-replaced"));
        }
        Ok(owner.to_string())
    }

    async fn proxy(
        &self,
        app_id: &str,
        owner: &str,
        interface: &'static str,
    ) -> zbus::Result<Proxy<'static>> {
        Proxy::new_owned(
            self.bus.clone(),
            owner.to_owned(),
            object_path(app_id),
            interface,
        )
        .await
    }

    /// Ask the verified owner what stopping now would interrupt.
    pub async fn query(&self, app_id: &str, unit: &Unit) -> Result<Value> {
        Ok(self.query_on(app_id, unit).await?.0)
    }

    /// The review and the interface that answered it, so `Stop` goes to the
    /// same interface. The interface is not part of the public review.
    async fn query_on(&self, app_id: &str, unit: &Unit) -> Result<(Value, &'static str)> {
        let owner = self.owner(app_id, unit).await?;
        let (reply, interface) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            either_interface(|interface| {
                let owner = owner.clone();
                async move {
                    self.proxy(app_id, &owner, interface)
                        .await?
                        .call::<_, _, (String, Vec<Consequence>)>("QueryStop", &())
                        .await
                }
            }),
        )
        .await
        .map_err(|_| refused("application-lifecycle-unavailable"))?
        .map_err(call_error)?;
        let mut result = consequences(&reply.0, &reply.1)?;
        if self.owner(app_id, unit).await? != owner {
            return Err(refused("application-lifecycle-owner-changed"));
        }
        result["owner"] = json!(owner);
        result["main_pid"] = json!(unit.main_pid);
        result["start_ticks"] = json!(unit.start_ticks);
        Ok((result, interface))
    }

    pub async fn stop(
        &self,
        app_id: &str,
        unit: &Unit,
        review: &Value,
        choice: &str,
        guard: &impl Check,
    ) -> Result<Value> {
        if !["finish-then-exit", "cancel-and-exit"].contains(&choice) {
            return Err(refused("application-lifecycle-choice"));
        }
        let (fresh, interface) = self.query_on(app_id, unit).await?;
        if authorization(&fresh) != authorization(review) {
            return Err(refused("application-lifecycle-review-stale"));
        }
        guard.check().await?;
        let owner = review["owner"].as_str().unwrap_or_default();
        if self.owner(app_id, unit).await? != owner {
            return Err(refused("application-lifecycle-owner-changed"));
        }
        let proxy = bounded(
            self.proxy(app_id, owner, interface),
            2,
            "application-lifecycle-unavailable",
        )
        .await?;
        let revision = review["revision"].as_str().unwrap_or_default();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            proxy.call::<_, _, String>("Stop", &(choice, revision)),
        )
        .await
        .map_err(|_| refused("application-lifecycle-unavailable"))?
        .map_err(call_error)?;
        match outcome.as_str() {
            "accepted" => Ok(json!({"state": "requested", "choice": choice,
                "application_exit_confirmation_required": true, "force_fallback_used": false})),
            "stale-revision" => Err(refused("application-lifecycle-review-stale")),
            _ => Err(refused("application-lifecycle-stop-refused")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_admission_diagnostics_only_publish_fixed_stage_codes() {
        let denied = "org.freedesktop.DBus.Error.AccessDenied";
        let message = format!("{ADMISSION_PREFIX}the caller runs another executable");
        assert_eq!(
            admission(denied, Some(&message)).as_deref(),
            Some("application-lifecycle-admission-executable-identity")
        );
        assert!(is_admission_code(
            "application-lifecycle-admission-deadline"
        ));
        assert_eq!(
            admission(
                denied,
                Some("not the OS background-apps service: /home/x secret")
            ),
            None
        );
        assert_eq!(
            admission("org.freedesktop.DBus.Error.Failed", Some(&message)),
            None
        );
        assert_eq!(admission(denied, None), None);
        let neutral = format!("{NEUTRAL_ADMISSION_PREFIX}the caller check did not finish in time");
        assert_eq!(
            admission(denied, Some(&neutral)).as_deref(),
            Some("application-lifecycle-admission-deadline")
        );
    }

    #[test]
    fn hostile_or_unbounded_consequences_refused() {
        let row = |k: &str, t: &str, d: &str| (k.to_owned(), t.to_owned(), d.to_owned());
        assert!(consequences("r-1", &[row("upload", "Uploading", "")]).is_ok());
        assert_eq!(
            consequences("bad revision", &[]).unwrap_err().0,
            "application-lifecycle-revision"
        );
        assert_eq!(
            consequences("r", &vec![row("k", "t", ""); 33])
                .unwrap_err()
                .0,
            "application-lifecycle-consequence-bound"
        );
        assert_eq!(
            consequences("r", &[row("k", "t\u{1b}[31m", "")])
                .unwrap_err()
                .0,
            "application-lifecycle-consequence-text"
        );
        assert_eq!(
            consequences("r", &[row("", "t", "")]).unwrap_err().0,
            "application-lifecycle-consequence-text"
        );
    }

    #[test]
    fn progress_detail_changes_without_invalidating_authorized_work() {
        let a = consequences("r1", &[("k".into(), "Upload".into(), "10%".into())]).unwrap();
        let b = consequences("r1", &[("k".into(), "Upload".into(), "80%".into())]).unwrap();
        assert_eq!(authorization(&a), authorization(&b));
        let c = consequences("r1", &[("k".into(), "Export".into(), "10%".into())]).unwrap();
        assert_ne!(authorization(&a), authorization(&c));
    }

    fn method_error(name: &str) -> zbus::Error {
        let message = zbus::message::Message::method_call("/org/example/App", "QueryStop")
            .unwrap()
            .build(&())
            .unwrap();
        let reply = zbus::message::Message::error(&message.header(), name)
            .unwrap()
            .build(&())
            .unwrap();
        zbus::Error::from(reply)
    }

    /// Records the interfaces asked, answering each with the given outcome.
    async fn run(
        neutral: Option<&str>,
        legacy: Option<&str>,
    ) -> (
        std::result::Result<(u8, &'static str), String>,
        Vec<&'static str>,
    ) {
        let asked = std::sync::Mutex::new(Vec::new());
        let result = either_interface(|interface| {
            asked.lock().unwrap().push(interface);
            let outcome = if interface == INTERFACE {
                neutral
            } else {
                legacy
            };
            async move { outcome.map_or(Ok(7), |name| Err(method_error(name))) }
        })
        .await
        .map_err(|e| match e {
            zbus::Error::MethodError(name, _, _) => name.to_string(),
            other => other.to_string(),
        });
        (result, asked.into_inner().unwrap())
    }

    #[tokio::test]
    async fn neutral_interface_first_legacy_only_when_not_served() {
        let unknown_interface = "org.freedesktop.DBus.Error.UnknownInterface";
        let unknown_method = "org.freedesktop.DBus.Error.UnknownMethod";
        let denied = "org.freedesktop.DBus.Error.AccessDenied";
        assert_eq!(run(None, None).await, (Ok((7, INTERFACE)), vec![INTERFACE]));
        for missing in [unknown_interface, unknown_method] {
            assert_eq!(
                run(Some(missing), None).await,
                (Ok((7, LEGACY_INTERFACE)), vec![INTERFACE, LEGACY_INTERFACE])
            );
            assert_eq!(
                run(Some(missing), Some(missing)).await,
                (Err(missing.into()), vec![INTERFACE, LEGACY_INTERFACE])
            );
        }
        // An admission refusal or failure on the neutral name is the answer.
        for final_ in [
            denied,
            "org.freedesktop.DBus.Error.Failed",
            "org.freedesktop.DBus.Error.UnknownObject",
        ] {
            assert_eq!(
                run(Some(final_), None).await,
                (Err(final_.into()), vec![INTERFACE])
            );
        }
        assert!(not_served(&zbus::Error::FDO(Box::new(
            zbus::fdo::Error::UnknownInterface("x".into())
        ))));
        assert!(!not_served(&zbus::Error::FDO(Box::new(
            zbus::fdo::Error::AccessDenied("x".into())
        ))));
    }
}
