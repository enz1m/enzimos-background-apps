// SPDX-License-Identifier: MIT
//! Window presence, work and future activation are independent application facts.
use crate::{Result, lifecycle, manifest::Manifest, process_identity::Unit, refused};
use enzimos_platform::json::fingerprint;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const ACTIVE: [&str; 4] = ["active", "activating", "reloading", "refreshing"];
const STATES: [&str; 8] = [
    "active",
    "activating",
    "reloading",
    "refreshing",
    "inactive",
    "failed",
    "deactivating",
    "unknown",
];
pub const MODES: [&str; 4] = ["graceful", "finish-then-exit", "cancel-and-exit", "force"];

pub type Policy = BTreeMap<String, bool>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    pub known: bool,
    pub count: u32,
    pub minimized: u32,
}
pub const UNKNOWN_WINDOWS: Windows = Windows {
    known: false,
    count: 0,
    minimized: 0,
};

pub fn digest(value: &Value) -> String {
    fingerprint(value).unwrap_or_default()
}

/// User launch, agent activation and ongoing work default on; everything else off.
pub fn defaults(manifest: &Manifest) -> Policy {
    manifest
        .activation_sources
        .iter()
        .map(|s| {
            (
                s.clone(),
                matches!(s.as_str(), "user" | "agent" | "ongoing-work"),
            )
        })
        .collect()
}

/// A requested policy names every declared source and never disables direct user launch.
pub fn requested(manifest: &Manifest, value: &Value) -> Result<Policy> {
    let fields = || refused("background-policy-fields");
    let object = value.as_object().ok_or_else(fields)?;
    let defaults = defaults(manifest);
    if !object.keys().eq(defaults.keys()) {
        return Err(fields());
    }
    let policy = object
        .iter()
        .map(|(k, v)| v.as_bool().map(|b| (k.clone(), b)))
        .collect::<Option<Policy>>()
        .ok_or_else(fields)?;
    if policy.get("user") == Some(&false) {
        return Err(fields());
    }
    Ok(policy)
}

pub fn policy_value(policy: &Policy) -> Value {
    json!(policy)
}

pub fn snapshot(
    manifest: &Manifest,
    unit: &Unit,
    windows: &Windows,
    settings: &Policy,
) -> Result<Value> {
    if !STATES.contains(&unit.state.as_str()) {
        return Err(refused("background-unit-observation"));
    }
    if unit.unit != manifest.unit {
        return Err(refused("background-unit-identity"));
    }
    if windows.count > 256 || windows.minimized > windows.count {
        return Err(refused("background-window-observation"));
    }
    let running = ACTIVE.contains(&unit.state.as_str());
    let visibility = if !windows.known {
        "unknown"
    } else if windows.count == 0 {
        "windowless"
    } else {
        "has-windows"
    };
    let controls = running && unit.identity_verified;
    let autostart = manifest
        .autostart_supported
        .then(|| unit.autostart_state.clone());
    Ok(json!({
        "schema": 1, "app_id": manifest.app_id, "title": manifest.title, "purpose": manifest.purpose,
        "running": running, "unit_observation_known": unit.state != "unknown", "unit_state": unit.state,
        "visibility": visibility, "background": running && visibility == "windowless",
        "window_count": windows.known.then_some(windows.count),
        "minimized_window_count": windows.known.then_some(windows.minimized),
        // No work adapter is installed: work is unknown, never "nothing running".
        "work": [], "work_observation_known": false,
        "activation_policy": settings, "agent_tool_consent_required": true,
        "autostart_supported": manifest.autostart_supported, "autostart_state": autostart,
        "graceful_stop_supported": controls && manifest.graceful() && unit.graceful_adapter_verified,
        "force_stop_supported": controls, "identity_verified": unit.identity_verified,
        "stopping_disables_future_activation": false, "changing_policy_stops_ongoing_work": false,
    }))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Review {
    pub plan: Value,
    pub plan_sha256: String,
}

impl Review {
    pub fn value(&self) -> Value {
        json!({"plan": self.plan, "plan_sha256": self.plan_sha256})
    }
}

pub fn stop_review(
    manifest: &Manifest,
    unit: &Unit,
    windows: &Windows,
    mode: &str,
    settings: &Policy,
) -> Result<Review> {
    let state = snapshot(manifest, unit, windows, settings)?;
    if !MODES.contains(&mode) || state["running"] != true || !unit.identity_verified {
        return Err(refused("background-stop-unavailable"));
    }
    if mode != "force" && state["graceful_stop_supported"] != true {
        return Err(refused("application-graceful-stop-unavailable"));
    }
    if unit.main_pid == 0 || unit.start_ticks == 0 {
        return Err(refused("background-process-identity"));
    }
    let plan = json!({
        "schema": 1, "app_id": manifest.app_id, "unit": manifest.unit, "mode": mode,
        "main_pid": unit.main_pid, "start_ticks": unit.start_ticks,
        "manifest_sha256": digest(&manifest.value()), "observation_sha256": digest(&state),
        "active_work_count": null, "may_interrupt_work": true,
        "may_close_windows": !windows.known || windows.count > 0,
        "future_activation_policy_changed": false, "personal_files_removed": false,
    });
    Ok(Review {
        plan_sha256: digest(&plan),
        plan,
    })
}

/// Progress detail is display-only; the authorized plan binds work membership.
pub fn stop_authorization(plan: &Value) -> Value {
    let mut plan = plan.clone();
    if let Some(review) = plan.get("lifecycle").cloned() {
        plan["lifecycle"] = lifecycle::authorization(&review);
    }
    plan
}

pub fn stop_digest(plan: &Value) -> String {
    digest(&stop_authorization(plan))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manifest::decode;

    pub fn manifest(graceful: bool) -> Manifest {
        let mut m = decode(
            crate::registry::tests::manifest_json("org.example.Music").as_bytes(),
            "org.example.Music.json",
        )
        .unwrap();
        if graceful {
            m.graceful_stop = crate::manifest::GRACEFUL.into();
        }
        m
    }
    pub fn unit(state: &str, verified: bool) -> Unit {
        Unit {
            unit: "enzui-agent-org.example.Music.service".into(),
            state: state.into(),
            main_pid: 4242,
            start_ticks: 99,
            identity_verified: verified,
            autostart_state: "disabled".into(),
            graceful_adapter_verified: true,
            graceful_admission_failure: None,
        }
    }
    pub fn windows(count: u32, minimized: u32) -> Windows {
        Windows {
            known: true,
            count,
            minimized,
        }
    }

    #[test]
    fn unknown_window_state_does_not_invent_headless_status() {
        let m = manifest(false);
        let s = snapshot(&m, &unit("active", true), &UNKNOWN_WINDOWS, &defaults(&m)).unwrap();
        assert_eq!(s["visibility"], "unknown");
        assert_eq!(s["background"], false);
        assert!(s["window_count"].is_null());
    }

    #[test]
    fn windowless_running_app_and_sources_remain_separate() {
        let m = manifest(false);
        let s = snapshot(&m, &unit("active", true), &windows(0, 0), &defaults(&m)).unwrap();
        assert_eq!(s["background"], true);
        assert_eq!(
            s["activation_policy"],
            json!({"agent": true, "autostart": false, "user": true})
        );
        assert_eq!(s["stopping_disables_future_activation"], false);
        assert_eq!(s["work_observation_known"], false);
    }

    #[test]
    fn stop_review_bound_to_pid_and_manifest() {
        let m = manifest(false);
        let a = stop_review(
            &m,
            &unit("active", true),
            &windows(0, 0),
            "force",
            &defaults(&m),
        )
        .unwrap();
        let mut moved = unit("active", true);
        moved.start_ticks = 100;
        let b = stop_review(&m, &moved, &windows(0, 0), "force", &defaults(&m)).unwrap();
        assert_ne!(a.plan_sha256, b.plan_sha256);
        assert_eq!(a.plan["may_interrupt_work"], true);
        assert_eq!(a.plan["may_close_windows"], false);
    }

    #[test]
    fn unknown_identity_cannot_be_stopped() {
        let m = manifest(false);
        let code = stop_review(
            &m,
            &unit("active", false),
            &windows(0, 0),
            "force",
            &defaults(&m),
        )
        .unwrap_err();
        assert_eq!(code.0, "background-stop-unavailable");
        let code = stop_review(
            &m,
            &unit("inactive", true),
            &windows(0, 0),
            "force",
            &defaults(&m),
        )
        .unwrap_err();
        assert_eq!(code.0, "background-stop-unavailable");
    }

    #[test]
    fn unknown_window_presence_warns_that_force_may_close_windows() {
        let m = manifest(false);
        let r = stop_review(
            &m,
            &unit("active", true),
            &UNKNOWN_WINDOWS,
            "force",
            &defaults(&m),
        )
        .unwrap();
        assert_eq!(r.plan["may_close_windows"], true);
    }

    #[test]
    fn unavailable_graceful_stop_does_not_silently_force() {
        let m = manifest(false);
        let code = stop_review(
            &m,
            &unit("active", true),
            &windows(0, 0),
            "graceful",
            &defaults(&m),
        )
        .unwrap_err();
        assert_eq!(code.0, "application-graceful-stop-unavailable");
        let m = manifest(true);
        let mut u = unit("active", true);
        u.graceful_adapter_verified = false;
        let code =
            stop_review(&m, &u, &windows(0, 0), "finish-then-exit", &defaults(&m)).unwrap_err();
        assert_eq!(code.0, "application-graceful-stop-unavailable");
        assert!(
            stop_review(
                &m,
                &unit("active", true),
                &windows(0, 0),
                "finish-then-exit",
                &defaults(&m)
            )
            .is_ok()
        );
    }

    #[test]
    fn policy_cannot_disable_direct_user_launch_or_forge_sources() {
        let m = manifest(false);
        assert!(
            requested(
                &m,
                &json!({"user": true, "agent": false, "autostart": true})
            )
            .is_ok()
        );
        for bad in [
            json!({"user": false, "agent": true, "autostart": false}),
            json!({"user": true, "agent": true}),
            json!({"user": true, "agent": true, "autostart": false, "search": true}),
            json!({"user": true, "agent": 1, "autostart": false}),
        ] {
            assert_eq!(
                requested(&m, &bad).unwrap_err().0,
                "background-policy-fields"
            );
        }
    }
}
