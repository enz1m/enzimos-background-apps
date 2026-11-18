use super::*;
use crate::model::{defaults, tests::manifest};

fn with(base: &Policy, key: &str, value: bool) -> Policy {
    let mut p = base.clone();
    p.insert(key.into(), value);
    p
}

#[test]
fn unit_file_mutation_only_when_autostart_changes() {
    let m = manifest(false);
    let previous = defaults(&m);
    let on = with(&previous, "autostart", true);
    assert_eq!(
        policy_change(
            &m,
            &previous,
            &on,
            false,
            false,
            Some("disabled"),
            &json!("disabled")
        )
        .unwrap(),
        Some(true)
    );
    assert_eq!(
        policy_change(
            &m,
            &on,
            &previous,
            false,
            false,
            Some("enabled"),
            &json!("enabled")
        )
        .unwrap(),
        Some(false)
    );
    assert_eq!(
        policy_change(
            &m,
            &previous,
            &previous,
            false,
            false,
            Some("disabled"),
            &json!("disabled")
        )
        .unwrap(),
        None
    );
    assert_eq!(
        policy_change(
            &m,
            &previous,
            &on,
            false,
            false,
            Some("static"),
            &json!("static")
        )
        .unwrap_err()
        .0,
        "application-autostart-state-unavailable"
    );
}

#[test]
fn changed_actual_autostart_state_invalidates_saved_review() {
    let m = manifest(false);
    let previous = defaults(&m);
    let on = with(&previous, "autostart", true);
    assert_eq!(
        policy_change(
            &m,
            &previous,
            &on,
            false,
            false,
            Some("enabled"),
            &json!("disabled")
        )
        .unwrap_err()
        .0,
        "background-policy-review-stale"
    );
}

#[test]
fn unimplemented_sources_refuse_before_commit_or_unit_mutation() {
    let mut m = manifest(false);
    m.activation_sources
        .extend(["scheduled".into(), "ongoing-work".into()]);
    let previous = defaults(&m);
    for (key, value) in [("scheduled", true), ("ongoing-work", false)] {
        let code = policy_change(
            &m,
            &previous,
            &with(&previous, key, value),
            true,
            false,
            Some("disabled"),
            &json!("disabled"),
        )
        .unwrap_err();
        assert_eq!(code.0, "activation-source-adapter-unavailable");
    }
    let code = policy_change(
        &m,
        &previous,
        &with(&previous, "agent", false),
        false,
        false,
        Some("disabled"),
        &json!("disabled"),
    )
    .unwrap_err();
    assert_eq!(code.0, "agent-activation-policy-adapter-unavailable");
    assert!(
        policy_change(
            &m,
            &previous,
            &with(&previous, "agent", false),
            true,
            false,
            Some("disabled"),
            &json!("disabled")
        )
        .is_ok()
    );
}

#[test]
fn search_policy_cannot_be_written_with_an_old_mcp_reader() {
    let mut m = manifest(false);
    m.activation_sources.push("search".into());
    let previous = defaults(&m);
    let code = policy_change(
        &m,
        &previous,
        &previous,
        false,
        false,
        Some("disabled"),
        &json!("disabled"),
    )
    .unwrap_err();
    assert_eq!(code.0, "background-policy-schema-adapter-unavailable");
    let code = policy_change(
        &m,
        &previous,
        &with(&previous, "search", true),
        true,
        false,
        Some("disabled"),
        &json!("disabled"),
    )
    .unwrap_err();
    assert_eq!(code.0, "activation-source-adapter-unavailable");
}

#[test]
fn qualified_search_adapter_makes_only_search_settable() {
    let mut m = manifest(false);
    m.activation_sources
        .extend(["search".into(), "scheduled".into()]);
    let previous = defaults(&m);
    assert!(!previous["search"]);
    let on = with(&previous, "search", true);
    // Enabling and revoking search through the reviewed policy, never touching autostart.
    assert_eq!(
        policy_change(
            &m,
            &previous,
            &on,
            true,
            true,
            Some("disabled"),
            &json!("disabled")
        )
        .unwrap(),
        None
    );
    assert_eq!(
        policy_change(
            &m,
            &on,
            &previous,
            true,
            true,
            Some("disabled"),
            &json!("disabled")
        )
        .unwrap(),
        None
    );
    // Still needs the matched MCP reader for a six-source row.
    let code = policy_change(
        &m,
        &previous,
        &on,
        false,
        true,
        Some("disabled"),
        &json!("disabled"),
    )
    .unwrap_err();
    assert_eq!(code.0, "background-policy-schema-adapter-unavailable");
    let code = policy_change(
        &m,
        &previous,
        &with(&previous, "scheduled", true),
        true,
        true,
        Some("disabled"),
        &json!("disabled"),
    )
    .unwrap_err();
    assert_eq!(code.0, "activation-source-adapter-unavailable");
}

#[test]
fn only_units_behind_a_row_invalidate_the_inventory() {
    let apps = [
        ("org.example.Music", "enzui-agent-org.example.Music.service"),
        ("org.example.Mus", "enzui-agent-org.example.Mus.service"),
    ];
    let event = |unit: &str| unit_event(apps.iter().copied(), unit);
    assert_eq!(
        event("enzui-agent-org.example.Music.service"),
        UnitEvent::App("org.example.Music".into())
    );
    assert_eq!(
        event("app-flatpak-org.example.Music-3383539412.scope"),
        UnitEvent::App("org.example.Music".into())
    );
    assert_eq!(
        event("app-enzui-org.example.Mus-a1B2.scope"),
        UnitEvent::App("org.example.Mus".into())
    );
    // A Flatpak instance the portal may list.
    assert_eq!(
        event("app-flatpak-org.other.Chat-12.scope"),
        UnitEvent::Flatpak
    );
    // What a read loads (the broker unit) and anything else systemd loads
    // or garbage-collects never reaches readers.
    for unit in [
        agent_policy::UNIT,
        "dbus.socket",
        "run-u12.service",
        "app-enzui-org.other.App-1.scope",
        "enzui-agent-org.other.App.service",
    ] {
        assert_eq!(event(unit), UnitEvent::Ignore, "{unit}");
    }
}

#[test]
fn force_requires_a_unit_that_does_not_restart() {
    let mut p = crate::process_identity::tests::properties(1);
    assert!(force_ready(&p).is_ok());
    p.restart = "on-failure".into();
    assert_eq!(
        force_ready(&p).unwrap_err().0,
        "application-unit-restarts-automatically"
    );
    let mut p = crate::process_identity::tests::properties(1);
    p.kill_mode = "process".into();
    assert!(force_ready(&p).is_err());
}
