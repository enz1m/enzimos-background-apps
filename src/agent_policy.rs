// SPDX-License-Identifier: MIT
//! Source controls require an installed broker ABI and no stale running executable.
use crate::{
    process_identity::{UnitProperties, observe, trusted_unit},
    registry::{executable_identity, read},
};
use serde_json::json;
use std::path::Path;

pub const PATH: &str = "/usr/share/enzui/mcp-center/background-policy.json";
pub const UNIT: &str = "enzui-center.service";
const EXECUTABLE: &str = "/usr/bin/enzui-center";

/// The MCP broker reads this exact policy ABI and its unit is idle or verified current.
pub fn available(properties: &UnitProperties, uid: u32) -> bool {
    let expected = json!({"schema": 1, "future_agent_activation_policy_abi": 2,
        "policy_path": ".local/state/enzimos/background-apps/policy.json",
        "affects_running_apps": false, "grants_tool_consent": false});
    let descriptor = read(Path::new(PATH), 0)
        .ok()
        .and_then(|d| enzimos_platform::json::decode(&d, 16384).ok());
    if descriptor != Some(expected) || trusted_unit(properties, UNIT, 0).is_err() {
        return false;
    }
    if properties.main_pid == 0 {
        return ["inactive", "failed"].contains(&properties.active_state.as_str());
    }
    executable_identity(EXECUTABLE, 0)
        .map(|exe| {
            observe(UNIT, &exe, properties, uid, Path::new("/proc"), &|p, u| {
                trusted_unit(p, u, 0)
            })
            .identity_verified
        })
        .unwrap_or(false)
}
