// SPDX-License-Identifier: MIT
//! Bind application controls to an installed unit and a current user process.
use crate::{Result, refused, registry};
use enzimos_platform::process_identity::parse_uids;
use std::{fs, path::Path};

pub fn start_ticks(stat: &str) -> Result<u64> {
    let fields = stat
        .rfind(')')
        .map(|i| stat[i + 1..].split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.len() >= 20)
        .ok_or_else(|| refused("process-start-identity"))?;
    fields[19]
        .parse::<u64>()
        .ok()
        .filter(|t| *t > 0)
        .ok_or_else(|| refused("process-start-identity"))
}

pub fn read_start_ticks(proc: &Path, pid: u32) -> Result<u64> {
    start_ticks(
        &fs::read_to_string(proc.join(pid.to_string()).join("stat"))
            .map_err(|_| refused("process-start-identity"))?,
    )
}

/// Every UID (real, effective, saved, filesystem) is `uid`.
pub fn same_user(proc: &Path, pid: u32, uid: u32) -> bool {
    fs::read_to_string(proc.join(pid.to_string()).join("status"))
        .ok()
        .and_then(|s| parse_uids(&s).ok())
        .is_some_and(|ids| ids.iter().all(|v| *v == uid))
}

/// The systemd user-manager view of one unit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitProperties {
    pub id: String,
    pub fragment_path: String,
    pub drop_in_paths: Vec<String>,
    pub active_state: String,
    pub control_group: String,
    pub restart: String,
    pub unit_file_state: String,
    pub kill_mode: String,
    pub main_pid: u32,
    pub transient: bool,
    /// systemd's current invocation, as `$INVOCATION_ID` spells it; empty if none.
    pub invocation_id: String,
}

/// One application unit observation; only a verified identity enables controls.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    pub unit: String,
    pub state: String,
    pub main_pid: u32,
    pub start_ticks: u64,
    pub identity_verified: bool,
    pub autostart_state: String,
    pub graceful_adapter_verified: bool,
    pub graceful_admission_failure: Option<String>,
}

impl Unit {
    pub fn unknown(unit: &str) -> Self {
        Self {
            unit: unit.into(),
            state: "unknown".into(),
            autostart_state: "unknown".into(),
            ..Default::default()
        }
    }
    /// Fields that bind a stop to one process; adapter diagnostics are excluded.
    pub fn identity(&self) -> (&str, &str, u32, u64, bool, &str) {
        (
            &self.unit,
            &self.state,
            self.main_pid,
            self.start_ticks,
            self.identity_verified,
            &self.autostart_state,
        )
    }
}

pub fn trusted_unit(properties: &UnitProperties, unit: &str, owner: u32) -> Result<()> {
    if properties.id != unit || properties.transient {
        return Err(refused("application-unit-not-installed"));
    }
    let paths = std::iter::once(&properties.fragment_path)
        .chain(&properties.drop_in_paths)
        .collect::<Vec<_>>();
    if properties.fragment_path.is_empty() || paths.len() > 17 {
        return Err(refused("application-unit-fragment"));
    }
    for item in paths {
        if !(item.starts_with("/usr/lib/systemd/user/") || item.starts_with("/etc/systemd/user/"))
            || item.split('/').any(|p| p == "..")
        {
            return Err(refused("application-unit-untrusted-path"));
        }
        registry::read(Path::new(item), owner)?;
    }
    Ok(())
}

pub type UnitCheck<'a> = &'a dyn Fn(&UnitProperties, &str) -> Result<()>;

pub fn installed_unit(properties: &UnitProperties, unit: &str) -> Result<()> {
    trusted_unit(properties, unit, 0)
}

/// Observe the unit's main process: installed unit, same user, exact
/// executable inode, the unit's own cgroup and an unchanged start time.
pub fn observe(
    unit: &str,
    executable: &registry::Executable,
    properties: &UnitProperties,
    uid: u32,
    proc: &Path,
    unit_check: UnitCheck,
) -> Unit {
    let mut result = Unit {
        unit: unit.into(),
        state: if properties.active_state.is_empty() {
            "inactive".into()
        } else {
            properties.active_state.clone()
        },
        autostart_state: properties.unit_file_state.clone(),
        ..Default::default()
    };
    let pid = properties.main_pid;
    if pid == 0 {
        return result;
    }
    result.main_pid = pid;
    let verified = (|| -> Result<u64> {
        unit_check(properties, unit)?;
        let directory = proc.join(pid.to_string());
        let before = read_start_ticks(proc, pid)?;
        if !same_user(proc, pid, uid) {
            return Err(refused("application-process-user"));
        }
        if !executable.matches(&fs::metadata(directory.join("exe"))?) {
            return Err(refused("application-process-executable"));
        }
        let cgroup = &properties.control_group;
        if !cgroup.starts_with("/user.slice/")
            || Path::new(cgroup).file_name().is_none_or(|n| n != unit)
        {
            return Err(refused("application-process-cgroup"));
        }
        let expected = format!("0::{cgroup}");
        if !fs::read_to_string(directory.join("cgroup"))?
            .lines()
            .any(|l| l == expected)
        {
            return Err(refused("application-process-cgroup"));
        }
        if read_start_ticks(proc, pid)? != before {
            return Err(refused("application-process-replaced"));
        }
        Ok(before)
    })();
    if let Ok(ticks) = verified {
        result.start_ticks = ticks;
        result.identity_verified = true;
    }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::registry::tests::{private_dir, uid, write};
    use std::os::unix::fs::symlink;

    pub fn stat(pid: u32, ticks: u64) -> String {
        format!(
            "{pid} (music app) S 1 {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0"
        )
    }
    /// A fake /proc entry whose exe links to `exe`.
    pub fn process(proc: &Path, pid: u32, ticks: u64, uid: u32, exe: &Path, cgroup: &str) {
        let dir = proc.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), stat(pid, ticks)).unwrap();
        fs::write(
            dir.join("status"),
            format!("Name:\tmusic\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )
        .unwrap();
        fs::write(dir.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
        let _ = fs::remove_file(dir.join("exe"));
        symlink(exe, dir.join("exe")).unwrap();
    }
    pub const CGROUP: &str = "/user.slice/user-1000.slice/user@1000.service/app.slice/enzui-agent-org.example.Music.service";
    pub fn properties(pid: u32) -> UnitProperties {
        UnitProperties {
            id: "enzui-agent-org.example.Music.service".into(),
            fragment_path: "/usr/lib/systemd/user/enzui-agent-org.example.Music.service".into(),
            active_state: "active".into(),
            control_group: CGROUP.into(),
            restart: "no".into(),
            unit_file_state: "disabled".into(),
            kill_mode: "control-group".into(),
            main_pid: pid,
            ..Default::default()
        }
    }
    pub fn ok(_: &UnitProperties, _: &str) -> Result<()> {
        Ok(())
    }

    #[test]
    fn start_ticks_parse_after_command_name() {
        assert_eq!(start_ticks(&stat(42, 777)).unwrap(), 777);
        assert!(start_ticks("42 (x) S 1").is_err());
        assert!(start_ticks(&stat(42, 0)).is_err());
    }

    #[test]
    fn current_exact_executable_uid_and_cgroup_admitted_and_changes_refused() {
        let dir = private_dir();
        let exe = dir.path().join("music");
        write(&exe, "#!/bin/sh\n", 0o755);
        let identity = registry::executable_identity(exe.to_str().unwrap(), uid()).unwrap();
        let proc = dir.path().join("proc");
        let unit = "enzui-agent-org.example.Music.service";
        process(&proc, 4242, 99, uid(), &exe, CGROUP);
        let seen = observe(unit, &identity, &properties(4242), uid(), &proc, &ok);
        assert!(seen.identity_verified);
        assert_eq!((seen.main_pid, seen.start_ticks), (4242, 99));
        // Another user, cgroup, or binary is observed but not controllable.
        process(&proc, 4242, 99, uid() + 1, &exe, CGROUP);
        assert!(!observe(unit, &identity, &properties(4242), uid(), &proc, &ok).identity_verified);
        process(&proc, 4242, 99, uid(), &exe, "/user.slice/other.service");
        assert!(!observe(unit, &identity, &properties(4242), uid(), &proc, &ok).identity_verified);
        let other = dir.path().join("other");
        write(&other, "#!/bin/sh\n", 0o755);
        process(&proc, 4242, 99, uid(), &other, CGROUP);
        assert!(!observe(unit, &identity, &properties(4242), uid(), &proc, &ok).identity_verified);
        // Missing process or no main PID never verifies.
        assert!(!observe(unit, &identity, &properties(77), uid(), &proc, &ok).identity_verified);
        assert_eq!(
            observe(unit, &identity, &properties(0), uid(), &proc, &ok).main_pid,
            0
        );
    }

    #[test]
    fn uninstalled_or_transient_units_refused() {
        let mut p = properties(1);
        p.transient = true;
        assert_eq!(
            trusted_unit(&p, &p.id.clone(), 0).unwrap_err().0,
            "application-unit-not-installed"
        );
        let mut p = properties(1);
        p.fragment_path = "/home/user/.config/systemd/user/x.service".into();
        assert_eq!(
            trusted_unit(&p, &p.id.clone(), 0).unwrap_err().0,
            "application-unit-untrusted-path"
        );
        let mut p = properties(1);
        p.fragment_path.clear();
        assert_eq!(
            trusted_unit(&p, &p.id.clone(), 0).unwrap_err().0,
            "application-unit-fragment"
        );
    }
}
