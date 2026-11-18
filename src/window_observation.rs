// SPDX-License-Identifier: MIT
//! Bounded shell observations are tied to one owner and exact app process identity.
use crate::{
    Result, bounded,
    manifest::{app_id as valid_app, text},
    model::{UNKNOWN_WINDOWS, Windows},
    process_identity::{Unit, read_start_ticks, same_user},
    refused, registry,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zbus::{Connection, Proxy, fdo::DBusProxy, names::BusName};

pub const NAME: &str = "dev.enzui.Shell";
pub const PATH: &str = "/dev/enzui/Shell/Windows";
pub const INTERFACE: &str = "dev.enzui.Shell.Windows1";
const SHELL: &str = "/usr/lib/enzui/bin/enzui-shell";

/// (app_id, unit, main_pid, start_ticks, mapped, minimized) on the wire.
pub type Row = (String, String, u32, u64, u32, u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u64,
    pub known: bool,
    pub rows: Vec<Row>,
}

fn scope(unit: &str, prefix: &str, digits_only: bool) -> bool {
    unit.strip_prefix(prefix)
        .and_then(|r| r.strip_suffix(".scope"))
        .is_some_and(|id| {
            !id.is_empty()
                && id.bytes().all(|c| {
                    if digits_only {
                        c.is_ascii_digit()
                    } else {
                        c.is_ascii_alphanumeric()
                    }
                })
        })
}

pub fn decode(generation: u64, known: bool, rows: Vec<Row>) -> Result<Snapshot> {
    if rows.len() > 256 {
        return Err(refused("shell-window-snapshot-bound"));
    }
    let mut identities = std::collections::BTreeSet::new();
    for (app, unit, pid, ticks, mapped, minimized) in &rows {
        if !text(app, 127) || !valid_app(app) || !text(unit, 255) {
            return Err(refused("shell-window-entry-identity"));
        }
        if !(*unit == format!("enzui-agent-{app}.service")
            || scope(unit, &format!("app-enzui-{app}-"), false)
            || scope(unit, &format!("app-flatpak-{app}-"), true))
        {
            return Err(refused("shell-window-entry-unit"));
        }
        if *pid == 0 || *ticks == 0 || minimized > mapped || *mapped > 256 {
            return Err(refused("shell-window-entry-process-or-count"));
        }
        if !identities.insert((app, unit, pid, ticks)) {
            return Err(refused("shell-window-duplicate-process"));
        }
    }
    Ok(Snapshot {
        generation,
        known,
        rows,
    })
}

/// Windows of one verified app process; anything else stays unknown.
pub fn observation(snapshot: &Snapshot, app_id: &str, unit: &Unit) -> Windows {
    if !snapshot.known || !unit.identity_verified {
        return UNKNOWN_WINDOWS;
    }
    let matches = snapshot
        .rows
        .iter()
        .filter(|r| r.0 == app_id)
        .collect::<Vec<_>>();
    if matches
        .iter()
        .any(|r| (r.1.as_str(), r.2, r.3) != (unit.unit.as_str(), unit.main_pid, unit.start_ticks))
    {
        return UNKNOWN_WINDOWS;
    }
    let count = matches.iter().map(|r| r.4).sum::<u32>();
    let minimized = matches.iter().map(|r| r.5).sum::<u32>();
    if count > 256 {
        return UNKNOWN_WINDOWS;
    }
    Windows {
        known: true,
        count,
        minimized,
    }
}

pub type OwnerIdentity = (u32, u64, u64, u64);

/// The bus owner is the installed shell binary, running as this user, unreplaced.
pub fn verify_owner(pid: u32, uid: u32, proc: &Path, shell: &Path) -> Result<OwnerIdentity> {
    let before = read_start_ticks(proc, pid)?;
    let expected = registry::executable_identity(&shell.to_string_lossy(), 0)?;
    let actual = fs::metadata(proc.join(pid.to_string()).join("exe"))?;
    use std::os::unix::fs::MetadataExt;
    if (actual.dev(), actual.ino()) != (expected.device, expected.inode) {
        return Err(refused("shell-window-owner-executable"));
    }
    if !same_user(proc, pid, uid) {
        return Err(refused("shell-window-owner-user"));
    }
    if read_start_ticks(proc, pid)? != before {
        return Err(refused("shell-window-owner-replaced"));
    }
    Ok((pid, before, actual.dev(), actual.ino()))
}

pub struct Adapter {
    bus: Connection,
    uid: u32,
    proc: PathBuf,
    pub owner: Option<String>,
    identity: Option<OwnerIdentity>,
    cached: Option<Snapshot>,
}

impl Adapter {
    pub fn new(bus: Connection, uid: u32) -> Self {
        Self {
            bus,
            uid,
            proc: PathBuf::from("/proc"),
            owner: None,
            identity: None,
            cached: None,
        }
    }
    pub fn invalidate(&mut self) {
        self.cached = None;
    }
    pub fn owner_lost(&mut self) {
        self.owner = None;
        self.cached = None;
    }

    pub async fn query(&mut self, app_id: &str, unit: &Unit) -> Windows {
        if !unit.identity_verified {
            return UNKNOWN_WINDOWS;
        }
        match self.refresh().await {
            Ok(snapshot) => observation(snapshot, app_id, unit),
            Err(_) => {
                self.cached = None;
                UNKNOWN_WINDOWS
            }
        }
    }

    async fn current(&self) -> Result<(String, OwnerIdentity)> {
        let code = "shell-window-owner";
        let daemon = bounded(DBusProxy::new(&self.bus), 1, code).await?;
        let owner = bounded(
            daemon.get_name_owner(BusName::try_from(NAME).map_err(|_| refused(code))?),
            1,
            code,
        )
        .await?;
        let unique = || BusName::Unique(owner.inner().clone());
        if bounded(daemon.get_connection_unix_user(unique()), 1, code).await? != self.uid {
            return Err(refused(code));
        }
        let pid = bounded(daemon.get_connection_unix_process_id(unique()), 1, code).await?;
        Ok((
            owner.to_string(),
            verify_owner(pid, self.uid, &self.proc, Path::new(SHELL))?,
        ))
    }

    async fn refresh(&mut self) -> Result<&Snapshot> {
        let (owner, identity) = self.current().await?;
        if Some(&owner) != self.owner.as_ref() || Some(identity) != self.identity {
            self.owner = Some(owner.clone());
            self.identity = Some(identity);
            self.cached = None;
        }
        if self.cached.is_none() {
            let code = "shell-window-snapshot";
            let proxy = bounded(
                Proxy::new_owned(self.bus.clone(), owner.clone(), PATH, INTERFACE),
                2,
                code,
            )
            .await?;
            let (generation, known, rows): (u64, bool, Vec<Row>) =
                bounded(proxy.call("GetApps", &()), 2, code).await?;
            let snapshot = decode(generation, known, rows)?;
            if self.current().await? != (owner, identity) {
                return Err(refused("shell-window-owner-changed"));
            }
            self.cached = Some(snapshot);
        }
        Ok(self.cached.as_ref().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::tests::unit,
        process_identity::tests::process,
        registry::tests::{private_dir, uid, write},
    };

    fn row(app: &str, unit: &str, pid: u32, ticks: u64, mapped: u32, minimized: u32) -> Row {
        (app.into(), unit.into(), pid, ticks, mapped, minimized)
    }
    const APP: &str = "org.example.Music";
    const UNIT: &str = "enzui-agent-org.example.Music.service";

    #[test]
    fn other_flatpak_windows_do_not_hide_native_observations() {
        let s = decode(
            1,
            true,
            vec![
                row(APP, UNIT, 4242, 99, 1, 0),
                row(
                    "org.other.App",
                    "app-flatpak-org.other.App-123.scope",
                    7,
                    8,
                    2,
                    0,
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            observation(&s, APP, &unit("active", true)),
            Windows {
                known: true,
                count: 1,
                minimized: 0
            }
        );
        let minimized = decode(1, true, vec![row(APP, UNIT, 4242, 99, 2, 2)]).unwrap();
        assert_eq!(
            observation(&minimized, APP, &unit("active", true)),
            Windows {
                known: true,
                count: 2,
                minimized: 2
            }
        );
        let none = decode(1, true, vec![]).unwrap();
        assert_eq!(
            observation(&none, APP, &unit("active", true)),
            Windows {
                known: true,
                count: 0,
                minimized: 0
            }
        );
    }

    #[test]
    fn scope_app_identity_and_flatpak_instance_are_exact() {
        assert!(
            decode(
                1,
                true,
                vec![row(
                    APP,
                    "app-enzui-org.example.Music-a1B2.scope",
                    5,
                    6,
                    1,
                    0
                )]
            )
            .is_ok()
        );
        for unit in [
            "app-flatpak-org.example.Music-x1.scope",
            "app-enzui-org.other.App-1.scope",
            "enzui-agent-org.other.App.service",
        ] {
            assert_eq!(
                decode(1, true, vec![row(APP, unit, 5, 6, 1, 0)])
                    .unwrap_err()
                    .0,
                "shell-window-entry-unit"
            );
        }
    }

    #[test]
    fn unknown_and_replaced_process_are_not_windowless() {
        let unknown = decode(1, false, vec![]).unwrap();
        assert_eq!(
            observation(&unknown, APP, &unit("active", true)),
            UNKNOWN_WINDOWS
        );
        let replaced = decode(1, true, vec![row(APP, UNIT, 4242, 100, 1, 0)]).unwrap();
        assert_eq!(
            observation(&replaced, APP, &unit("active", true)),
            UNKNOWN_WINDOWS
        );
        let s = decode(1, true, vec![row(APP, UNIT, 4242, 99, 1, 0)]).unwrap();
        assert_eq!(
            observation(&s, APP, &unit("active", false)),
            UNKNOWN_WINDOWS
        );
    }

    #[test]
    fn hostile_snapshots_are_bounded() {
        assert_eq!(
            decode(1, true, vec![row(APP, UNIT, 1, 1, 1, 0); 257])
                .unwrap_err()
                .0,
            "shell-window-snapshot-bound"
        );
        assert_eq!(
            decode(1, true, vec![row(APP, UNIT, 0, 1, 1, 0)])
                .unwrap_err()
                .0,
            "shell-window-entry-process-or-count"
        );
        assert_eq!(
            decode(1, true, vec![row(APP, UNIT, 1, 1, 1, 2)])
                .unwrap_err()
                .0,
            "shell-window-entry-process-or-count"
        );
        assert_eq!(
            decode(1, true, vec![row(APP, UNIT, 1, 1, 1, 0); 2])
                .unwrap_err()
                .0,
            "shell-window-duplicate-process"
        );
        assert_eq!(
            decode(1, true, vec![row("bad", UNIT, 1, 1, 1, 0)])
                .unwrap_err()
                .0,
            "shell-window-entry-identity"
        );
    }

    #[test]
    fn owner_binary_and_all_uids_are_verified() {
        let dir = private_dir();
        let shell = dir.path().join("enzui-shell");
        write(&shell, "#!/bin/sh\n", 0o755);
        let proc = dir.path().join("proc");
        process(&proc, 300, 5, uid(), &shell, "/");
        // The fixed shell path must be root-owned, so a user-owned test binary is refused.
        assert!(verify_owner(300, uid(), &proc, &shell).is_err());
    }
}
