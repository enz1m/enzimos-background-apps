// SPDX-License-Identifier: MIT
//! User-bus identity with logind session checks and fixed native control clients.
use crate::{
    Result, bounded,
    process_identity::{read_start_ticks, same_user},
    refused,
    registry::{Executable, executable_identity},
};
use enzimos_system_backend::authority::Authority as SystemAuthority;
use std::{collections::BTreeSet, fs, path::Path};
use zbus::{
    Connection,
    fdo::DBusProxy,
    names::{BusName, UniqueName},
};

pub const CLIENTS: [&str; 3] = [
    "/usr/lib/enzui/apps/terminal-emulator",
    "/usr/lib/enzui/bin/enzui-settings",
    "/usr/lib/enzui/bin/enzui-shell",
];

/// The installed shell; only it asks for search activation.
pub const SHELL: &str = "/usr/lib/enzui/bin/enzui-shell";

/// One process: `Ok(None)` when it runs one of `clients`, else its parent.
fn step(pid: u32, uid: u32, proc: &Path, clients: &[Executable]) -> Result<Option<u32>> {
    let directory = proc.join(pid.to_string());
    if directory.join("root/.flatpak-info").exists() {
        return Err(refused("flatpak"));
    }
    let stat = fs::read_to_string(directory.join("stat"))?;
    let before = crate::process_identity::start_ticks(&stat)?;
    let parent = stat
        .rfind(')')
        .and_then(|i| stat[i + 1..].split_whitespace().nth(1))
        .and_then(|p| p.parse::<u32>().ok())
        .ok_or_else(|| refused("stat"))?;
    if !same_user(proc, pid, uid) {
        return Err(refused("user"));
    }
    let actual = fs::metadata(directory.join("exe"))?;
    let matched = clients.iter().any(|c| c.matches(&actual));
    if read_start_ticks(proc, pid)? != before {
        return Err(refused("replaced"));
    }
    Ok(if matched { None } else { Some(parent) })
}

/// The caller or one of its ancestors is an installed control client, all
/// running as `uid` outside any Flatpak sandbox.
pub fn trusted_client(mut pid: u32, uid: u32, proc: &Path, clients: &[Executable]) -> bool {
    let mut visited = BTreeSet::new();
    for _ in 0..16 {
        if pid <= 1 || !visited.insert(pid) {
            return false;
        }
        match step(pid, uid, proc, clients) {
            Ok(None) => return true,
            Ok(Some(parent)) => pid = parent,
            Err(_) => return false,
        }
    }
    false
}

/// The caller itself (not an ancestor) runs `client`.
pub fn direct_client(pid: u32, uid: u32, proc: &Path, client: Option<&Executable>) -> bool {
    pid > 1
        && client.is_some_and(|c| matches!(step(pid, uid, proc, std::slice::from_ref(c)), Ok(None)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub start_ticks: u64,
    pub session: String,
    pub origin_session: Option<String>,
    pub trusted_control_client: bool,
    /// The caller process is the installed shell itself.
    pub shell: bool,
}

pub struct Authority {
    user: Connection,
    system: SystemAuthority,
    uid: u32,
}

impl Authority {
    pub fn new(user: Connection, system: SystemAuthority, uid: u32) -> Self {
        Self { user, system, uid }
    }
    /// True once logind was replaced; this process can no longer bind callers.
    pub fn stale(&self) -> bool {
        self.system.stale()
    }

    async fn credentials(&self, sender: &str) -> Result<(u32, u32)> {
        let code = "active-trusted-local-client-required";
        let name =
            UniqueName::try_from(sender).map_err(|_| refused("unique-user-bus-sender-required"))?;
        let daemon = bounded(DBusProxy::new(&self.user), 2, code).await?;
        if !bounded(
            daemon.name_has_owner(BusName::Unique(name.clone())),
            2,
            code,
        )
        .await?
        {
            return Err(refused(code));
        }
        let uid = bounded(
            daemon.get_connection_unix_user(BusName::Unique(name.clone())),
            2,
            code,
        )
        .await?;
        let pid = bounded(
            daemon.get_connection_unix_process_id(BusName::Unique(name)),
            2,
            code,
        )
        .await?;
        Ok((uid, pid))
    }

    /// A same-user caller in this user's active, unlocked, local graphical session.
    pub async fn peer(&self, sender: &str) -> Result<Peer> {
        let refuse = || refused("active-trusted-local-client-required");
        let (uid, pid) = self.credentials(sender).await?;
        if uid != self.uid {
            return Err(refuse());
        }
        let session = self
            .system
            .session_for(uid, pid)
            .await
            .map_err(|_| refuse())?;
        if !["wayland", "x11"].contains(&session.kind.as_str()) {
            return Err(refuse());
        }
        let proc = Path::new("/proc");
        let clients = CLIENTS
            .iter()
            .filter_map(|p| executable_identity(p, 0).ok())
            .collect::<Vec<_>>();
        let peer = Peer {
            pid,
            start_ticks: read_start_ticks(proc, pid).map_err(|_| refuse())?,
            session: session.session,
            origin_session: session.origin_session,
            trusted_control_client: trusted_client(pid, uid, proc, &clients),
            shell: direct_client(pid, uid, proc, executable_identity(SHELL, 0).ok().as_ref()),
        };
        if self.credentials(sender).await? != (uid, pid) {
            return Err(refuse());
        }
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        process_identity::tests::process,
        registry::tests::{private_dir, uid, write},
    };

    #[test]
    fn launched_by_a_control_client_is_trusted_but_flatpak_and_other_users_are_not() {
        let dir = private_dir();
        let (shell, tool) = (dir.path().join("shell"), dir.path().join("tool"));
        write(&shell, "#!/bin/sh\n", 0o755);
        write(&tool, "#!/bin/sh\n", 0o755);
        let proc = dir.path().join("proc");
        process(&proc, 10, 5, uid(), &shell, "/");
        process(&proc, 20, 6, uid(), &tool, "/");
        // Re-parent the tool under the shell.
        fs::write(
            proc.join("20/stat"),
            "20 (tool) S 10 20 20 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 6 0 0",
        )
        .unwrap();
        fs::write(
            proc.join("10/stat"),
            "10 (shell) S 1 10 10 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0",
        )
        .unwrap();
        let clients = [Executable::of(
            shell.to_string_lossy().into(),
            &fs::metadata(&shell).unwrap(),
        )];
        assert!(trusted_client(20, uid(), &proc, &clients));
        assert!(!trusted_client(20, uid(), &proc, &[]));
        assert!(!trusted_client(20, uid() + 1, &proc, &clients));
        // Only the shell process itself is the direct search caller.
        assert!(direct_client(10, uid(), &proc, clients.first()));
        assert!(!direct_client(20, uid(), &proc, clients.first()));
        assert!(!direct_client(10, uid(), &proc, None));
        fs::create_dir_all(proc.join("20/root")).unwrap();
        fs::write(proc.join("20/root/.flatpak-info"), "").unwrap();
        assert!(!trusted_client(20, uid(), &proc, &clients));
    }
}
