use super::*;

fn row(map: &[(&str, OwnedValue)]) -> HashMap<String, OwnedValue> {
    map.iter()
        .map(|(k, v)| ((*k).to_owned(), v.try_clone().unwrap()))
        .collect()
}

#[test]
fn portal_rows_are_validated_not_guessed() {
    let s = |t: &str| OwnedValue::try_from(zbus::zvariant::Value::from(t)).unwrap();
    let rows = vec![
        row(&[
            ("app_id", s("org.example.Music")),
            ("instance", s("1234")),
            ("message", s("Playing \u{202e}x")),
        ]),
        row(&[("app_id", s("../etc")), ("instance", s("1"))]),
        row(&[("app_id", s("org.example.Sync")), ("instance", s("12a"))]),
        row(&[("app_id", s("org.example.Mail")), ("instance", s("7"))]),
    ];
    let apps = portal_rows(&rows);
    assert_eq!(apps.len(), 2);
    assert_eq!(apps[0].message, "Playing x");
    assert_eq!(
        (apps[1].app_id.as_str(), apps[1].message.as_str()),
        ("org.example.Mail", "")
    );
}

/// A fake instance record and sandbox process; the returned file holds the
/// `.ref` lock as bwrap does while the sandbox runs.
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, getuid).")]
fn sandbox(root: &Path, instance: &str, pid: u32, app: &str, info_instance: &str) -> std::fs::File {
    let dir = root.join("run/.flatpak").join(instance);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("info"), format!("[Application]\nname={app}\n")).unwrap();
    std::fs::write(
        dir.join("bwrapinfo.json"),
        format!("{{\n    \"child-pid\": {pid},\n    \"pid-namespace\": 4026534445\n}}\n"),
    )
    .unwrap();
    let process = root.join("proc").join(pid.to_string());
    std::fs::create_dir_all(process.join("root")).unwrap();
    let uid = unsafe { libc::getuid() };
    std::fs::write(
        process.join("status"),
        format!("Name:\tbwrap\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
    )
    .unwrap();
    std::fs::write(
        process.join("root/.flatpak-info"),
        format!("[Application]\nname={app}\n\n[Instance]\ninstance-id={info_instance}\n"),
    )
    .unwrap();
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join(".ref"))
        .unwrap();
    let mut l: libc::flock = unsafe { std::mem::zeroed() };
    (l.l_type, l.l_whence) = (libc::F_RDLCK as _, libc::SEEK_SET as _);
    // An OFD lock conflicts with the POSIX lock query even in this process.
    assert_eq!(
        unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_OFD_SETLK, &l) },
        0
    );
    lock
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn portal_rows_are_cross_checked_against_the_live_instance() {
    let root = private_root();
    let (run, proc, uid) = (root.path().join("run"), root.path().join("proc"), unsafe {
        libc::getuid()
    });
    let state = |app: &str, instance: &str| instance_state(&run, &proc, uid, app, instance);
    let lock = sandbox(
        root.path(),
        "3383539412",
        4242,
        "org.example.Music",
        "3383539412",
    );
    assert_eq!(
        state("org.example.Music", "3383539412"),
        InstanceState::Running(4242)
    );
    assert_eq!(
        state("org.example.Music", "3383539412").value(),
        json!(true)
    );
    // Another app's name, or a record that is not this instance's, is not it.
    assert_eq!(
        state("org.example.Other", "3383539412"),
        InstanceState::Gone
    );
    let _mismatched_instance_lock = sandbox(root.path(), "77", 4343, "org.example.Music", "78");
    assert_eq!(state("org.example.Music", "77"), InstanceState::Gone);
    // A PID now owned by another user is not the sandbox.
    std::fs::write(
        proc.join("4242/status"),
        format!("Uid:\t{0}\t{0}\t{0}\t{0}\n", uid + 1),
    )
    .unwrap();
    assert_eq!(
        state("org.example.Music", "3383539412"),
        InstanceState::Gone
    );
    // The process exited: the portal row is stale.
    std::fs::remove_dir_all(proc.join("4242")).unwrap();
    assert_eq!(
        state("org.example.Music", "3383539412").value(),
        json!(false)
    );
    // Starting up: locked, but bwrap has not written its info yet.
    std::fs::remove_file(run.join(".flatpak/3383539412/bwrapinfo.json")).unwrap();
    assert_eq!(
        state("org.example.Music", "3383539412").value(),
        Value::Null
    );
    // The sandbox released its lock: a stale record, whatever else remains.
    drop(lock);
    assert_eq!(
        state("org.example.Music", "3383539412"),
        InstanceState::Gone
    );
    assert_eq!(state("org.example.Music", "1"), InstanceState::Gone);
    assert_eq!(state("org.example.Music", "../77"), InstanceState::Gone);
}

#[tokio::test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
async fn portal_stop_signals_only_the_verified_sandbox_process() {
    let root = private_root();
    let (run, proc, uid) = (root.path().join("run"), root.path().join("proc"), unsafe {
        libc::getuid()
    });
    let mut child = std::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let _lock = sandbox(root.path(), "12", child.id(), "org.example.Music", "12");
    assert_eq!(
        instance_app(&run, "12").as_deref(),
        Some("org.example.Music")
    );
    assert_eq!(instance_app(&run, "../12"), None);
    struct Caller(bool);
    impl crate::Check for Caller {
        async fn check(&self) -> Result<()> {
            if self.0 {
                Ok(())
            } else {
                Err(refused("caller-session-changed"))
            }
        }
    }
    assert_eq!(
        kill_checked(&run, &proc, uid, "org.example.Music", "12", &Caller(false))
            .await
            .unwrap_err()
            .0,
        "caller-session-changed"
    );
    assert!(child.try_wait().unwrap().is_none());

    assert_eq!(
        kill_instance(&run, &proc, uid, "org.example.Other", "12")
            .unwrap_err()
            .0,
        "portal-app-instance-not-running"
    );
    assert_eq!(
        kill_checked(&run, &proc, uid, "org.example.Music", "12", &Caller(true))
            .await
            .unwrap()["state"],
        "stop-requested"
    );
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    // Exited: refused with a reason, never a generic failure.
    std::fs::remove_dir_all(proc.join(child.id().to_string())).unwrap();
    assert_eq!(
        kill_instance(&run, &proc, uid, "org.example.Music", "12")
            .unwrap_err()
            .0,
        "portal-app-instance-not-running"
    );
}

/// Writes refuse world-writable ancestors such as /tmp; stay in the checkout.
fn private_root() -> tempfile::TempDir {
    tempfile::tempdir_in(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .unwrap()
}

fn session(bin_dirs: &[&Path]) -> Session {
    Session {
        desktops: vec!["enzUI".into(), "Hyprland".into()],
        bin_dirs: bin_dirs.iter().map(|d| d.to_path_buf()).collect(),
    }
}

fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = private_root();
    let (user, system) = (root.path().join("user"), root.path().join("system"));
    std::fs::create_dir(&system).unwrap();
    (root, user, system)
}

#[test]
fn user_files_override_system_entries_by_name() {
    let (_root, user, system) = dirs();
    std::fs::create_dir(&user).unwrap();
    std::fs::write(
        system.join("a.desktop"),
        "[Desktop Entry]\nName=A\nExec=a\n",
    )
    .unwrap();
    std::fs::write(
        system.join("b.desktop"),
        "[Desktop Entry]\nName=B\nExec=b\nX-GNOME-Autostart-enabled=false\n",
    )
    .unwrap();
    std::fs::write(
        user.join("a.desktop"),
        "[Desktop Entry]\nName=A\nHidden=true\n",
    )
    .unwrap();
    std::fs::write(
        user.join("c.desktop"),
        "[Desktop Entry]\nName=C\nExec=c\nX-Flatpak=org.example.Chat\nOnlyShowIn=GNOME;KDE;\n",
    )
    .unwrap();
    std::fs::write(user.join("bad name.desktop"), "[Desktop Entry]\n").unwrap();
    let rows = autostart(&user, &system)
        .iter()
        .map(|r| autostart_value(r, &session(&[])))
        .collect::<Vec<_>>();
    let by = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap().clone();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        (
            by("a.desktop")["origin"].as_str(),
            by("a.desktop")["enabled"].as_bool()
        ),
        (Some("user-override"), Some(false))
    );
    assert_eq!(by("b.desktop")["enabled"], false);
    assert_eq!(by("c.desktop")["flatpak_app_id"], "org.example.Chat");
    assert_eq!(by("c.desktop")["only_show_in"], json!(["GNOME", "KDE"]));
    for broken in [false, true] {
        std::fs::remove_file(user.join("a.desktop")).unwrap();
        if broken {
            std::os::unix::fs::symlink(user.join("missing"), user.join("a.desktop")).unwrap();
        } else {
            std::fs::write(user.join("a.desktop"), "x".repeat(MAX_ENTRY_BYTES + 1)).unwrap();
        }
        let (rows, complete) = autostart_inventory(&user, &system);
        assert!(!complete);
        let value = autostart_value(
            rows.iter().find(|r| r.id == "a.desktop").unwrap(),
            &session(&[]),
        );
        assert_eq!(value["origin"], "user-override");
        assert_eq!(value["observable"], false);
        assert!(value["enabled"].is_null() && value["runs_here"].is_null());
    }
    for n in 0..=MAX_ENTRIES {
        std::fs::write(
            user.join(format!("over{n}.desktop")),
            "[Desktop Entry]\nExec=true\n",
        )
        .unwrap();
    }
    let (rows, complete) = autostart_inventory(&user, &system);
    assert!(!complete);
    assert_ne!(
        rows.iter().find(|r| r.id == "b.desktop").unwrap().origin,
        Origin::System
    );
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn disabling_writes_the_spec_override_and_enabling_restores_the_system_entry() {
    let (_root, user, system) = dirs();
    let uid = unsafe { libc::getuid() };
    std::fs::write(
        system.join("a.desktop"),
        "[Desktop Entry]\nName=A\nExec=a\n[Desktop Action x]\nName=X\n",
    )
    .unwrap();
    let off = set_autostart(&user, &system, uid, "a.desktop", false).unwrap();
    assert_eq!(off["changed"], true);
    let written = std::fs::read_to_string(user.join("a.desktop")).unwrap();
    assert!(
        written.contains("Hidden=true\nX-enzimOS-Autostart-Override=true\n[Desktop Action x]"),
        "{written}"
    );
    assert_eq!(
        set_autostart(&user, &system, uid, "a.desktop", false).unwrap()["changed"],
        false
    );
    set_autostart(&user, &system, uid, "a.desktop", true).unwrap();
    assert!(!user.join("a.desktop").exists());
    assert_eq!(
        set_autostart(&user, &system, uid, "../x.desktop", true)
            .unwrap_err()
            .0,
        "autostart-entry-unknown"
    );
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn re_enabling_a_stub_override_restores_the_system_entry_and_links_are_read() {
    let (_root, user, system) = dirs();
    let uid = unsafe { libc::getuid() };
    std::fs::create_dir(&user).unwrap();
    std::fs::write(
        system.join("a.desktop"),
        "[Desktop Entry]\nName=A\nExec=a\n",
    )
    .unwrap();
    // The common hand-written way to disable a system entry.
    std::fs::write(user.join("a.desktop"), "[Desktop Entry]\nHidden=true\n").unwrap();
    set_autostart(&user, &system, uid, "a.desktop", true).unwrap();
    assert!(!user.join("a.desktop").exists());
    // A desktop file linked into autostart is listed; GLib booleans 1/0 count.
    std::fs::write(
        system.join("..").join("linked.source"),
        "[Desktop Entry]\nName=L\nExec=l\nHidden=1\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        system.join("..").join("linked.source"),
        user.join("linked.desktop"),
    )
    .unwrap();
    let rows = autostart(&user, &system)
        .iter()
        .map(|r| autostart_value(r, &session(&[])))
        .collect::<Vec<_>>();
    let linked = rows.iter().find(|r| r["id"] == "linked.desktop").unwrap();
    assert_eq!(linked["enabled"], false);
    let source = system.join("..").join("linked.source");
    let prefix = "[Desktop Entry]\nName=L\nExec=l\nHidden=1\n";
    let full = format!("{prefix}{}", "#".repeat(MAX_ENTRY_BYTES - prefix.len()));
    std::fs::write(&source, &full).unwrap();
    assert!(set_autostart(&user, &system, uid, "linked.desktop", true).is_err());
    assert!(
        std::fs::symlink_metadata(user.join("linked.desktop"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read_to_string(&source).unwrap(), full);
    std::fs::write(&source, prefix).unwrap();
    set_autostart(&user, &system, uid, "linked.desktop", true).unwrap();
    assert!(
        !std::fs::symlink_metadata(user.join("linked.desktop"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read_to_string(&source).unwrap(), prefix);
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn a_users_own_entry_is_edited_in_place() {
    let (_root, user, system) = dirs();
    let uid = unsafe { libc::getuid() };
    std::fs::create_dir(&user).unwrap();
    std::fs::write(
        user.join("sync.desktop"),
        "[Desktop Entry]\nName=Sync\nExec=sync --tray\nX-GNOME-Autostart-enabled=true\n",
    )
    .unwrap();
    set_autostart(&user, &system, uid, "sync.desktop", false).unwrap();
    let text = std::fs::read_to_string(user.join("sync.desktop")).unwrap();
    assert_eq!(
        text,
        "[Desktop Entry]\nName=Sync\nExec=sync --tray\nHidden=true\n"
    );
    set_autostart(&user, &system, uid, "sync.desktop", true).unwrap();
    assert!(enabled(
        &std::fs::read_to_string(user.join("sync.desktop")).unwrap()
    ));
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn a_linked_user_entry_becomes_a_standalone_copy() {
    let (root, user, system) = dirs();
    let uid = unsafe { libc::getuid() };
    std::fs::create_dir(&user).unwrap();
    let source = root.path().join("sync.source");
    std::fs::write(&source, "[Desktop Entry]\nName=Sync\nExec=sync\n").unwrap();
    std::os::unix::fs::symlink(&source, user.join("sync.desktop")).unwrap();
    assert_eq!(
        set_autostart(&user, &system, uid, "sync.desktop", false).unwrap()["changed"],
        true
    );
    assert!(
        !std::fs::symlink_metadata(user.join("sync.desktop"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_to_string(user.join("sync.desktop")).unwrap(),
        "[Desktop Entry]\nName=Sync\nExec=sync\nHidden=true\n"
    );
    assert_eq!(
        std::fs::read_to_string(&source).unwrap(),
        "[Desktop Entry]\nName=Sync\nExec=sync\n"
    );
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn enabling_over_a_stub_copies_the_disabled_system_entry() {
    let (_root, user, system) = dirs();
    let uid = unsafe { libc::getuid() };
    std::fs::create_dir(&user).unwrap();
    std::fs::write(
        system.join("a.desktop"),
        "[Desktop Entry]\nType=Application\nExec=a\nX-GNOME-Autostart-enabled=false\n",
    )
    .unwrap();
    std::fs::write(user.join("a.desktop"), "[Desktop Entry]\nHidden=true\n").unwrap();
    set_autostart(&user, &system, uid, "a.desktop", true).unwrap();
    let text = std::fs::read_to_string(user.join("a.desktop")).unwrap();
    assert_eq!(
        text,
        "[Desktop Entry]\nType=Application\nExec=a\nHidden=false\nX-enzimOS-Autostart-Override=true\n"
    );
    // Ours now: disabling again removes it, since the system entry is off.
    set_autostart(&user, &system, uid, "a.desktop", false).unwrap();
    assert!(!user.join("a.desktop").exists());
}

#[test]
fn runs_here_applies_desktop_lists_and_try_exec() {
    use std::os::unix::fs::PermissionsExt;
    let root = private_root();
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(bin.join("tool"), "").unwrap();
    std::fs::write(bin.join("plain"), "").unwrap();
    std::fs::set_permissions(bin.join("tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let value = |text: &str| {
        let row = Autostart {
            id: "x.desktop".into(),
            origin: Origin::User,
            text: text.into(),
            system_enabled: None,
            system_text: None,
        };
        autostart_value(&row, &session(&[&bin]))
    };
    let both = |v: Value| {
        (
            v["enabled"].as_bool().unwrap(),
            v["runs_here"].as_bool().unwrap(),
            v["program_missing"].as_bool().unwrap(),
        )
    };
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nTryExec=tool\n")),
        (true, true, false)
    );
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nOnlyShowIn=GNOME;\n")),
        (true, false, false)
    );
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nOnlyShowIn=KDE;Hyprland;\n")),
        (true, true, false)
    );
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nNotShowIn=enzUI;\n")),
        (true, false, false)
    );
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nTryExec=plain\n")),
        (true, false, true)
    );
    assert_eq!(
        both(value(&format!(
            "[Desktop Entry]\nExec=x\nTryExec={}\n",
            bin.join("tool").display()
        ))),
        (true, true, false)
    );
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nTryExec=../bin/tool\n")),
        (true, false, true)
    );
    assert_eq!(
        both(value("[Desktop Entry]\nExec=x\nHidden=true\n")),
        (false, false, false)
    );
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn a_linked_autostart_directory_of_the_user_is_resolved() {
    use std::os::unix::fs::PermissionsExt;
    let home = private_root();
    let uid = unsafe { libc::getuid() };
    let (config, real) = (
        home.path().join(".config"),
        home.path().join("dotfiles/autostart"),
    );
    std::fs::create_dir_all(&config).unwrap();
    std::fs::create_dir_all(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&real, config.join("autostart")).unwrap();
    let resolved = user_autostart(home.path(), uid);
    assert_eq!(resolved, std::fs::canonicalize(&real).unwrap());
    std::fs::write(
        resolved.join("sync.desktop"),
        "[Desktop Entry]\nExec=sync\n",
    )
    .unwrap();
    set_autostart(
        &resolved,
        &home.path().join("none"),
        uid,
        "sync.desktop",
        false,
    )
    .unwrap();
    assert!(
        std::fs::read_to_string(real.join("sync.desktop"))
            .unwrap()
            .contains("Hidden=true")
    );
    // A shared target is not adopted: writes keep refusing it.
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        user_autostart(home.path(), uid),
        std::fs::canonicalize(&config).unwrap().join("autostart")
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
}
