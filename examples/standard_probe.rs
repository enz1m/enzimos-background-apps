// SPDX-License-Identifier: MIT
//! Print the standard background sources this session exposes (manual check).
#[tokio::main(flavor = "current_thread")]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
async fn main() {
    use enzimos_background_apps::standard;
    let bus = zbus::Connection::session().await.expect("session bus");
    let home = std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let apps = standard::portal_apps(&bus).await;
    println!("portal: {apps:?}");
    let runtime = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
    for app in apps.iter().flatten() {
        let running = standard::instance_state(
            &runtime,
            std::path::Path::new("/proc"),
            unsafe { libc::getuid() },
            &app.app_id,
            &app.instance,
        );
        println!(
            "instance {}: record {:?}, {running:?}",
            app.instance,
            standard::instance_app(&runtime, &app.instance)
        );
    }
    let (uid, session) = (unsafe { libc::getuid() }, standard::Session::current(&home));
    for row in standard::autostart(
        &standard::user_autostart(&home, uid),
        std::path::Path::new(standard::SYSTEM_AUTOSTART),
    )
    .iter()
    .take(40)
    {
        println!("{}", standard::autostart_value(row, &session));
    }
}
