// SPDX-License-Identifier: MIT
//! D-Bus activated user service; arguments are never accepted.
#[allow(
    unsafe_code,
    reason = "Sanitizes the environment before starting runtime threads."
)]
fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 {
        return std::process::ExitCode::from(2);
    }
    // SAFETY: startup has not created runtime threads or shared native environment borrows.
    let address = match unsafe { enzimos_background_apps::service::runtime_guard() } {
        Ok(address) => address,
        Err(error) => {
            eprintln!("background service refused: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return std::process::ExitCode::from(2),
    };
    match runtime.block_on(enzimos_background_apps::service::serve(address)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("background service stopped: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
