// SPDX-License-Identifier: MIT
//! Root boot step recording the initial mount namespace for user services.
fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 {
        return std::process::ExitCode::from(2);
    }
    match enzimos_background_apps::runtime_trust::prepare() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("background runtime trust: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
