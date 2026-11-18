// SPDX-License-Identifier: MIT
//! Review application stopping separately from future activation permissions.
use serde_json::{Value, json};
use std::{process::ExitCode, time::Duration};

const NAME: &str = "org.enzimos.Background1";
const PATH: &str = "/org/enzimos/Background1";
const USAGE: &str = "usage: enzimos-background capabilities | query
       enzimos-background review-stop|stop APP_ID [--mode graceful|finish-then-exit|cancel-and-exit|force]
       enzimos-background review-policy|set-policy APP_ID POLICY_JSON
       enzimos-background stop-portal-app FLATPAK_APP_ID INSTANCE
       enzimos-background set-autostart ENTRY.desktop on|off";

async fn call(bus: &zbus::Connection, method: &str, body: Option<Value>) -> Result<Value, String> {
    let proxy = zbus::Proxy::new(bus, NAME, PATH, NAME)
        .await
        .map_err(|_| "service unavailable".to_owned())?;
    let call = async {
        match body {
            None => proxy.call::<_, _, String>(method, &()).await,
            Some(mut body) => {
                body["schema"] = json!(1);
                proxy
                    .call::<_, _, String>(method, &(body.to_string(),))
                    .await
            }
        }
    };
    let reply = tokio::time::timeout(Duration::from_secs(35), call)
        .await
        .map_err(|_| "timed out".to_owned())?;
    match reply {
        Ok(text) => serde_json::from_str(&text).map_err(|_| "invalid reply".into()),
        Err(zbus::Error::MethodError(_, Some(message), _)) => Err(message),
        Err(_) => Err("service unavailable".into()),
    }
}

#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
async fn run(args: &[String]) -> Result<Value, String> {
    let uid = unsafe { libc::getuid() };
    let bus = zbus::connection::Builder::address(format!("unix:path=/run/user/{uid}/bus").as_str())
        .map_err(|_| "user bus unavailable".to_owned())?
        .build()
        .await
        .map_err(|_| "user bus unavailable".to_owned())?;
    match args {
        [c] if c == "capabilities" => call(&bus, "GetCapabilities", None).await,
        [c] if c == "query" => call(&bus, "Query", None).await,
        [c, app, rest @ ..] if c == "review-stop" || c == "stop" => {
            let mode = match rest {
                [] => "graceful",
                [flag, mode]
                    if flag == "--mode"
                        && ["graceful", "finish-then-exit", "cancel-and-exit", "force"]
                            .contains(&mode.as_str()) =>
                {
                    mode
                }
                _ => return Err(USAGE.into()),
            };
            let body = json!({"app_id": app, "mode": mode});
            let review = call(&bus, "ReviewStop", Some(body.clone())).await?;
            if c == "review-stop" {
                return Ok(review);
            }
            let mut commit = body;
            commit["plan_sha256"] = review["plan_sha256"].clone();
            commit["valid_for_ms"] = json!(30000);
            call(&bus, "Stop", Some(commit)).await
        }
        [c, app, policy] if c == "review-policy" || c == "set-policy" => {
            let policy: Value =
                serde_json::from_str(policy).map_err(|_| "invalid-policy-json".to_owned())?;
            let body = json!({"app_id": app, "policy": policy});
            let review = call(&bus, "ReviewPolicy", Some(body.clone())).await?;
            if c == "review-policy" {
                return Ok(review);
            }
            let mut commit = body;
            commit["plan_sha256"] = review["plan_sha256"].clone();
            commit["valid_for_ms"] = json!(30000);
            call(&bus, "SetPolicy", Some(commit)).await
        }
        [c, app, instance] if c == "stop-portal-app" => {
            call(
                &bus,
                "StopPortalApp",
                Some(json!({"app_id": app, "instance": instance})),
            )
            .await
        }
        [c, id, state] if c == "set-autostart" && (state == "on" || state == "off") => {
            call(
                &bus,
                "SetAutostart",
                Some(json!({"id": id, "enabled": state == "on"})),
            )
            .await
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    match runtime.block_on(run(&args)) {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(message) if message.starts_with("usage:") => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
        Err(message) => {
            eprintln!("Background operation refused: {message}");
            ExitCode::FAILURE
        }
    }
}
