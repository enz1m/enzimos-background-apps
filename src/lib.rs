// SPDX-License-Identifier: MIT
//! On-demand policy and inventory for registered background applications.
//! Window presence, active work, activation sources and stopping consequences
//! remain separate facts; infrastructure services are never stop targets.
pub mod agent_policy;
pub mod authority;
pub mod dispatch;
pub mod lifecycle;
pub mod manifest;
pub mod model;
pub mod preferences;
pub mod process_identity;
pub mod provider;
pub mod registry;
pub mod runtime_trust;
pub mod search;
pub mod service;
pub mod standard;
pub mod window_observation;

pub use enzimos_platform::{Error, Result, require};
use std::{future::Future, time::Duration};

/// A fixed public refusal code; peer text and paths never become codes.
pub fn refused(code: &str) -> Error {
    Error(code.into())
}

/// Bound a D-Bus round trip; any failure or timeout becomes `code`.
pub async fn bounded<T, E, F: Future<Output = std::result::Result<T, E>>>(
    future: F,
    seconds: u64,
    code: &str,
) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| refused(code))?
        .map_err(|_| refused(code))
}

/// Checked before each commit step: the caller is unchanged and inside its deadline.
pub trait Check {
    fn check(&self) -> impl Future<Output = Result<()>> + Send;
}
