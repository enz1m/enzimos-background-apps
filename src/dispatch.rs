// SPDX-License-Identifier: MIT
//! Bounded user-bus requests with fresh caller, session and review checks.
use crate::{
    Check, Result,
    authority::{Authority, Peer},
    manifest::app_id,
    refused,
};
use enzimos_platform::json::{DecodeFailure, decode_classified};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, time::Instant};

pub fn sender(value: &str) -> bool {
    value
        .strip_prefix(':')
        .and_then(|r| r.split_once('.'))
        .is_some_and(|(a, b)| {
            [a, b]
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
        })
}

pub fn decode(body: &str, fields: &[&str]) -> Result<Map<String, Value>> {
    if body.len() > 32768 {
        return Err(refused("request-bound"));
    }
    let value = decode_classified(body.as_bytes(), 32768).map_err(|e| match e {
        DecodeFailure::Duplicate => refused("request-duplicate"),
        DecodeFailure::Bound => refused("request-bound"),
        DecodeFailure::Malformed => refused("request-invalid"),
    })?;
    let Value::Object(object) = value else {
        return Err(refused("request-fields"));
    };
    let expected = fields
        .iter()
        .copied()
        .chain(["schema"])
        .collect::<BTreeSet<_>>();
    if !object
        .keys()
        .map(String::as_str)
        .eq(expected.iter().copied())
        || !object["schema"].is_u64()
        || object["schema"] != 1
    {
        return Err(refused("request-fields"));
    }
    if fields.contains(&"app_id") && !object["app_id"].as_str().is_some_and(app_id) {
        return Err(refused("request-app-identity"));
    }
    Ok(object)
}

/// A reviewed commit: its own fields plus a plan digest and a 1–30 s deadline.
pub fn commit_request(body: &str, field: &str) -> Result<(Map<String, Value>, String, u64)> {
    let request = decode(body, &["app_id", field, "plan_sha256", "valid_for_ms"])?;
    let valid = request["valid_for_ms"]
        .as_u64()
        .filter(|v| (1000..=30000).contains(v) && request["valid_for_ms"].is_u64());
    let digest = request["plan_sha256"].as_str().filter(|d| {
        d.len() == 64
            && d.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    });
    match (valid, digest) {
        (Some(valid), Some(digest)) => {
            let digest = digest.to_owned();
            Ok((request, digest, valid))
        }
        _ => Err(refused("request-review-or-deadline")),
    }
}

pub async fn trusted_peer(authority: &Authority, sender_name: &str) -> Result<Peer> {
    if !sender(sender_name) {
        return Err(refused("unique-user-bus-sender-required"));
    }
    let peer = authority.peer(sender_name).await?;
    if !peer.trusted_control_client {
        return Err(refused("active-trusted-local-client-required"));
    }
    Ok(peer)
}

/// Before each commit step: inside the reviewed deadline, same caller and session.
pub struct Guard<'a> {
    pub authority: &'a Authority,
    pub sender: String,
    pub peer: Peer,
    pub deadline: Instant,
}

impl Check for Guard<'_> {
    async fn check(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(refused("request-expired"));
        }
        if trusted_peer(self.authority, &self.sender).await? != self.peer {
            return Err(refused("caller-session-changed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_sender_only() {
        assert!(sender(":1.42"));
        for bad in ["org.example.App", ":1", ":1.x", "1.2", ":.2"] {
            assert!(!sender(bad), "{bad}");
        }
    }

    #[test]
    fn duplicate_nonfinite_and_large_requests_refused() {
        let ok = r#"{"schema":1,"app_id":"org.example.Music","mode":"force"}"#;
        assert!(decode(ok, &["app_id", "mode"]).is_ok());
        let dup = r#"{"schema":1,"schema":1,"app_id":"org.example.Music","mode":"force"}"#;
        assert_eq!(
            decode(dup, &["app_id", "mode"]).unwrap_err().0,
            "request-duplicate"
        );
        let nan = r#"{"schema":1,"app_id":"org.example.Music","mode":NaN}"#;
        assert_eq!(
            decode(nan, &["app_id", "mode"]).unwrap_err().0,
            "request-invalid"
        );
        let big = format!(
            r#"{{"schema":1,"app_id":"org.example.Music","mode":"{}"}}"#,
            "x".repeat(40000)
        );
        assert_eq!(
            decode(&big, &["app_id", "mode"]).unwrap_err().0,
            "request-bound"
        );
        let extra = r#"{"schema":1,"app_id":"org.example.Music","mode":"force","x":1}"#;
        assert_eq!(
            decode(extra, &["app_id", "mode"]).unwrap_err().0,
            "request-fields"
        );
        let app = r#"{"schema":1,"app_id":"../etc","mode":"force"}"#;
        assert_eq!(
            decode(app, &["app_id", "mode"]).unwrap_err().0,
            "request-app-identity"
        );
    }

    #[test]
    fn commit_needs_digest_and_bounded_deadline() {
        let body = |ms: &str, digest: &str| {
            format!(
                r#"{{"schema":1,"app_id":"org.example.Music","mode":"force","plan_sha256":"{digest}","valid_for_ms":{ms}}}"#
            )
        };
        let digest = "a".repeat(64);
        assert!(commit_request(&body("30000", &digest), "mode").is_ok());
        for (ms, d) in [
            ("999", digest.as_str()),
            ("30001", &digest),
            ("5000.5", &digest),
            ("5000", "ABC"),
        ] {
            assert_eq!(
                commit_request(&body(ms, d), "mode").unwrap_err().0,
                "request-review-or-deadline"
            );
        }
    }
}
