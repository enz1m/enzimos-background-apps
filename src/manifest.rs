// SPDX-License-Identifier: MIT
//! Bounded installed declarations for application units, excluding infrastructure.
use crate::{Result, refused};
use enzimos_platform::json::{DecodeFailure, decode_classified};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const SOURCES: [&str; 6] = [
    "user",
    "autostart",
    "agent",
    "scheduled",
    "ongoing-work",
    "search",
];
pub const MAX_BYTES: usize = 16384;
const INFRASTRUCTURE: [&str; 10] = [
    "dev.enzui.Desktop",
    "dev.enzui.Compositor",
    "org.enzimos.Background",
    "org.enzimos.Activity",
    "org.enzui.McpCenter",
    "org.enzui.Desktop",
    "org.enzui.Shell",
    "org.enzui.Compositor",
    "org.enzimos.Background1",
    "org.enzimos.Activity1",
];
const FIELDS: [&str; 9] = [
    "schema",
    "app_id",
    "title",
    "unit",
    "executable",
    "purpose",
    "activation_sources",
    "autostart_supported",
    "graceful_stop",
];
pub const GRACEFUL: &str = "application-lifecycle-v1";

fn label(part: &str) -> bool {
    let b = part.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphabetic()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

/// Reverse-DNS application identity: two to eight labels, at most 127 bytes.
pub fn app_id(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    value.len() <= 127 && (2..=8).contains(&parts.len()) && parts.iter().all(|p| label(p))
}

/// Non-empty printable text of at most `limit` characters.
pub fn text(value: &str, limit: usize) -> bool {
    let count = value.chars().count();
    (1..=limit).contains(&count) && value.chars().all(|c| c >= ' ' && c != '\x7f')
}

/// Absolute, already-normalized path (no empty, `.` or `..` components).
pub fn normal_path(path: &str) -> bool {
    path.strip_prefix('/').is_some_and(|rest| {
        rest.split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub app_id: String,
    pub title: String,
    pub unit: String,
    pub executable: String,
    pub purpose: String,
    pub activation_sources: Vec<String>,
    pub autostart_supported: bool,
    pub graceful_stop: String,
}

impl Manifest {
    pub fn value(&self) -> Value {
        json!({"schema": 1, "app_id": self.app_id, "title": self.title, "unit": self.unit,
               "executable": self.executable, "purpose": self.purpose,
               "activation_sources": self.activation_sources,
               "autostart_supported": self.autostart_supported, "graceful_stop": self.graceful_stop})
    }
    pub fn graceful(&self) -> bool {
        self.graceful_stop == GRACEFUL
    }
}

pub fn decode(data: &[u8], filename: &str) -> Result<Manifest> {
    if data.is_empty() || data.len() > MAX_BYTES {
        return Err(refused("manifest-bound"));
    }
    let value = decode_classified(data, MAX_BYTES).map_err(|e| match e {
        DecodeFailure::Duplicate => refused("manifest-duplicate-field"),
        _ => refused("manifest-invalid"),
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| refused("manifest-fields"))?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let mut expected = FIELDS.into_iter().collect::<BTreeSet<_>>();
    if !keys.contains("graceful_stop") {
        expected.remove("graceful_stop");
    }
    if keys != expected || !object["schema"].is_u64() || object["schema"] != 1 {
        return Err(refused("manifest-fields"));
    }
    let string = |key: &str| object[key].as_str().unwrap_or("").to_owned();
    let identifier = string("app_id");
    if !object["app_id"].is_string()
        || !app_id(&identifier)
        || INFRASTRUCTURE.contains(&identifier.as_str())
        || filename != format!("{identifier}.json")
    {
        return Err(refused("manifest-app-identity"));
    }
    let unit = string("unit");
    if unit != format!("enzui-agent-{identifier}.service")
        && unit != format!("enzui-background-{identifier}.service")
    {
        return Err(refused("manifest-unit-identity"));
    }
    let path = string("executable");
    if !text(&path, 256)
        || !["/usr/bin/", "/usr/lib/enzui/apps/", "/usr/lib/enzui/bin/"]
            .iter()
            .any(|p| path.starts_with(p))
        || !normal_path(&path)
    {
        return Err(refused("manifest-native-executable"));
    }
    let (title, purpose) = (string("title"), string("purpose"));
    if !text(&title, 160) || !text(&purpose, 160) {
        return Err(refused("manifest-label"));
    }
    let sources = object["activation_sources"]
        .as_array()
        .filter(|s| (1..=SOURCES.len()).contains(&s.len()))
        .and_then(|s| {
            s.iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .filter(|s| {
            s.iter().all(|v| SOURCES.contains(&v.as_str()))
                && s.iter().collect::<BTreeSet<_>>().len() == s.len()
        })
        .ok_or_else(|| refused("manifest-activation-sources"))?;
    let autostart = object["autostart_supported"]
        .as_bool()
        .filter(|v| *v == sources.iter().any(|s| s == "autostart"))
        .ok_or_else(|| refused("manifest-autostart-capability"))?;
    let graceful_stop = object
        .get("graceful_stop")
        .map_or(Some("unavailable"), Value::as_str)
        .filter(|v| [GRACEFUL, "unavailable"].contains(v))
        .ok_or_else(|| refused("manifest-graceful-stop-capability"))?
        .to_owned();
    Ok(Manifest {
        app_id: identifier,
        title,
        unit,
        executable: path,
        purpose,
        activation_sources: sources,
        autostart_supported: autostart,
        graceful_stop,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample(id: &str) -> Value {
        json!({"schema": 1, "app_id": id, "title": "Music", "unit": format!("enzui-agent-{id}.service"),
               "executable": "/usr/bin/music", "purpose": "Plays music",
               "activation_sources": ["user", "agent", "autostart"], "autostart_supported": true})
    }
    fn code(value: Value, name: &str) -> String {
        decode(value.to_string().as_bytes(), name).unwrap_err().0
    }

    #[test]
    fn producer_optional_graceful_stop_defaults_to_unavailable() {
        let m = decode(
            sample("org.example.Music").to_string().as_bytes(),
            "org.example.Music.json",
        )
        .unwrap();
        assert_eq!(m.graceful_stop, "unavailable");
        assert!(!m.graceful());
        let mut v = sample("org.example.Music");
        v["graceful_stop"] = json!(GRACEFUL);
        assert!(
            decode(v.to_string().as_bytes(), "org.example.Music.json")
                .unwrap()
                .graceful()
        );
        v["graceful_stop"] = json!("sometimes");
        assert_eq!(
            code(v, "org.example.Music.json"),
            "manifest-graceful-stop-capability"
        );
    }

    #[test]
    fn infrastructure_unit_paths_duplicates_and_labels_refused() {
        let name = "org.example.Music.json";
        assert_eq!(
            code(sample("org.enzui.Shell"), "org.enzui.Shell.json"),
            "manifest-app-identity"
        );
        assert_eq!(
            code(sample("org.example.Music"), "other.json"),
            "manifest-app-identity"
        );
        let mut v = sample("org.example.Music");
        v["unit"] = json!("dbus.service");
        assert_eq!(code(v, name), "manifest-unit-identity");
        for path in [
            "/usr/bin/../bin/sh",
            "/opt/music",
            "/usr/bin//music",
            "/usr/bin/music/",
        ] {
            let mut v = sample("org.example.Music");
            v["executable"] = json!(path);
            assert_eq!(code(v, name), "manifest-native-executable", "{path}");
        }
        let mut v = sample("org.example.Music");
        v["title"] = json!("bad\nlabel");
        assert_eq!(code(v, name), "manifest-label");
        let mut v = sample("org.example.Music");
        v["activation_sources"] = json!(["user", "user"]);
        assert_eq!(code(v, name), "manifest-activation-sources");
        let mut v = sample("org.example.Music");
        v["autostart_supported"] = json!(false);
        assert_eq!(code(v, name), "manifest-autostart-capability");
        let mut v = sample("org.example.Music");
        v["schema"] = json!(true);
        assert_eq!(code(v, name), "manifest-fields");
        let duplicate = br#"{"schema":1,"schema":1}"#;
        assert_eq!(
            decode(duplicate, name).unwrap_err().0,
            "manifest-duplicate-field"
        );
        assert_eq!(decode(b"", name).unwrap_err().0, "manifest-bound");
    }

    #[test]
    fn identities_are_bounded_reverse_dns() {
        assert!(app_id("org.example.Music"));
        assert!(!app_id("Music"));
        assert!(!app_id("org.1example.Music"));
        assert!(!app_id("a.b.c.d.e.f.g.h.i"));
        assert!(text("Plays", 160) && !text("", 160) && !text("a\u{7f}", 160));
    }
}
