# Lifecycle caller descriptor, schema 1

An application serving `org.enzui.ApplicationLifecycle1` (formerly
`org.enzimos.ApplicationLifecycle1`) answers `QueryStop` and `Stop` only for a
caller the installed OS has declared. The OS declares each allowed caller in a
root-owned descriptor file; the framework reads them and keeps no built-in
caller. This document is the contract between the OS (writer) and the enzUI
framework (reader).

enzimOS ships one descriptor, from this package:
`/usr/share/enzui/lifecycle-callers/org.enzimos.Background1.json`
(source: [`packaging/org.enzimos.Background1.json`](../packaging/org.enzimos.Background1.json)).

```json
{
  "schema": 1,
  "executable": "/usr/lib/enzimos-background/enzimos-background-service",
  "bus_name": "org.enzimos.Background1",
  "unit": "enzimos-background-apps.service",
  "witness": {
    "bus": "org.enzimos.System1",
    "path": "/org/enzimos/System1",
    "interface": "org.enzimos.System1",
    "method": "InspectBackgroundBroker",
    "schema": 1
  }
}
```

## Location and file checks

- Directory: `/usr/share/enzui/lifecycle-callers/`. It and every ancestor must
  be a real directory (not a symlink), protected-owned and not group or world
  writable (`mode & 0o022 == 0`).
- Files: only names ending in `.json` are considered, in byte order; other
  names are ignored. The name must be exactly `<bus_name>.json`.
- Each file is opened with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and checked
  on the open descriptor: a regular file, protected-owned, not group or world
  writable, one link, 1 to 4096 bytes. The file is read through that descriptor
  only, at most 4096 bytes.
- "Protected-owned" means uid 0, judged as admission already judges installed
  files: inside a user namespace an owner shown as the unmapped overflow uid
  counts, under the same `OwnerView` rule. A file owned by the calling user is
  never valid.
- At most 32 `.json` entries. More than that is treated as a tampered directory
  and refuses every caller.

## Fields

The body is one UTF-8 JSON object. Unknown fields, at the top level or in
`witness`, make the descriptor invalid. Duplicate keys make it invalid.

| Field | Type | Rule |
|---|---|---|
| `schema` | integer | Exactly `1`. Any other value: descriptor ignored (not an error for other descriptors). |
| `executable` | string | Absolute, normalized path (starts with `/`, no empty, `.` or `..` components), at most 4096 bytes. At call time it must pass the existing installed-identity check (root-owned regular file, protected ancestors), and the caller's `/proc/PID/exe` must have its device and inode. |
| `bus_name` | string | D-Bus well-known name: at most 255 bytes, two or more `.`-separated elements, each non-empty, made of `[A-Za-z0-9_-]` and not starting with a digit; never a unique name (`:`). Must equal the file name without `.json`. |
| `unit` | string | systemd user unit name: at most 255 bytes, `[A-Za-z0-9:_.@\-]`, ends in `.service`, not a bare template (`…@.service`), no `/`. |
| `witness` | object, optional | See below. |

`witness` describes the OS observation admission asks for when the app runs
inside a user namespace (where root ownership cannot be seen directly). All
five fields are required when the object is present:

| Field | Type | Rule |
|---|---|---|
| `bus` | string | Well-known name on the **system** bus (same syntax as `bus_name`). |
| `path` | string | D-Bus object path syntax. |
| `interface` | string | D-Bus interface name syntax (as `bus_name`, no `-`). |
| `method` | string | D-Bus member name: `[A-Za-z_][A-Za-z0-9_]*`, at most 255 bytes. |
| `schema` | integer | Request/response schema. Only `1` is defined; any other value makes the descriptor invalid. |

## Witness call, schema 1

This is the contract `witness.rs` implements today, with its constants taken
from the descriptor instead:

- Call `witness.method` on `witness.interface` at `witness.path`, destination
  `witness.bus`, on the system bus, with one string argument
  `{"schema":1}`. The reply is one string holding a JSON object.
- The reply's sender must be the current owner of `witness.bus`, and the bus
  daemon must report that connection as uid 0.
- The object must have: `schema` = 1; `uid`, `pid`, `start_ticks` equal to
  the caller facts admission authenticated on the user bus; `user_bus_name`
  equal to the caller's unique name; `boot_id` equal to
  `/proc/sys/kernel/random/boot_id`; `unit` equal to the descriptor's `unit`;
  `initial_namespace_root_owned` = `true`; `observation_only` = `true`;
  `control_group`, `unit_sha256`, `executable_sha256` non-empty strings.
- Any missing service, error, timeout or mismatch refuses. The witness is asked
  again on every call; it is an observation, never a grant.

If admission needs a witness (a user namespace) and the matching descriptor has
no `witness`, that descriptor does not admit.

## Semantics

- Read the directory on every admission check, inside the existing
  `ADMISSION_DEADLINE`, so installing, updating or removing a package takes
  effect on the next call without restarting apps. Caching is allowed only
  if keyed on the directory and file identity (device, inode, size, mtime,
  ctime) and revalidated on every call.
- Each valid descriptor is one `CallerPolicy { executable, bus_name, unit }`
  plus its optional witness. The existing checks run unchanged against it:
  same uid, name ownership, unit cgroup, unit main PID, root-controlled unit
  file and drop-ins, installed executable identity, witness when needed,
  start-time stability.
- The caller is admitted when **any** valid descriptor admits it. Since a bus
  connection owns a given well-known name at most once, a reader should first
  select the descriptors whose `bus_name` the sender owns, then run the rest of
  the checks on those.
- An invalid descriptor admits nobody and does not affect other descriptors.
- A missing directory, no valid descriptor, or too many entries refuses every
  caller. There is no built-in fallback caller.
- The test-only `OwnExecutable` admission is unaffected.

## Diagnostics

Refusals stay `org.freedesktop.DBus.Error.AccessDenied` with a fixed text, so
the OS can turn exact texts into public codes
(`application-lifecycle-admission-<check>`). The OS accepts the existing
prefix `not the OS background-apps service: ` and the neutral prefix
`not an admitted lifecycle caller: `, followed by one of the existing check
texts in `admission.rs`. A new refusal for "no valid descriptor" may use any
fixed text; the OS reports unrecognised texts as
`application-lifecycle-unavailable`. Never include paths or descriptor content.

## Migration

The OS ships this descriptor before the framework reads it, and Background1
asks `org.enzui.ApplicationLifecycle1` first, falling back to
`org.enzimos.ApplicationLifecycle1` only on `UnknownInterface` or
`UnknownMethod`. Apps built before and after the rename both work.
