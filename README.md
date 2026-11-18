# enzimOS background applications

On-demand policy and inventory for registered background applications, in Rust.
Window presence, active work, activation sources and stopping consequences
remain separate facts. Infrastructure services are never application stop
targets.

## Binaries

- `enzimos-background-service`: the D-Bus activated user service
  `org.enzimos.Background1` (`/usr/lib/enzimos-background/`). It takes no
  arguments and exits after 60 seconds idle. Inventory updates follow desktop and system events.
- `enzimos-background-trust`: a root boot step that records the initial mount
  namespace and boot ID in `/run/enzimos-background-trust/namespace.json`. The
  user service refuses to start in any other namespace.
- `enzimos-background`: the command-line client (`capabilities`, `query`,
  `review-stop`, `stop`, `review-policy`, `set-policy`).

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked
cargo fmt --check
```

Requires Linux and Rust 1.95 or newer. Shared platform/backend dependencies are
pinned to an immutable source revision. Tests use temporary files, owned processes
and private bus fixtures. Installed systemd/logind/lifecycle integration must be
tested in a disposable guest, never against unrelated host applications.

`packaging/` supplies the session service, trust bootstrap unit, activation and
lifecycle descriptor. Building does not install or enable them.

## Inventory

Installed declarations live in `/usr/share/enzui/background-apps/<app_id>.json`
and the compatibility directory `/usr/share/enzimos/background-apps/`
(root-owned, at most 128 in total). Both directories pass the same checks. The
neutral directory takes precedence: when it holds `<app_id>.json`, valid or not,
the legacy file for that app is ignored. An unsafe directory makes the whole
inventory unknown. Both directories and their parents are watched. Each names one `enzui-agent-` or
`enzui-background-` user unit and a native executable. A running app is
controllable only when its unit is installed (not transient), its main process
runs as the user with the declared executable's exact inode and timestamps, and
it sits in the unit's own cgroup.

The inventory is cached and invalidated by systemd events for the declared
units and app scopes of registered apps, Flatpak instance scopes, unit-file
changes, bus name changes, the shell's window feed, the portal's background
list and inotify on the declaration and preference directories. Units loaded
or garbage-collected for any other reason are ignored. After each burst the
service re-reads the inventory and emits `Changed(t)` only if the snapshot
differs: `generation` counts distinct snapshots, so a reader's own
`GetCapabilities`/`Query` after `Changed` never causes another one.

Reads never load units: a unit systemd has not loaded is reported inactive
with its unit-file state (`GetUnit`, `GetUnitFileState`). Only commits load
the declared unit, to verify its fragment and drop-ins. The MCP broker unit
behind `agent_policy_adapter` is loaded at most once per unit-file change while
it is not otherwise loaded.

## Callers

Every method except `GetCapabilities` requires a same-user caller in the user's
active, unlocked, local graphical logind session. The caller, or one of its
ancestors, must be an installed control client: Terminal, Settings or the shell.
Flatpak callers are refused. `ActivateForSearch` accepts only the installed
shell process itself.

Commits repeat the review: `Stop`/`SetPolicy` take the reviewed `plan_sha256` and
a 1–30 second deadline. The service re-observes the app, recomputes the plan, and
rechecks the caller and deadline immediately before changing anything.

## Reviewed graceful shutdown

`ReviewStop` and `Stop` accept `finish-then-exit` or `cancel-and-exit`. The older
`graceful` spelling selects finish-then-exit. `force` is a separate explicit
action and kills only a unit with `Restart=no` and `KillMode=control-group`,
through a pidfd. Graceful failure never escalates to force, and changing
activation policy never stops work.

The service calls `org.enzui.ApplicationLifecycle1` only for a manifest
declaring `application-lifecycle-v1`, on the app's verified unique bus owner.
An app that answers `UnknownInterface` or `UnknownMethod` is asked again on the
deprecated `org.enzimos.ApplicationLifecycle1`; `Stop` goes to whichever
interface answered the fresh `QueryStop`. The package installs
`/usr/share/enzui/lifecycle-callers/org.enzimos.Background1.json`, which tells
the framework to admit this service; see
[lifecycle caller descriptor](docs/LIFECYCLE_CALLER_DESCRIPTOR.md).
Consequence detail is display-only; the revision and consequence kinds/titles
bind the review. Exact framework admission refusals become
`application-lifecycle-admission-<check>` codes. Other peer text, paths and
credentials never become public codes.

## Window observation

The shell adapter implements `dev.enzui.Shell.Windows1`: at most 256 rows, an
installed root-owned shell binary as the bus owner, matched unit/PID/start ticks.
Minimized windows remain windows; missing or replaced observations stay unknown.

## Standard desktop sources

Besides registered native units, `Query` reports what every Linux desktop
already exposes, so apps that know nothing about enzimOS are still visible:

- `flatpak_background`: the xdg-desktop-portal background monitor
  (`org.freedesktop.background.Monitor.BackgroundApps`, the list GNOME Shell
  shows), with the portal's per-app status message. `null` means the portal
  did not answer. The portal's list can briefly outlive an exited app, so each
  row carries `instance_running`, checked against the instance itself:
  `true` when `$XDG_RUNTIME_DIR/.flatpak/INSTANCE/.ref` is still locked by the
  sandbox and the `child-pid` in its `bwrapinfo.json` runs as the user with a
  `/.flatpak-info` naming the same app and `instance-id`; `false` when the
  record is gone or unlocked or that process exited or is something else;
  `null` when it cannot be observed (starting up, unreadable). Nothing is
  matched or scanned by name.
  `StopPortalApp {app_id, instance}` re-reads the list, checks the instance's
  own Flatpak record names the same app, verifies the sandbox process as
  above, pins it with a pidfd, verifies it again and sends it `SIGKILL`, as
  `flatpak kill INSTANCE` does. Refusals: `portal-app-not-running-in-background`,
  `portal-app-identity-changed`, `portal-app-instance-not-running`,
  `portal-app-instance-unobservable`, `portal-app-stop-failed-errno-N`.
- `autostart`: XDG Autostart entries (`~/.config/autostart` over
  `/etc/xdg/autostart`, user files replace system files by name).
  `SetAutostart {id, enabled}` uses the spec's own mechanism: `Hidden=true`
  in the user's file, or for a system entry a user override marked
  `X-enzimOS-Autostart-Override=true`, removed again on re-enable.

The shell's portal backend (`org.freedesktop.impl.portal.Background`) answers
the portal's window and consent questions; this service only reads the result.

## Activation policy

Per-user preferences live in `~/.local/state/enzimos/background-apps/policy.json`
(private directory, 0600). Agent activation changes need the MCP broker's policy
ABI 2 descriptor and a current or idle broker unit. `scheduled` and
`ongoing-work` are recognized but cannot be changed yet. An autostart change
writes a journal first; a lost systemd reply leaves an `uncertain` record that
needs a fresh review, and it is never replayed. Each committed `SetPolicy`
emits `PolicyChanged(s app_id)`.

## Search activation

`ActivateForSearch(s app_id) → (b started, s reason)` starts an installed
native search provider's fixed unit once for the shell's Search, behind its
verified Root-installed provider, desktop and D-Bus service declarations and
the separate `search` source (default off), and waits up to 1 s for its bus
name. Revoking `search` stops only an idle, windowless instance the broker
started for search. Default builds leave the adapter disabled. See
[search activation](docs/SEARCH_ACTIVATION.md) for the build option and runtime
requirements.

## License

MIT; see [LICENSE](LICENSE).
