# Application-search activation

The adapter is disabled by default. With it disabled, `ActivateForSearch`
returns `search-policy-adapter-unavailable`, policy writes for the `search`
source return `activation-source-adapter-unavailable`, and capabilities report
`search_policy_adapter: false`. To build a package for installed integration
checks, set `ENZIMOS_SEARCH_ADAPTER_QUALIFIED=1` while compiling.

## Policy source

Installed native manifests may declare `search` in `activation_sources`,
separately from `user`, `agent`, `autostart`, `scheduled` and `ongoing-work`.
Its default is **false**. A newly declared source never re-grants an earlier
denial of another source, and a saved `search: false` is a denial.

With the gate on, `search` is changed through the existing reviewed
`ReviewPolicy`/`SetPolicy` pair. Writing any policy row containing `search`
still needs the matched MCP policy reader (ABI 2 descriptor and a current or
idle `enzui-center.service`); otherwise `background-policy-schema-adapter-unavailable`.
`GetCapabilities.search_policy_adapter` is true only when the gate is on **and**
that reader is present, since the source cannot be enabled without it. The MCP
reader ignores `search` when deciding agent activation: the two sources are
independent.

Every committed `SetPolicy` emits `PolicyChanged(s app_id)` on
`/org/enzimos/Background1` (besides `Changed(t)` for the inventory). The shell
re-reads the policy and drops a provider whose `search` source was revoked.

## `ActivateForSearch(s app_id) → (b started, s reason)`

Only the installed shell process itself (`/usr/lib/enzui/bin/enzui-shell`,
same user, active local graphical session, not Flatpak) may call it; a
process merely launched from a control client is refused with
`search-caller-not-shell`. Calls are serialized. In order:

1. Gate on, app id well formed, app in the admitted native catalogue
   (`installed-application-unavailable` otherwise, which covers Flatpak and
   any app of unknown provenance).
2. Declarations verified (below), including no user, `/usr/local` or Flatpak
   override.
3. Saved policy has `search: true` (`search-activation-disabled`), and no
   policy commit for the app is waiting for review
   (`background-policy-outcome-needs-review`).
4. The manifest's unit is observed without loading it. Running with a
   verified main process → `(true, "already-running")`, nothing started.
   Running but unverified → `search-running-instance-unverified`;
   `deactivating` → `search-unit-busy`.
5. If the bus name already has an owner while the unit is not running, the
   broker does not start a second instance: `search-bus-name-owned-outside-unit`.
6. The unit is loaded and its fragment and drop-ins must be Root-owned under
   `/usr/lib/systemd/user` or `/etc/systemd/user` (no user units or drop-ins).
7. The origin record is written as pending, then `StartUnit(unit, "fail")` is
   sent **once**. Failure → `search-unit-start-failed` (record removed).
8. Without holding the provider lock, the broker waits up to
   `START_DEADLINE` (1 s) for `NameOwnerChanged` on the app's name (it
   subscribes first, then asks `NameHasOwner`; it never starts a name
   through the bus).
9. Owned: the unit's main process must be verified (installed executable
   inode, own cgroup, same user) and be the name's owner, else
   `search-started-instance-unverified` / `search-bus-owner-mismatch`. The
   origin record is bound to the unit's invocation ID → `(true, "started")`.
   Not owned in time → `(false, "search-activation-timeout")`; no retry, and
   the started invocation stays recorded so a revocation can still find it.
   A unit that never owns its name is left to exit on its own.

All refusals are `(false, code)` with fixed lowercase codes; nothing from a
peer, path or file crosses the bus.

### Declarations

`search::verify` checks, for an admitted catalogue entry declaring `search`:

- `/usr/share/enzui/search-providers/<app_id>.ini`: `[enzUI Search Provider]`,
  `Version=1`, `DesktopId=<app_id>.desktop`, `BusName=<app_id>`, a valid
  object path and `MinQueryLength` 1–256 (default 2);
- `/usr/share/applications/<app_id>.desktop`: `Type=Application`,
  `DBusActivatable=true`, not `Hidden`/`NoDisplay`, `Exec` program equal to
  the manifest executable;
- `/usr/share/dbus-1/services/<app_id>.service`: `Name=<app_id>`,
  `SystemdService=` the manifest unit, `Exec` program equal to the manifest
  executable.

Each file is at most 4 KiB, a regular single-link file owned by Root, not
group/other writable, under protected parents, parsed strictly (no duplicate
keys or sections, no keys before a section, no continuation lines, no
`[DEFAULT]`, no control characters). The executable's device, inode, size and
timestamps are re-read and must equal the admitted identity. The same file
name under `~/.local/share`, `/usr/local/share`,
`~/.local/share/flatpak/exports/share` or `/var/lib/flatpak/exports/share`
refuses the proof (`search-declaration-overridden`). The framework's
`installed::dbus_service`, `search_provider_ini` and desktop entry produce
exactly these files.

### Origin record (what the app can read)

`$XDG_RUNTIME_DIR/enzimos/search-activation/<app_id>.json` (directory 0700,
file 0600, same user):

```json
{"schema": 1, "origin": "search", "app_id": "…", "unit": "enzui-agent-….service",
 "invocation_id": null | "<32 hex>", "requested_realtime_us": 1760000000000000}
```

An app started with `--agent-background` may treat its start as a search
start when `invocation_id` equals its `$INVOCATION_ID`, or is `null` and
`requested_realtime_us` is within a few seconds of its own start (the
broker binds the invocation only after the name is owned, so a freshly
started app normally sees the pending form). The record is informational:
it grants nothing, and a search start must still stay windowless, give no
agent or MCP authority and idle-exit by itself. A systemd environment or
drop-in was not used: a non-transient unit's environment cannot be changed
per start, and a runtime drop-in would no longer be a Root-installed unit.
The framework has no reader for this record yet.

## Revocation

When a committed `SetPolicy` changes `search` from true to false (gate on),
the broker looks at the record. It stops the instance only if all hold:

- the record is bound to an invocation ID equal to the unit's current one
  (a later user, agent or autostart start of the unit is never stopped);
- the main process is verified and the shell's window feed is known and
  reports **no** windows (an instance with a window was promoted: it is kept
  and its record dropped);
- the manifest declares `application-lifecycle-v1` and a fresh `QueryStop`
  on the verified bus owner reports no consequences (no agent call, task or
  app work).

Then it asks the app's lifecycle `Stop` with `finish-then-exit`; never a kill.
Agent use and promotion that ended before revocation are otherwise not
observable, so without the lifecycle contract, with unknown windows or with
reported work, the instance is left to its own idle exit (the framework's
windowless worker exits about 30 s after its last activity). The commit
result carries `search_instance`: `stop-requested`, `promoted`,
`work-in-progress`, `left-to-idle-exit`, `instance-unobservable`,
`not-running` or `not-search-started`. The review plan of an app declaring
`search` binds `revoking_search_may_stop_idle_search_instance`. Changing
policy never stops work.

## No D-Bus autostart bypass

The shell keeps `NO_AUTO_START` on every `Search` call; only this method
cold-starts a provider for a query. The broker never calls
`StartServiceByName` and installs nothing that makes a name activatable. The
D-Bus service file it requires is the framework's single-instance launch path
(a `DBusActivatable` desktop entry, `Activate`/`Open`), which is a user
launch: it already exists for every installed enzUI app and is not a search
source. A same-user peer that sends to the name without `NO_AUTO_START` can
start the unit through it, exactly as a desktop launch does.

## Prerequisites (framework, confirmed in source)

- `--agent-background` (`center::background::run`): the app's own state and
  reducer without display, renderer or window.
- Same-instance promotion: a desktop launch or `Activate`/`Open` reaches the
  running worker over `org.freedesktop.Application`, which presents its
  window over the same state (`enzui-agent-app`).
- Idle exit: `DEFAULT_IDLE_EXIT` is 30 s; a worker without broker work
  returns `Idle` and exits.
- `ApplicationService::serve_search` serves `dev.enzui.SearchProvider1`
  beside `org.freedesktop.Application`.

## Installed integration checks

Unit tests (`search::tests`, `provider::tests`, `service::tests`) cover the
declaration binding, refusals, cold start, already running, disabled and
denied source, unverified declarations, timeout without retry and revocation
with the gate forced on through the `adapter` argument. They do not
establish the installed seam. Before flipping the gate, on an installed image
with matched Background, MCP (ABI 2) and shell packages and one enzUI app
shipping the three declarations, a manifest declaring `search` and
`application-lifecycle-v1`:

1. With the gate built on in a test package: `GetCapabilities` shows
   `search_policy_adapter: true` only with the ABI 2 MCP reader present.
2. Default: the app's `search` is false; a query does not start it
   (`search-activation-disabled`), and a Search `Search` call without the
   broker does not auto-start it.
3. Enable `search` in Settings (ReviewPolicy/SetPolicy); `PolicyChanged`
   arrives; MCP agent policy and tool consent are unchanged.
4. Cold query: the unit starts once, the name is owned within 1 s, no window
   maps, results appear; the origin record matches `$INVOCATION_ID`.
5. Second query while running: `already-running`, no new invocation.
6. Choosing a result promotes the same process (same PID/invocation) to a
   window; closing it leaves the worker until idle exit.
7. Revoke `search`: an idle, windowless search-started instance gets a
   lifecycle stop; a promoted one and one with a live agent call are kept;
   the shell drops the provider.
8. Timeout: an app whose unit never owns its name gives
   `search-activation-timeout` after ~1 s with exactly one `StartUnit` in the
   user journal.
9. Refusals: a user `~/.local/share/applications/<app_id>.desktop`, a
   `~/.config/systemd/user` unit or drop-in, a replaced executable, a
   Flatpak with the same ID and a caller other than the shell are refused.
10. The idle worker exits on its own (~30 s) and `org.enzimos.Background1`
    exits after its 60 s idle.
