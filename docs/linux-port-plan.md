# iai-mcp Linux Port Plan

## Executive summary

iai-mcp is **80–85% portable today**. The core Python pipeline (LanceDB, sentence-transformers, NetworkX, igraph, cryptography, psutil, keyring) is cross-platform; `fcntl.flock` and `os.kill(pid, 0)` already work identically on Linux; the daemon's socket server already speaks the systemd-compatible `LISTEN_FDS` protocol; a working systemd user unit is shipped at `deploy/systemd/iai-mcp-daemon.service`; `cli.py` already branches Darwin vs Linux for install/uninstall/start/stop/logs and renders the unit with `sys.executable`; the test suite includes a Linux smoke test (`tests/shell/test_systemd_install.sh`) and a mocked `test_install_linux_writes_unit_and_invokes_systemctl`. The remaining gaps are: (1) `idle_detector.py` is wholly macOS, hard-coded to `/usr/sbin/ioreg` + `/usr/bin/pmset` and returns `False` on Linux (no sleep cycles will ever fire); (2) `doctor.py::_respawn_daemon` only yields to launchd's KeepAlive, not systemd's `Restart=on-failure`; (3) `scripts/install.sh` section 6 (LaunchAgent registration with socket activation) has no Linux counterpart; (4) the MCP wrapper (`mcp-wrapper/src/lifecycle.ts`) only kickstarts on darwin and falls back to writing `wake.signal`; (5) hook scripts hard-code `/usr/bin/python3`; and (6) Bazzite-specific concerns: distrobox D-Bus passthrough for SecretService, `loginctl enable-linger` semantics, and whether the daemon should live in the distrobox or on the host. Estimated effort: **2–4 focused days** for a working port; **5–7 days** to reach full feature parity (idle detection + socket activation + tests passing).

---

## Platform gap inventory

| File | Symbol / Pattern | macOS API used | Linux replacement | Notes |
|---|---|---|---|---|
| `src/iai_mcp/idle_detector.py` | `_IOREG_BIN = "/usr/sbin/ioreg"`, `IdleDetector.hid_idle_time_sec()` | `ioreg -c IOHIDSystem` parsed for `HIDIdleTime` ns | logind via `loginctl show-session $XDG_SESSION_ID -p IdleHint -p IdleSinceHint` | logind path requires D-Bus; if absent, falls back gracefully |
| `src/iai_mcp/idle_detector.py` | `_PMSET_BIN = "/usr/bin/pmset"`, `pmset_recent_sleep()` | `pmset -g log` for `System Sleep` / `Display is turned off` | `journalctl -b -t systemd-logind` for `Operation 'sleep'` / `Lid closed` — BUT only accessible from host journal, not distrobox. Practical: skip on Linux, lean on IdleHint + heartbeat-idle | On Bazzite/distrobox the container systemd journal doesn't see host suspend events |
| `src/iai_mcp/idle_detector.py` | `IdleDetector.status()` `available_signals: ["HIDIdleTime", "pmset"]` | hard-coded macOS signal names | rename to `["logind_idle", "logind_suspend"]` or populate from backend | cascades to `doctor.py::check_n_hid_idle_source` |
| `src/iai_mcp/doctor.py` | `check_n_hid_idle_source()` detail string | macOS terminology | platform-conditional or generic terms ("idle: 1234s, recent-suspend: clean") | display only, not logic |
| `src/iai_mcp/doctor.py` | `_respawn_daemon()` | yields to launchd KeepAlive when plist exists | add branch: if systemd unit exists, call `systemctl --user start iai-mcp-daemon.socket` instead of `subprocess.Popen`-racing | without this fix doctor races systemd's `Restart=on-failure` |
| `src/iai_mcp/doctor.py` | `check_g_no_dup_binders()`, `_kill_dup_binders()` | `lsof -U -F pn` | `lsof` exists on Fedora/Arch; keep it, add to install docs | ensure `lsof` is installed in distrobox |
| `src/iai_mcp/cli.py` | `cmd_daemon_install` Linux branch (lines ~436–466) | already calls `loginctl` + `systemctl --user` | works as-is structurally, but needs `.socket` unit support (Task 3) | logic exists but untested by author |
| `deploy/systemd/iai-mcp-daemon.service` | missing socket activation, missing env vars | launchd plist has socket activation + full env | add `Requires=iai-mcp-daemon.socket`, `After=iai-mcp-daemon.socket`, and env vars: `LIFECYCLE_DROWSY_AFTER_SEC=300`, `LIFECYCLE_SLEEP_HEARTBEAT_IDLE_SEC=1800`, `LIFECYCLE_HIBERNATE_AFTER_SEC=7200`, `IAI_MCP_SLEEP_QUARANTINE_TTL_HOURS=24`, `IAI_MCP_SYSTEMD_MANAGED=1` | |
| `deploy/systemd/iai-mcp-daemon.socket` | **missing** | macOS plist `Sockets.Listener` block | new file: `[Socket]\nListenStream=%h/.iai-mcp/.daemon.sock\nSocketMode=0600\n[Install]\nWantedBy=sockets.target` | daemon already supports `LISTEN_FDS` socket inheritance |
| `scripts/install.sh` | Section 6 gated to Darwin | `launchctl load -w` with plist template | add Linux `elif` branch: copy service+socket units to `~/.config/systemd/user/`, `daemon-reload`, `enable --now iai-mcp-daemon.socket`, `loginctl enable-linger $USER` | today Linux user must run `iai-mcp daemon install --yes` separately |
| `scripts/uninstall.sh` | Sections 2, 3, 7 Darwin-only | `launchctl unload`, plist removal | symmetric Linux: `systemctl --user disable --now iai-mcp-daemon.{socket,service}`, rm units, `daemon-reload` | currently no uninstall path on Linux through this script |
| `scripts/update.sh` | lines 103–115: launchd plist drift detection | reads `~/Library/LaunchAgents/*.plist` | Linux branch: compare `~/.config/systemd/user/iai-mcp-daemon.service` against template | cosmetic — fires WARN on drift |
| `mcp-wrapper/src/lifecycle.ts` | `LAUNCHCTL_BIN = "/bin/launchctl"`, `defaultSpawnKickstart()` gated to `process.platform === "darwin"` | `launchctl kickstart -k ...` | with socket activation: connect alone triggers systemd to spawn service — no kickstart needed. Fallback: `execFile("/usr/bin/systemctl", ["--user", "start", "iai-mcp-daemon.socket"])` | today Linux always writes `wake.signal` |
| `deploy/hooks/iai-mcp-session-capture.sh` | line 31 `/usr/bin/python3` | assumed present | use `command -v python3` at top | Arch distrobox may lack `/usr/bin/python3` |
| `deploy/hooks/iai-mcp-session-capture.sh` | line 97 candidates array | only macOS paths | prepend `$HOME/.local/bin/iai-mcp` | without this, hook silently no-ops on Linux |
| `deploy/hooks/iai-mcp-codex-session-capture.sh` | line 81 `/opt/homebrew/bin/iai-mcp` | Apple Silicon brew prefix | replace with `$HOME/.local/bin/iai-mcp` | |
| `deploy/hooks/iai-mcp-turn-capture.sh` | lines 142–146 `/usr/bin/python3` direct invocation | macOS path | use `command -v python3` shim | |
| `deploy/hooks/iai-mcp-session-recall.sh` | line 23 `/usr/bin/python3` | same | same | |
| `src/iai_mcp/cli.py` | keyring-migrate help text says "macOS Keychain" | macOS branding | change to "OS keyring (macOS Keychain / Linux SecretService)" | cosmetic |
| `tests/test_plist_template_lint.py` | macOS-only plist test | — | optional: add `tests/test_systemd_unit_lint.py` | low priority |

---

## Bazzite-specific considerations

### Architecture decision: daemon runs on the Bazzite host

Distroboxes are regularly rebuilt — any daemon installed inside a container doesn't survive a rebuild. The clean solution is to **run the daemon on the Bazzite host** using Homebrew Python, with the socket accessible from inside distrobox via the bind-mounted `$HOME`.

How it works:
- `$HOME` is bind-mounted into distrobox by default on Bazzite
- The daemon socket (`~/.iai-mcp/.daemon.sock`) is a path under `$HOME` → Claude Code in distrobox reaches it natively, no extra bind-mount config needed
- The memory store (`~/.iai-mcp/`) is also under `$HOME` → persists across distrobox rebuilds
- `loginctl enable-linger $USER` on the host + host systemd user service → survives reboots
- Logind idle detection on the host is fully accurate (not degraded like inside a container)

Install path for Bazzite:
1. `brew install python@3.12` on the host
2. Clone repo, `bash scripts/install.sh` (uses Homebrew Python for venv)
3. `iai-mcp daemon install --yes` (writes host systemd user unit, runs `loginctl enable-linger`)
4. Install MCP hooks inside distrobox (hooks call `$HOME/.local/bin/iai-mcp` which resolves on host)
5. Claude Code in distrobox connects to socket at `$HOME/.iai-mcp/.daemon.sock`

Node.js: the MCP wrapper (`node` command) must be installed on the host (also via `brew install node`), not just inside the distrobox, since the daemon and wrapper are host-side. Claude Code in distrobox runs the `node` binary path from the mcpServers config — if it's a host path not visible inside the container, point to the venv's wrapper binary instead. The `mcp-wrapper/dist/index.js` can be invoked with the host node path in the config.

### SecretService / keyring on Bazzite host

Bazzite KDE ships KWallet. `keyring` on the host (outside a container) will use KWallet via D-Bus. Should work out of the box. If not, `NoKeyringError` → `iai-mcp crypto init` (file-backed). Document in install output: *"If keyring errors, run `iai-mcp crypto init` — file-backed storage is the supported default on Linux."*

### General Linux (non-Bazzite) notes

For the upstream PR, the install targets any Linux with Python 3.11+ and systemd. The Bazzite-specific note (use Homebrew Python) goes in a README subsection, not the core install flow. The core Linux path assumes native Python is available (`python3 --version >= 3.11`).

---

## Implementation plan

Tasks in dependency order. Complexity: **S** = under 1 hr, **M** = a few hours, **L** = half day+.

### Task 1 — Smoke-test existing Linux branch end-to-end (S)
**Goal:** Establish baseline. Find latent bugs before writing new code.

- In distrobox: `bash scripts/install.sh` (expect "non-Darwin OS — skipping LaunchAgent registration")
- Run `iai-mcp daemon install --yes`
- Verify: `~/.config/systemd/user/iai-mcp-daemon.service` written, `systemctl --user is-enabled iai-mcp-daemon.service` → enabled, daemon running
- Run `iai-mcp doctor`. Capture all FAILs/WARNs
- Document the gap between expected and actual

### Task 2 — Linux idle-detector backend (M)
**Goal:** Replace macOS-only `idle_detector.py` with backend-dispatching design.

Files: `src/iai_mcp/idle_detector.py`, `src/iai_mcp/doctor.py`, `tests/test_idle_detector.py`

- Introduce a `_Backend` protocol: `hid_idle_sec()`, `recent_suspend(window_min)`, `available_signals()`
- Move existing ioreg+pmset logic into `_MacOSBackend`
- New `_LinuxLogindBackend`:
  - `hid_idle_sec()`: run `loginctl show-session {XDG_SESSION_ID} --property=IdleHint --property=IdleSinceHint`, parse `IdleSinceHint` (µs since epoch), compute elapsed
  - `recent_suspend(window_min)`: skip (distrobox can't see host journal). Return `False` with available_signal entry omitted
  - Fail gracefully on missing `loginctl` or absent D-Bus
- New `_NullBackend`: returns `None` / `False` always
- `IdleDetector.__init__` selects backend by `platform.system()`
- Update `doctor.py::check_n_hid_idle_source` to use generic terms from `available_signals()`
- Add `tests/test_idle_detector_linux.py` with mocked `subprocess.run`

### Task 3 — Add `iai-mcp-daemon.socket` unit + socket activation (M)
**Goal:** Match launchd's socket-activation behavior on Linux.

Files: `deploy/systemd/iai-mcp-daemon.socket` (new), `deploy/systemd/iai-mcp-daemon.service`, `src/iai_mcp/cli.py`

- New `deploy/systemd/iai-mcp-daemon.socket`:
  ```ini
  [Unit]
  Description=IAI-MCP Sleep Daemon socket
  [Socket]
  ListenStream=%h/.iai-mcp/.daemon.sock
  SocketMode=0600
  DirectoryMode=0700
  [Install]
  WantedBy=sockets.target
  ```
- Edit `deploy/systemd/iai-mcp-daemon.service`:
  - Add `Requires=iai-mcp-daemon.socket`, `After=iai-mcp-daemon.socket`
  - Add env vars: `LIFECYCLE_DROWSY_AFTER_SEC=300`, `LIFECYCLE_SLEEP_HEARTBEAT_IDLE_SEC=1800`, `LIFECYCLE_HIBERNATE_AFTER_SEC=7200`, `IAI_MCP_SLEEP_QUARANTINE_TTL_HOURS=24`, `IAI_MCP_SYSTEMD_MANAGED=1`
- Edit `cli.py::cmd_daemon_install` Linux branch to also write + enable `.socket` unit
  - `systemctl --user enable --now iai-mcp-daemon.socket` (socket is the boot anchor; it activates the service on first connect)
- Edit `cmd_daemon_uninstall` to stop+disable+rm both units

### Task 4 — Doctor: systemd-aware respawn (S)
**Goal:** `_respawn_daemon` yields to systemd instead of racing it.

Files: `src/iai_mcp/doctor.py`, `tests/test_doctor_apply_recovery.py`

- After the launchd-yield branch, add Linux branch:
  - If systemd unit exists and socket is managed, call `systemctl --user start iai-mcp-daemon.socket` (idempotent; fast)
  - Return `(True, "systemd-managed: socket unit restarted", duration_ms)`
- Add `_SYSTEMD_REACT_DELAY_SEC` constant
- Extend recovery tests with Linux branch

### Task 5 — `scripts/install.sh` section 6 Linux branch (M)
**Goal:** One-stop install on Linux, parallel to Darwin LaunchAgent path.

Files: `scripts/install.sh`, `scripts/uninstall.sh`, `scripts/update.sh`

`install.sh` changes:
- Add `elif [[ "$(uname)" == "Linux" ]]` branch in section 6:
  - Probe `systemctl --user status` (abort with clear message if no user-systemd session)
  - Copy + `sed`-render `deploy/systemd/iai-mcp-daemon.{service,socket}` into `~/.config/systemd/user/`, substituting `sys.executable` path
  - `systemctl --user daemon-reload`
  - `systemctl --user enable --now iai-mcp-daemon.socket`
  - `loginctl enable-linger $USER`
  - Verify: `systemctl --user is-enabled iai-mcp-daemon.socket | grep -q enabled`
- Lift `iai-mcp crypto init` call above Darwin guard (runs on both platforms)

`uninstall.sh` changes:
- Add Linux branches for sections 2, 3, 7:
  - `systemctl --user disable --now iai-mcp-daemon.{socket,service}`
  - `rm ~/.config/systemd/user/iai-mcp-daemon.{service,socket}`
  - `systemctl --user daemon-reload`

`update.sh` changes:
- Add Linux branch in section 5: compare installed unit against template, print WARN on drift

### Task 6 — Hook scripts: portable Python lookup + Linux install paths (S)
**Goal:** Hooks fire on Linux.

Files: all four `deploy/hooks/*.sh`

- At top of each: `PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo /usr/bin/python3)"`
- Replace every literal `/usr/bin/python3` with `"$PY"`
- `iai-mcp-session-capture.sh` line 96 candidates: prepend `"$HOME/.local/bin/iai-mcp"`
- `iai-mcp-codex-session-capture.sh` line 81: replace `/opt/homebrew/bin/iai-mcp` with `$HOME/.local/bin/iai-mcp`

### Task 7 — MCP wrapper Linux activation path (S)
**Goal:** Wrapper triggers socket activation on Linux.

Files: `mcp-wrapper/src/lifecycle.ts`, `mcp-wrapper/test/lifecycle.test.ts`

- Add constants: `SYSTEMCTL_BIN = "/usr/bin/systemctl"`, `SYSTEMD_SOCKET_UNIT = "iai-mcp-daemon.socket"`
- In `ensureDaemonAlive`: on Linux, after failed socket probe, call `execFile(SYSTEMCTL_BIN, ["--user", "start", SYSTEMD_SOCKET_UNIT])` before writing `wake.signal`
- With socket activation enabled (Task 3), `socketReachable()` returns `true` immediately — no kickstart needed in the happy path; the fallback covers the non-socket-activated case
- Update test with Linux branch (mock `execFile`)

### Task 8 — Cosmetic cleanup (S)
**Goal:** Strip macOS-only wording from user-visible output on Linux.

Files: `src/iai_mcp/cli.py`, `src/iai_mcp/doctor.py`

- Replace "macOS Keychain" with "OS keyring (macOS Keychain / Linux SecretService)" in help text and doctor detail strings
- `cli.py` line ~1129 `killall Claude`: keep, it's already Darwin-only

### Task 9 — Linux integration tests (M)
**Goal:** CI-runnable lock-in for the port.

Files: `tests/shell/test_systemd_install.sh`, `tests/test_cli_daemon.py`, `tests/test_idle_detector_linux.py`, `tests/test_doctor_systemd_respawn.py`

- Verify `tests/shell/test_systemd_install.sh` passes after Tasks 3+5
- Extend `test_cli_daemon.py` with Linux-branch coverage: mock `subprocess.run`, set `platform.system()` to `"Linux"`, assert `.socket` unit rendered alongside `.service`
- `test_idle_detector_linux.py`: cover `_LinuxLogindBackend` (Task 2) with mocked `loginctl` + absent D-Bus paths
- `test_doctor_systemd_respawn.py`: cover Task 4 recovery branch

### Task 10 — Documentation update (S)
**Goal:** README + CHANGELOG reflect Linux support.

Files: `README.md`, `CHANGELOG.md`

- Replace macOS-only badge/caveat with platform table: macOS (production-tested), Linux (supported, distrobox-friendly)
- Add "Bazzite / distrobox quickstart" subsection: enable-linger, distrobox auto-start, expected degraded idle detection (heartbeat-only mode), `lsof` install requirement
- Document `systemctl --user` commands and service files
- Add CHANGELOG entry

---

## Open questions

Remaining decisions before/during implementation:

1. **Node.js on host for Bazzite.** The mcpServers config written by `cli.py` uses `command: "node"`. On the Bazzite host, `brew install node` provides it. But the path (`/home/linuxbrew/.linuxbrew/bin/node`) needs to be in the config. The CLI could auto-detect `command -v node` and write the absolute path. Does the CLI already do this, or does it always write `"node"` and rely on PATH?

2. **Wayland idle detection.** Before Task 2, do a quick manual test on the Bazzite host: `loginctl show-session $XDG_SESSION_ID -p IdleHint -p IdleSinceHint`. Confirm the values update when the machine is idle. On KDE Wayland this usually works; on some compositors it may not. If it returns nothing useful, heartbeat-only is the correct Linux fallback.

3. **`lsof` on the host.** Bazzite's base has `lsof` (Fedora ships it). Should the install script verify and print a hint if missing? Or rely on doctor to flag it?

4. **Upstream PR scope.** The author says Linux support is planned. Is the goal to open a single PR with the full port, or land it in chunks (e.g. Task 6 hook fixes first as an easy win, then Task 2 idle detector, then socket activation)?

---

## Out of scope

- **Windows support** — no changes
- **Optional `llmlingua`/`accelerate` compression** — already handles CPU/CUDA/MPS; no Linux-specific work
- **Claude Desktop on Linux** — `_claude_desktop_config_path()` already returns XDG path; untested but plausibly working; leave alone
- **Host-side daemon (Option B)** — documented, deferred
- **Refactoring `cli.py`** — surgical changes only to existing Linux branches; no restructure
- **Replacing `lsof` with `ss`** — `lsof` works on Linux; switching is churn without benefit
