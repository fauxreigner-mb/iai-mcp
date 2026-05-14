// Phase 10.5 L5 + L4 — wrapper-side proactive wake + heartbeat refresh.
//
// Two responsibilities, both lazy and idle-CPU-near-zero:
//
//   L5  ensureDaemonAlive:
//       Probe the daemon UNIX socket (~/.iai-mcp/.daemon.sock) at boot.
//       If reachable, return immediately — no kickstart cost, no signal.
//       If unreachable AND platform is darwin, spawn `launchctl kickstart
//       -k gui/<uid>/com.iai-mcp.daemon` via Node's `execFile` API
//       (array args, hard-coded binary path, NEVER `shell: true`).
//       If the kickstart command fails or the platform is not darwin,
//       atomic-write ~/.iai-mcp/wake.signal so the next daemon cold-
//       start consumes it via `iai_mcp.wake_handler.WakeHandler`. The
//       wrapper itself NEVER spawns the daemon Python process — that
//       remains a launchd / external-init concern (Phase 7.1 invariant).
//
//   L4  registerHeartbeat:
//       Atomically write ~/.iai-mcp/wrappers/heartbeat-<pid>-<uuid>.json
//       (temp + rename) and start a 30-second interval timer that
//       refreshes the `last_refresh` field. The timer is `unref()`d so
//       it does NOT block Node.js shutdown — the wrapper exits cleanly
//       even if `cleanupHeartbeat` is not called (the daemon's
//       HeartbeatScanner from Phase 10.4 will eventually classify the
//       file as STALE / ORPHAN and reap it).
//
// Hard rules carried from CONTEXT 10.5:
//
//   - All `child_process` calls go through `execFile` (array args).
//     NEVER the shell-interpreting `exec` variant. NEVER `shell: true`.
//     Hard-coded binary path (/bin/launchctl); only the GUI uid is
//     process-derived (`process.getuid()`).
//   - The 30-sec refresh is a single `setInterval` with `unref()`, not
//     a busy loop or per-tick spawn.
//   - macOS-first; Linux / unknown platforms write `wake.signal`
//     directly without attempting kickstart.
//   - 045999b decoupling preserved — this module is independent of the
//     bridge / tools/list path. `ensureDaemonAlive` is a probe + spawn,
//     not a connect; tools/list MUST keep responding from the static
//     wrapper registry whether the daemon is up or not.
//   - `src/utils/execFileNoThrow.ts` is referenced in CONTEXT 10.5 as a
//     pattern reference but does NOT exist in this repo. We inline the
//     pattern here: `promisify(execFile)` + try/catch. Keeps the LOC
//     budget tight and makes the security guarantee local.
//
// File schema (matches `iai_mcp.heartbeat_scanner._parse_heartbeat_file`):
//
//     {
//       "pid": 12345,
//       "uuid": "01HZQ...",                         // crypto.randomUUID()
//       "started_at": "2026-05-02T15:00:00Z",
//       "last_refresh": "2026-05-02T15:14:30Z",
//       "wrapper_version": "1.0.0",
//       "schema_version": 1
//     }

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------- constants

/** Refresh cadence (ms). 30 s is the LOCKED contract from CONTEXT 10.4 / 10.5
 * — three missed refreshes (~90 s) trip the heartbeat scanner's STALE
 * threshold (`DEFAULT_STALE_THRESHOLD_SEC` in `heartbeat_scanner.py`). */
export const HEARTBEAT_REFRESH_INTERVAL_MS = 30_000;

/** Wrapper schema version. Bump only on a breaking change to the heartbeat
 * file shape. Phase 10.4 reader currently treats `schema_version` as
 * informational; future versions may gate field-presence checks on it. */
export const HEARTBEAT_SCHEMA_VERSION = 1;

/** Wrapper version string written into each heartbeat file. Tracks the
 * `mcp-wrapper/package.json` version semantically; not auto-derived to
 * keep this module dependency-free at runtime. */
export const WRAPPER_VERSION = "1.0.0";

/** Hard-coded launchctl binary path. Argv-only invocation — no shell
 * interpretation, no PATH lookup, no user-input interpolation. */
const LAUNCHCTL_BIN = "/bin/launchctl";

/** Hard-coded launchd label for the IAI-MCP daemon. Matches the
 * `com.iai-mcp.daemon` LaunchAgent shipped by the project. */
const LAUNCHD_LABEL = "com.iai-mcp.daemon";

/** Subprocess timeout (ms) for the kickstart call. Covers the worst-case
 * `launchctl kickstart` round-trip on a heavily loaded box; well under
 * the wrapper's MCP `tools/list` budget (server.connect already happens
 * before this in the boot flow). */
const KICKSTART_TIMEOUT_MS = 5_000;

/** Hard-coded systemctl binary path. Used on Linux for socket-activation
 * kickstart. Argv-only invocation — no shell interpretation. */
const SYSTEMCTL_BIN = "/usr/bin/systemctl";

/** systemd user socket unit name for the IAI-MCP daemon. */
const SYSTEMD_SOCKET_UNIT = "iai-mcp-daemon.socket";

/** Subprocess timeout (ms) for the systemctl start call. */
const SYSTEMD_START_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------- types

interface HeartbeatPayload {
  pid: number;
  uuid: string;
  started_at: string;
  last_refresh: string;
  wrapper_version: string;
  schema_version: number;
}

// ---------------------------------------------------------------- paths

/** Compute `~/.iai-mcp/.daemon.sock`. Mirrors the daemon-side socket
 * path constant in `iai_mcp.concurrency`. */
export function defaultSocketPath(): string {
  return join(homedir(), ".iai-mcp", ".daemon.sock");
}

/** Compute `~/.iai-mcp/wake.signal`. Mirrors the path the daemon-side
 * `WakeHandler` consumes on cold-start. */
export function defaultWakeSignalPath(): string {
  return join(homedir(), ".iai-mcp", "wake.signal");
}

/** Compute `~/.iai-mcp/wrappers/heartbeat-<pid>-<uuid>.json`. Matches
 * the filename glob in `iai_mcp.heartbeat_scanner`. */
export function defaultHeartbeatPath(pid: number, uuid: string): string {
  return join(homedir(), ".iai-mcp", "wrappers", `heartbeat-${pid}-${uuid}.json`);
}

// ---------------------------------------------------------------- lifecycle

/** Constructor options. All fields optional; defaults derive from
 * `process` and `os.homedir()`. Dependency injection is here so tests
 * can supply a tmp dir without monkey-patching `homedir`. */
export interface WrapperLifecycleOptions {
  pid?: number;
  uuid?: string;
  socketPath?: string;
  wakeSignalPath?: string;
  heartbeatPath?: string;
  /** Override the platform string. Defaults to `process.platform`. */
  platform?: NodeJS.Platform;
  /** Probe the daemon socket. Defaults to a real `net.createConnection`
   * attempt with a short timeout. Tests inject a mock. */
  socketReachable?: () => Promise<boolean>;
  /** Spawn `launchctl kickstart`. Defaults to the real `execFile` call.
   * Tests inject a mock that resolves or rejects deterministically. */
  spawnKickstart?: () => Promise<void>;
  /** Spawn `systemctl --user start iai-mcp-daemon.socket`. Defaults to the
   * real `execFile` call. Tests inject a mock. */
  spawnSystemdSocket?: () => Promise<void>;
  /** Heartbeat refresh interval (ms). Defaults to
   * `HEARTBEAT_REFRESH_INTERVAL_MS`. Tests pass a smaller value. */
  refreshIntervalMs?: number;
}

export class WrapperLifecycle {
  private readonly pid: number;
  private readonly uuid: string;
  private readonly socketPath: string;
  private readonly wakeSignalPath: string;
  private readonly heartbeatPath: string;
  private readonly platform: NodeJS.Platform;
  private readonly socketReachable: () => Promise<boolean>;
  private readonly spawnKickstart: () => Promise<void>;
  private readonly spawnSystemdSocket: () => Promise<void>;
  private readonly refreshIntervalMs: number;

  private readonly startedAt: string;
  private timer: NodeJS.Timeout | null = null;

  constructor(opts: WrapperLifecycleOptions = {}) {
    this.pid = opts.pid ?? process.pid;
    this.uuid = opts.uuid ?? randomUUID();
    this.socketPath = opts.socketPath ?? defaultSocketPath();
    this.wakeSignalPath = opts.wakeSignalPath ?? defaultWakeSignalPath();
    this.heartbeatPath =
      opts.heartbeatPath ?? defaultHeartbeatPath(this.pid, this.uuid);
    this.platform = opts.platform ?? process.platform;
    this.socketReachable = opts.socketReachable ?? defaultSocketReachable(this.socketPath);
    this.spawnKickstart = opts.spawnKickstart ?? defaultSpawnKickstart();
    this.spawnSystemdSocket = opts.spawnSystemdSocket ?? defaultSpawnSystemdSocket();
    this.refreshIntervalMs = opts.refreshIntervalMs ?? HEARTBEAT_REFRESH_INTERVAL_MS;
    this.startedAt = isoNow();
  }

  /** L5: probe daemon socket; if unreachable, kickstart on darwin or
   * write `wake.signal` elsewhere. Never throws — the worst case is a
   * silent fallback to the signal file, which the daemon will pick up
   * on its next cold start. */
  async ensureDaemonAlive(): Promise<void> {
    let alive = false;
    try {
      alive = await this.socketReachable();
    } catch {
      alive = false;
    }
    if (alive) {
      return;
    }
    if (this.platform === "darwin") {
      try {
        await this.spawnKickstart();
        return;
      } catch {
        // Kickstart failed — fall through to wake.signal.
      }
    } else if (this.platform === "linux") {
      try {
        await this.spawnSystemdSocket();
        // Socket unit started; the daemon activates on first connect.
        return;
      } catch {
        // systemctl failed (unit not installed, systemd absent).
        // Fall through to wake.signal so a future daemon boot picks it up.
      }
    }
    // Non-darwin/linux OR fallback: write the cross-platform marker.
    try {
      await this.writeWakeSignal();
    } catch {
      // Even the wake.signal write failed (FS full, permission). Nothing
      // we can do safely here; do NOT escalate — the wrapper still has
      // useful work to do (tools/list responds from the static registry).
    }
  }

  /** L4: write the heartbeat file and start the 30-sec refresh timer.
   * Called once at wrapper boot. Idempotent on the timer side: a second
   * call clears any prior timer before installing a new one. */
  async registerHeartbeat(): Promise<void> {
    await this.writeHeartbeat();
    if (this.timer !== null) {
      clearInterval(this.timer);
    }
    const timer = setInterval(() => {
      void this.writeHeartbeat().catch(() => {
        // Refresh failure is non-fatal: the daemon will classify the
        // stale file as STALE on the next scan and recover. We do NOT
        // log here to keep the idle-CPU profile near zero.
      });
    }, this.refreshIntervalMs);
    timer.unref();
    this.timer = timer;
  }

  /** Graceful exit: stop the refresh timer and delete the heartbeat
   * file. Safe to call multiple times. Safe to call without prior
   * `registerHeartbeat` (no-ops). */
  async cleanupHeartbeat(): Promise<void> {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    try {
      await unlink(this.heartbeatPath);
    } catch {
      // Already gone (concurrent daemon-side cleanup of a STALE entry,
      // or never written). Idempotent — swallow.
    }
  }

  // ---------------------------------------------- internals (visible-for-test)

  /** Atomically write the heartbeat file: tmp + rename. The tmp
   * filename includes the wrapper's UUID so concurrent wrappers do
   * NOT collide on the staging path even if they share a working
   * directory. */
  private async writeHeartbeat(): Promise<void> {
    const payload: HeartbeatPayload = {
      pid: this.pid,
      uuid: this.uuid,
      started_at: this.startedAt,
      last_refresh: isoNow(),
      wrapper_version: WRAPPER_VERSION,
      schema_version: HEARTBEAT_SCHEMA_VERSION,
    };
    const dir = dirname(this.heartbeatPath);
    await mkdir(dir, { recursive: true });
    const tmp = `${this.heartbeatPath}.${this.uuid}.tmp`;
    await writeFile(tmp, JSON.stringify(payload), { encoding: "utf-8" });
    await rename(tmp, this.heartbeatPath);
  }

  /** Atomically write `wake.signal`: tmp + rename. Per-uuid tmp suffix
   * avoids cross-wrapper staging collisions on the same machine. */
  private async writeWakeSignal(): Promise<void> {
    const dir = dirname(this.wakeSignalPath);
    await mkdir(dir, { recursive: true });
    const payload = JSON.stringify({
      requested_at: isoNow(),
      wrapper_pid: this.pid,
      wrapper_uuid: this.uuid,
    });
    const tmp = `${this.wakeSignalPath}.${this.uuid}.tmp`;
    await writeFile(tmp, payload, { encoding: "utf-8" });
    await rename(tmp, this.wakeSignalPath);
  }
}

// ---------------------------------------------------------------- defaults

function isoNow(): string {
  // ISO-8601 with trailing Z — matches the wire format the daemon-side
  // `_parse_heartbeat_file` accepts (replaces "Z" with "+00:00" before
  // `datetime.fromisoformat`).
  return new Date().toISOString();
}

/** Default socket-probe: open a UNIX-domain socket connection to the
 * daemon path with a short timeout. Resolves true on `connect`,
 * false on `error` or timeout. */
function defaultSocketReachable(socketPath: string): () => Promise<boolean> {
  return async () => {
    const { createConnection } = await import("node:net");
    return await new Promise<boolean>((resolve) => {
      let settled = false;
      const settle = (v: boolean): void => {
        if (settled) return;
        settled = true;
        try {
          socket.destroy();
        } catch {
          // socket already destroyed by the loser of the connect/timeout
          // race — ignore.
        }
        resolve(v);
      };
      const socket = createConnection({ path: socketPath });
      socket.setTimeout(1_000);
      socket.once("connect", () => settle(true));
      socket.once("error", () => settle(false));
      socket.once("timeout", () => settle(false));
    });
  };
}

/** Default kickstart spawn: `execFile` with array args, hard-coded
 * binary path, no shell. The GUI uid is process-derived (`getuid()`)
 * so the same wrapper works for any signed-in user. */
function defaultSpawnKickstart(): () => Promise<void> {
  return async () => {
    // `process.getuid()` is undefined on Windows builds; ! asserts
    // non-null because we only ever call this on darwin (the
    // ensureDaemonAlive caller gates on platform === "darwin").
    const uid = typeof process.getuid === "function" ? process.getuid() : 0;
    const args = ["kickstart", "-k", `gui/${uid}/${LAUNCHD_LABEL}`];
    await execFileAsync(LAUNCHCTL_BIN, args, {
      timeout: KICKSTART_TIMEOUT_MS,
      // No `shell` option — argv-only invocation, no shell interpretation.
    });
  };
}

/** Default Linux socket-activation: `systemctl --user start iai-mcp-daemon.socket`.
 * Idempotent — safe to call even if the unit is already active.
 * The socket unit holds the UNIX socket open; service activates on first connect. */
function defaultSpawnSystemdSocket(): () => Promise<void> {
  return async () => {
    await execFileAsync(SYSTEMCTL_BIN, ["--user", "start", SYSTEMD_SOCKET_UNIT], {
      timeout: SYSTEMD_START_TIMEOUT_MS,
    });
  };
}
