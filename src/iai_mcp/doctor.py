"""daemon health doctor (R9) + R6 multi-binder check
+ file-backed crypto-key state check
+ [Wave2-Option-C] Lance versions-count diagnostic row
+ wake/sleep cycle rows (m) heartbeat scanner + (n) HID idle source
+ Task 1.3 lifecycle visibility rows
  (j) lifecycle current state, (k) lifecycle history 24h,
  (l) sleep cycle quarantine status.

Runs a 14-row PASS/WARN/FAIL checklist + up to 4-action repair sequence.

Beer VSM S2 anti-oscillation: reversibility-by-default. Default mode is
diagnose-only (zero mutations). --apply confirms each destructive action;
--apply --yes skips confirmations.

Constitutional guards:
- C-USER-CONSENT (invariant per D7-16): doctor --apply respects
  [y/N] confirmations unless --yes is also passed; no destructive action
  without explicit consent.
- C4 CLEAN UNINSTALL: doctor --apply may unlink stale ~/.iai-mcp/.daemon.sock
  ONLY. Lock file + state file are managed by daemon_state.save_state /
  iai-mcp daemon uninstall.
- R5 fail-loud: doctor surfaces failures with explicit user-readable diagnosis,
  never silently masks daemon death.
- Wrong-PID-kill mitigation (RESEARCH §Security T-04-XX): every kill action
  verifies BOTH os.kill(pid, 0) liveness AND psutil.Process(pid).cmdline()
  contains 'iai_mcp.core' (orphan target) or 'iai_mcp.daemon' (live target)
  before SIGTERM. Mitigates PID reuse on macOS (PIDs cycle within minutes).

Exit codes (D7-13):
  0 = all checks PASS (14 since ; WARN does NOT flip to 1)
  1 = one or more FAIL (no --apply)
  2 = --apply ran but final re-check still has FAIL

This module has NO LLM code and NO paid-API env var references.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


# Recovery action timing constants. Tuned so a launchd-managed daemon has
# time to react (KeepAlive bounces in 1-2s on macOS) and a manual respawn
# can finish bge-small load (~3-10s) plus LanceDB open (~1s).
_LAUNCHD_REACT_DELAY_SEC = 2.0
_SYSTEMD_REACT_DELAY_SEC = 2.0
_RESPAWN_BIND_TIMEOUT_SEC = 8.0
_RESPAWN_POLL_INTERVAL_SEC = 0.1


# -----------------------------------------------------------------------------
# Result + action dataclasses
# -----------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single doctor check.

    Attributes:
        name: Stable label printed verbatim (e.g. "(a) daemon process alive").
        passed: True iff the check is healthy. WARN rows count as ``passed=True``
            so they do NOT flip the doctor's exit code to 1 — they're advisory.
        detail: One-line explanation; printed verbatim after the
            [PASS]/[WARN]/[FAIL] tag.
        status: — one of "PASS", "WARN", "FAIL". Lets check_h
            emit the WARN tri-state without breaking the 3-arg construction
            pattern used by ~14 sites in test_doctor_checklist.py. When
            unspecified, derives from ``passed`` (True → "PASS", False → "FAIL").
    """

    name: str
    passed: bool
    detail: str
    status: str = ""

    def __post_init__(self) -> None:
        # Default-derive `status` from `passed` so legacy 3-arg construction
        # continues to work unchanged. Explicit ``status="WARN"`` is the only
        # way to produce a WARN row.
        if not self.status:
            self.status = "PASS" if self.passed else "FAIL"


@dataclass
class RepairAction:
    """A single --apply repair step.

    Attributes:
        label: Short slug used in audit events + log lines (e.g. "respawn_daemon").
        description: Human-readable phrasing shown in [y/N] prompt.
        destructive: True iff the action mutates state or kills processes; gated
            by [y/N] confirmation when --yes is not passed.
        execute: Callable returning (success, message, duration_ms).
    """

    label: str
    description: str
    destructive: bool
    execute: Callable[[], tuple[bool, str, int]]


# -----------------------------------------------------------------------------
# Helpers — socket path resolution honoring IAI_DAEMON_SOCKET_PATH
# -----------------------------------------------------------------------------


def _resolve_socket_path() -> Path:
    """Return the socket path honoring IAI_DAEMON_SOCKET_PATH env override.

     LOCK precedent: the env override is the test isolation
    mechanism; production users have no env var set and fall back to
    ~/.iai-mcp/.daemon.sock.
    """
    env_path = os.environ.get("IAI_DAEMON_SOCKET_PATH")
    if env_path:
        return Path(env_path)
    from iai_mcp.cli import SOCKET_PATH

    return Path(SOCKET_PATH)


async def _socket_status_probe(socket_path: Path, timeout: float) -> dict | None:
    """One-shot NDJSON `{type: status}` round-trip against socket_path.

    Returns the daemon's reply dict, or None if the daemon is unreachable
    (socket missing / connect refused / no reply within timeout).

    Distinct from cli._send_socket_request — that helper hard-codes the home
    socket path; the doctor needs to honor IAI_DAEMON_SOCKET_PATH so test
    isolation works (advisor reconciliation 2026-04-26).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path=str(socket_path)),
            timeout=timeout,
        )
    except (FileNotFoundError, ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return None
    try:
        writer.write((json.dumps({"type": "status"}) + "\n").encode("utf-8"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            return None
        return json.loads(line.decode("utf-8"))
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# 6 individual checks (D7-11 ordering)
# -----------------------------------------------------------------------------


def check_a_daemon_alive() -> CheckResult:
    """(a) daemon process alive.

    PID source-of-truth is `~/.iai-mcp/.daemon-state.json` per RESEARCH §2
    D7-11(a) revision (stamps `daemon_pid` on boot; the .lock
    file is fcntl-only and contains zero PID bytes).

    Wrong-PID kill mitigation: verifies BOTH os.kill(pid, 0) liveness AND
    psutil.cmdline contains 'iai_mcp.daemon'. Without the cmdline check,
    a recycled PID belonging to an unrelated process would falsely appear
    healthy.
    """
    from iai_mcp.daemon_state import load_state

    try:
        state = load_state() or {}
    except Exception as e:
        return CheckResult(
            "(a) daemon process alive",
            False,
            f"daemon-state.json unreadable: {type(e).__name__}: {e}",
        )

    pid = state.get("daemon_pid")
    if pid is None:
        return CheckResult(
            "(a) daemon process alive",
            False,
            "ABSENT (no daemon_pid in state — daemon never booted or already shut down)",
        )

    # Reject obviously-garbage PID values (negative / non-int / > INT_MAX)
    # from a corrupted state file before they reach os.kill, which raises
    # OverflowError for out-of-range ints. ProcessLookupError is the right
    # semantic here — the "process" is unreachable / bogus.
    if not isinstance(pid, int) or pid < 1 or pid > 2**31 - 1:
        return CheckResult(
            "(a) daemon process alive",
            False,
            f"daemon_pid={pid!r} is not a valid PID (corrupt state?)",
        )

    # Liveness probe via signal 0 (no actual signal sent).
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return CheckResult(
            "(a) daemon process alive",
            False,
            f"PID {pid} in state but no process found",
        )
    except PermissionError:
        # Process exists but is owned by another UID (extremely unlikely on a
        # single-user machine; would mean PID reuse to a system process).
        return CheckResult(
            "(a) daemon process alive",
            False,
            f"PID {pid} exists but is not owned by this user",
        )
    except OSError as e:
        return CheckResult(
            "(a) daemon process alive",
            False,
            f"liveness probe failed: {type(e).__name__}: {e}",
        )

    # Wrong-PID-kill mitigation: confirm the live PID is actually our daemon.
    try:
        import psutil

        proc = psutil.Process(pid)
        cmdline = " ".join(proc.cmdline() or [])
        if "iai_mcp.daemon" not in cmdline:
            return CheckResult(
                "(a) daemon process alive",
                False,
                f"PID {pid} is NOT iai_mcp.daemon (got: {proc.name()!r})",
            )
    except Exception as e:  # noqa: BLE001 — psutil edge cases all roll up here
        return CheckResult(
            "(a) daemon process alive",
            False,
            f"could not verify PID {pid}: {type(e).__name__}: {e}",
        )

    return CheckResult(
        "(a) daemon process alive",
        True,
        f"PID {pid} (iai_mcp.daemon)",
    )


def check_b_socket_fresh() -> CheckResult:
    """(b) socket file fresh.

    `~/.iai-mcp/.daemon.sock` (or IAI_DAEMON_SOCKET_PATH override) exists
    AND a `connect()` plus `{type: status}` round-trip succeeds within
    250 ms per SPEC R2.
    """
    socket_path = _resolve_socket_path()
    if not socket_path.exists():
        return CheckResult(
            "(b) socket file fresh",
            False,
            f"{socket_path} does not exist",
        )

    t0 = time.monotonic()
    try:
        resp = asyncio.run(_socket_status_probe(socket_path, timeout=0.25))
    except Exception as e:  # noqa: BLE001 — surface any unexpected probe failure
        return CheckResult(
            "(b) socket file fresh",
            False,
            f"connect failed: {type(e).__name__}: {e}",
        )
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    if resp is None:
        return CheckResult(
            "(b) socket file fresh",
            False,
            f"{socket_path} present but unreachable (timeout/refused)",
        )
    return CheckResult(
        "(b) socket file fresh",
        True,
        f"{socket_path} connected in {elapsed_ms} ms",
    )


def check_c_lock_healthy() -> CheckResult:
    """(c) lock file healthy.

    "Healthy" means `fcntl` operations on the lock file succeed without an
    OS-level error. A live daemon mid-REM holds exclusive (try_acquire
    returns False — that is HEALTHY, not broken). A live MCP recall holds
    shared (try_acquire returns False — also HEALTHY). Only an exception
    from `fcntl` or filesystem layer indicates an orphaned / corrupted lock
    that warrants doctor attention.

    Plan template's `acquire_shared(blocking=False) -> bool` does not exist
    on the project's ProcessLock (real API: blocking acquire_shared() -> None
    + non-blocking try_acquire_exclusive() -> bool). Fixed per advisor
    reconciliation 2026-04-26 (deviation Rule 1 — plan-template bug).
    """
    from iai_mcp.cli import LOCK_PATH
    from iai_mcp.concurrency import ProcessLock

    lock = None
    try:
        lock = ProcessLock(Path(LOCK_PATH))
        # Either acquiring or being blocked is healthy; only OSError-on-fcntl
        # indicates a broken / inaccessible lock file.
        if lock.try_acquire_exclusive():
            lock.release()
            return CheckResult(
                "(c) lock file healthy",
                True,
                f"{LOCK_PATH} acquirable (idle)",
            )
        return CheckResult(
            "(c) lock file healthy",
            True,
            f"{LOCK_PATH} held (daemon REM or MCP active — normal)",
        )
    except Exception as e:  # noqa: BLE001 — fcntl/OSError/permission all FAIL
        return CheckResult(
            "(c) lock file healthy",
            False,
            f"fcntl probe failed: {type(e).__name__}: {e}",
        )
    finally:
        if lock is not None:
            try:
                lock.close()
            except Exception:
                pass


def check_d_no_orphan_core() -> CheckResult:
    """(d) zero orphan iai_mcp.core processes (pre-Phase-7 leftovers).

    invariant (SUMMARY): NO `iai_mcp.core` processes
    should exist anywhere — wrappers spawn the singleton daemon, never a
    per-wrapper core. Any hit here is a pre-Phase-7 leftover that wastes
    ~1.2 GB RSS and confuses cross-client memory.
    """
    try:
        import psutil

        orphans: list[int] = []
        for p in psutil.process_iter(["pid", "cmdline"]):
            try:
                cl = " ".join(p.info.get("cmdline") or [])
                if "iai_mcp.core" in cl:
                    orphans.append(p.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not orphans:
            return CheckResult(
                "(d) no orphan iai_mcp.core procs",
                True,
                "0 found",
            )
        return CheckResult(
            "(d) no orphan iai_mcp.core procs",
            False,
            f"{len(orphans)} found: PIDs {orphans}",
        )
    except Exception as e:  # noqa: BLE001 — psutil edge cases
        return CheckResult(
            "(d) no orphan iai_mcp.core procs",
            False,
            f"psutil probe failed: {type(e).__name__}: {e}",
        )


def check_e_state_file_valid() -> CheckResult:
    """(e) daemon state file valid.

    `~/.iai-mcp/.daemon-state.json` either:
      - does not exist (daemon never booted — acceptable, NOT a bug); OR
      - parses as JSON AND `fsm_state` ∈ {WAKE, SLEEPING, DREAMING}.
    """
    from iai_mcp.daemon_state import load_state

    try:
        state = load_state() or {}
    except Exception as e:  # noqa: BLE001 — corrupt JSON / IO error
        return CheckResult(
            "(e) daemon state file valid",
            False,
            f"unreadable: {type(e).__name__}: {e}",
        )

    fsm_state = state.get("fsm_state")
    if fsm_state is None:
        # No state file (or no fsm_state key) is acceptable when daemon has
        # never booted. A separate check (a) catches the "never booted but
        # should have" case.
        return CheckResult(
            "(e) daemon state file valid",
            True,
            "no state file (daemon never booted — not a bug)",
        )

    valid = {"WAKE", "SLEEPING", "DREAMING"}
    if fsm_state in valid:
        return CheckResult(
            "(e) daemon state file valid",
            True,
            f"fsm_state={fsm_state}",
        )
    return CheckResult(
        "(e) daemon state file valid",
        False,
        f"fsm_state={fsm_state!r} not in {sorted(valid)}",
    )


def check_f_lancedb_readable() -> CheckResult:
    """(f) lancedb store readable.

    Open a MemoryStore handle. The constructor opens the lancedb connection;
    if the directory is corrupt / permission-denied / disk-full, the
    constructor raises and we report FAIL.
    """
    try:
        from iai_mcp.store import MemoryStore

        MemoryStore()
        return CheckResult(
            "(f) lancedb store readable",
            True,
            "opens without error",
        )
    except Exception as e:  # noqa: BLE001 — surface any open failure
        return CheckResult(
            "(f) lancedb store readable",
            False,
            f"open failed: {type(e).__name__}: {e}",
        )


# -----------------------------------------------------------------------------
# R6 — multi-binder detection
# -----------------------------------------------------------------------------


def _extract_binder_pids(lsof_output: str, target_socket: Path) -> set[int]:
    """Parse lsof -F pn output. Format alternates lines:

       p<pid>
       n<filename>

    Each PID is followed by 0+ name entries until next p<pid>. Return the
    set of PIDs whose name == str(target_socket).

    Defense-in-depth helper for check_g_no_dup_binders. Pure parser, no I/O —
    accepts the captured stdout and returns the matching PID set.
    """
    pids: set[int] = set()
    current_pid: int | None = None
    target = str(target_socket)
    for line in lsof_output.splitlines():
        if line.startswith("p"):
            try:
                current_pid = int(line[1:])
            except ValueError:
                current_pid = None
        elif line.startswith("n") and current_pid is not None:
            name = line[1:]
            if name == target:
                pids.add(current_pid)
    return pids


def check_g_no_dup_binders() -> CheckResult:
    """(g) no duplicate processes bound to socket — TOCTOU race aftermath detector.

    R6: even with launchd as the only spawn vector in production,
    a user can manually `python -m iai_mcp.daemon` while one is already
    running. lsof -U reports all processes holding the AF_UNIX socket fd;
    if >1, we have a singleton-invariant violation that no other check
    catches (check_a inspects state.json:daemon_pid; a second daemon that
    never wrote state is invisible to check_a).

    lsof unavailable (rare on macOS, possible on minimal Linux) returns
    PASS-with-skip per the existing check_d_no_orphan_core pattern.
    """
    socket_path = _resolve_socket_path()
    if not socket_path.exists():
        return CheckResult(
            "(g) no dup binders",
            True,
            "no socket file (skip)",
        )
    try:
        # -U: AF_UNIX only; -F pn: machine-parseable, p-prefix=PID, n-prefix=name
        result = subprocess.run(
            ["lsof", "-U", "-F", "pn"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return CheckResult(
            "(g) no dup binders",
            True,
            f"lsof unavailable: {e} (skip)",
        )
    binder_pids = _extract_binder_pids(result.stdout, socket_path)
    if len(binder_pids) <= 1:
        return CheckResult(
            "(g) no dup binders",
            True,
            f"{len(binder_pids)} binder(s)",
        )
    return CheckResult(
        "(g) no dup binders",
        False,
        f"{len(binder_pids)} processes bound to socket: {sorted(binder_pids)}",
    )


# -----------------------------------------------------------------------------
# — file-backed crypto-key state check
# -----------------------------------------------------------------------------


def check_h_crypto_file_state() -> CheckResult:
    """detect 'key file missing + Keychain entry exists' state.

    Detection matrix:
        | file present + valid | keyring entry | output |
        | yes                  | any           | PASS   |
        | no                   | yes           | WARN — `migrate-to-file` hint |
        | no                   | no/error      | PASS   (clean fresh-install state) |
        | yes (malformed)      | any           | FAIL   (CryptoKeyError detail)     |

    Imports of ``iai_mcp.crypto`` and ``keyring`` are LOCAL (function-scope)
    so the doctor module stays keyring-clean unless this check actually runs.
    Production daemon boot does NOT import ``keyring`` ;
    only the doctor's diagnostic-time probe does.

    WARN rows return ``passed=True`` (advisory only) — see ``CheckResult``
    docstring. The exit code stays 0 when only WARNs are present; ``cmd_doctor``
    prints a top-of-output remediation hint via ``_format_top_of_output_hint``.
    """
    # LOCAL imports keep the doctor module's footprint clean.
    from iai_mcp.crypto import CryptoKey, CryptoKeyError, SERVICE_NAME_DEFAULT

    ck = CryptoKey(user_id="default")
    path = ck._key_file_path()

    # Branch 1: file exists — validate via _try_file_get (mode + uid + length).
    if path.exists():
        try:
            ck._try_file_get()
            return CheckResult(
                "(h) crypto key file state",
                True,
                f"crypto key file present at {path} (mode 0o600, valid)",
                status="PASS",
            )
        except CryptoKeyError as exc:
            return CheckResult(
                "(h) crypto key file state",
                False,
                f"crypto key file is malformed: {exc}",
                status="FAIL",
            )

    # Branch 2: file missing — probe keyring for a pre-Phase-07.10 entry.
    # LOCAL imports here too: keyring is not imported at module top of
    # doctor.py (invariant).
    keyring_has_key = False
    keyring_probe_failed = False
    try:
        import keyring as _keyring
        import keyring.errors as _keyring_errors
    except ImportError:
        _keyring = None
        _keyring_errors = None  # type: ignore[assignment]

    if _keyring is not None:
        try:
            existing = _keyring.get_password(SERVICE_NAME_DEFAULT, "default")
            keyring_has_key = existing is not None
        except _keyring_errors.NoKeyringError:
            # No backend (Linux without Secret Service, etc.) — clean state.
            pass
        except _keyring_errors.KeyringError:
            # Backend exists but the read failed — could be ACL hang in a
            # non-interactive context. Mark as probe-failed; still emit a
            # WARN so the user is informed.
            keyring_probe_failed = True
        except Exception:  # noqa: BLE001 — defensive against keyring backend quirks
            keyring_probe_failed = True

    if keyring_has_key:
        return CheckResult(
            "(h) crypto key file state",
            True,  # WARN does NOT flip exit code
            (
                f"crypto key file missing at {path}, but an OS keyring entry was found.\n"
                f"  Run `iai-mcp crypto migrate-to-file` from a Terminal to migrate the key."
            ),
            status="WARN",
        )
    if keyring_probe_failed:
        return CheckResult(
            "(h) crypto key file state",
            True,  # WARN does NOT flip exit code
            (
                f"crypto key file missing at {path}; OS keyring (macOS Keychain / Linux SecretService) probe could not complete "
                f"(may indicate non-interactive context). If you have an existing OS keyring entry, "
                f"run `iai-mcp crypto migrate-to-file` from a Terminal."
            ),
            status="WARN",
        )

    # Branch 3: clean fresh-install state.
    return CheckResult(
        "(h) crypto key file state",
        True,
        (
            f"crypto key file absent at {path} and no OS keyring entry detected. "
            f"Fresh install — run `iai-mcp crypto init` or set IAI_MCP_CRYPTO_PASSPHRASE."
        ),
        status="PASS",
    )


# -----------------------------------------------------------------------------
# [Wave2-Option-C] — Lance versions-count diagnostic row
# -----------------------------------------------------------------------------


def _resolve_records_lance_versions_dir() -> Path:
    """Return the canonical path of records.lance/_versions/ for the active store.

    Honors ``IAI_MCP_STORE`` env (test isolation + multi-tenant layout per
     LOCK precedent) before falling back to the default
    home-derived layout. Mirrors the resolution pattern in
    ``iai_mcp.store.MemoryStore.__init__`` (line 205-206) so the doctor row
    inspects the SAME directory the daemon would actually open.
    """
    env_path = os.environ.get("IAI_MCP_STORE")
    root = Path(env_path) if env_path else (Path.home() / ".iai-mcp")
    return root / "lancedb" / "records.lance" / "_versions"


def check_i_lance_versions_count() -> CheckResult:
    """(i) records.lance versions count: PASS <=500, WARN 501..2000, FAIL >2000.

    [Wave2-Option-C] diagnostic row. The root-cause
    attack drained ``~/.iai-mcp/lancedb/records.lance/_versions/`` from 7298
    manifests to a small constant (Wave 1 compaction). This check warns the
    user before the pile re-accumulates to a daemon-boot-stalling scale.

    Resolution honors ``IAI_MCP_STORE`` env (test isolation + multi-tenant)
    before falling back to ``~/.iai-mcp``; mirrors ``MemoryStore.__init__``.

    Status thresholds:
      - PASS: ``count <= 500`` -- healthy steady state.
      - WARN: ``501 <= count <= 2000`` -- recommend ``iai-mcp maintenance
        compact-records --apply --yes`` at next quiet window.
      - FAIL: ``count > 2000`` -- daemon boot-bind will be slow (>10 s);
        recommend immediate compaction.

    Edge cases:
      - ``records.lance/_versions/`` directory absent (fresh install,
        store never written) -> PASS with explanatory detail.
      - ``OSError`` while enumerating (permission denied, FUSE error) ->
        WARN with the error class+message; never FAIL on a probe error.

    INV-7 (CPU-near-zero idle) preserved: this check runs ONLY when the
    user invokes ``iai-mcp doctor`` -- no background polling, no daemon-side
    work.
    """
    versions_dir = _resolve_records_lance_versions_dir()
    if not versions_dir.exists():
        return CheckResult(
            name="(i) lance versions count",
            passed=True,
            detail=f"{versions_dir} not present yet (fresh install or no writes yet)",
            status="PASS",
        )
    try:
        count = sum(1 for _ in versions_dir.glob("*.manifest"))
    except OSError as exc:
        return CheckResult(
            name="(i) lance versions count",
            passed=True,  # WARN, not FAIL: probe failure is advisory.
            detail=f"could not enumerate versions: {type(exc).__name__}: {exc}",
            status="WARN",
        )
    if count <= 500:
        return CheckResult(
            name="(i) lance versions count",
            passed=True,
            detail=f"{count} version manifest(s); healthy",
            status="PASS",
        )
    if count <= 2000:
        return CheckResult(
            name="(i) lance versions count",
            passed=True,  # WARN -- still passes the gate.
            detail=(
                f"{count} version manifests; consider running "
                f"`iai-mcp daemon stop && iai-mcp maintenance compact-records --apply --yes`"
            ),
            status="WARN",
        )
    return CheckResult(
        name="(i) lance versions count",
        passed=False,
        detail=(
            f"{count} version manifests (>2000); daemon boot will be slow. "
            f"Run `iai-mcp daemon stop && iai-mcp maintenance compact-records "
            f"--apply --yes && iai-mcp daemon start`."
        ),
        status="FAIL",
    )


# -----------------------------------------------------------------------------
# — daemon wake/sleep cycle diagnostic rows
# -----------------------------------------------------------------------------


def _resolve_wrappers_dir() -> Path:
    """Return the canonical path of the wrapper heartbeat directory.

    Honors ``IAI_MCP_STORE`` env (test isolation + multi-tenant layout per
     LOCK precedent) before falling back to ``~/.iai-mcp``.
    The heartbeat scanner watches ``<root>/wrappers/`` for the per-wrapper
    ``heartbeat-<pid>-<uuid>.json`` files written by the MCP wrapper.
    """
    env_path = os.environ.get("IAI_MCP_STORE")
    root = Path(env_path) if env_path else (Path.home() / ".iai-mcp")
    return root / "wrappers"


def check_m_heartbeat_scanner() -> CheckResult:
    """(m) heartbeat scanner health: PASS unless the wrappers dir is unreadable.

    L4 diagnostic row. The daemon's heartbeat scanner aggregates
    per-wrapper heartbeat files in ``~/.iai-mcp/wrappers/`` to decide WAKE
    vs. BEDTIME. This row surfaces the current per-status breakdown so the
    user can see at a glance whether stale / orphan files are accumulating.

    Status rules:
      - PASS: wrappers dir absent (fresh install) OR scan succeeds.
      - FAIL: wrappers dir exists but cannot be enumerated (permission /
        FUSE error). The probe failure is reported with the error class so
        the user can correct the underlying filesystem issue.

    Display: ``"n=3 fresh, 1 stale, 0 orphan"``. STALE / ORPHAN counts are
    reported even though they are advisory — they indicate to the user that
    a wrapper crashed without cleaning up, which is a benign but
    diagnostically interesting state.
    """
    from iai_mcp.heartbeat_scanner import HeartbeatScanner, HeartbeatStatus

    wrappers_dir = _resolve_wrappers_dir()
    if not wrappers_dir.exists():
        return CheckResult(
            name="(m) heartbeat scanner",
            passed=True,
            detail=(
                f"{wrappers_dir} not present yet (fresh install or no "
                "wrapper has refreshed yet)"
            ),
            status="PASS",
        )

    scanner = HeartbeatScanner(wrappers_dir)
    try:
        entries = scanner.scan()
    except OSError as exc:
        return CheckResult(
            name="(m) heartbeat scanner",
            passed=False,
            detail=(
                f"could not scan {wrappers_dir}: "
                f"{type(exc).__name__}: {exc}"
            ),
            status="FAIL",
        )

    fresh = sum(1 for e in entries if e.status is HeartbeatStatus.FRESH)
    stale = sum(1 for e in entries if e.status is HeartbeatStatus.STALE)
    orphan = sum(1 for e in entries if e.status is HeartbeatStatus.ORPHAN)
    return CheckResult(
        name="(m) heartbeat scanner",
        passed=True,
        detail=f"n={fresh} fresh, {stale} stale, {orphan} orphan",
        status="PASS",
    )


def _resolve_lifecycle_state_path() -> Path:
    """Return the path of ``lifecycle_state.json`` honoring IAI_MCP_STORE.

    Mirrors the pattern in ``_resolve_wrappers_dir`` so the
    doctor rows behave consistently with the heartbeat-scanner row when
    the user runs under a non-default store path.
    """
    env_path = os.environ.get("IAI_MCP_STORE")
    root = Path(env_path) if env_path else (Path.home() / ".iai-mcp")
    return root / "lifecycle_state.json"


def _resolve_lifecycle_log_dir() -> Path:
    """Return the directory of lifecycle event-log JSONL files."""
    env_path = os.environ.get("IAI_MCP_STORE")
    root = Path(env_path) if env_path else (Path.home() / ".iai-mcp")
    return root / "logs"


def _format_relative_short(ts_iso: str, *, now: Any = None) -> str:
    """Return a short elapsed-string ("12 min", "3 h", "2 d") for a UTC ts.

    Doctor uses a tighter format than `cli._format_relative` because each
    row prints on a single 80-col line; the trailing units stay singular
    ("min" not "minutes") to keep the alignment tight.
    """
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    try:
        ts = _dt.fromisoformat(ts_iso)
    except (TypeError, ValueError):
        return "?"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_tz.utc)
    moment = now if now is not None else _dt.now(_tz.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_tz.utc)
    seconds = int((moment - ts).total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} h"
    days = hours // 24
    return f"{days} d"


def check_j_lifecycle_current_state() -> CheckResult:
    """(j) lifecycle current state.

    L2 visibility. Reads ``lifecycle_state.json`` and reports
    the current state plus how long the daemon has been in it. Always
    PASS — the row is informational, not a health gate. The state file
    self-heals on missing/corrupt content (returns default WAKE), so
    this row never fails on a fresh install.
    """
    from iai_mcp.lifecycle_state import load_state

    state_path = _resolve_lifecycle_state_path()
    record = load_state(state_path)
    current = record.get("current_state", "WAKE")
    since_ts = record.get("since_ts", "?")
    elapsed = _format_relative_short(since_ts)
    shadow_run = record.get("shadow_run", True)

    detail = f"{current} since {elapsed} (shadow_run={'true' if shadow_run else 'false'})"
    return CheckResult(
        name="(j) lifecycle current state",
        passed=True,
        detail=detail,
        status="PASS",
    )


def check_k_lifecycle_history_24h() -> CheckResult:
    """(k) lifecycle history 24h.

    L4 visibility. Counts state-transition events in today's
    + yesterday's lifecycle event-log JSONL files, broken down by
    Wake/Sleep cycles. INFO row — always PASS.

    Implementation: parse ``lifecycle-events-YYYY-MM-DD.jsonl`` for
    today + yesterday (UTC), filter ``event=='state_transition'``,
    aggregate counts. Files absent / unparseable -> "0 transitions"
    rather than failure. The 24h window is approximate (UTC-day-bucket
    so a transition at 23:59 yesterday + 00:01 today is a 2-event
    window); precise sliding 24h is not needed for the operator
    summary.
    """
    from datetime import datetime as _dt
    from datetime import timedelta as _td
    from datetime import timezone as _tz

    from iai_mcp.lifecycle_event_log import LifecycleEventLog

    log_dir = _resolve_lifecycle_log_dir()
    if not log_dir.exists():
        return CheckResult(
            name="(k) lifecycle history 24h",
            passed=True,
            detail="no event log yet (fresh install or daemon never run)",
            status="PASS",
        )

    log = LifecycleEventLog(log_dir=log_dir)
    now = _dt.now(_tz.utc)
    today = now.strftime("%Y-%m-%d")
    yesterday = (now - _td(days=1)).strftime("%Y-%m-%d")

    transitions: list[dict[str, Any]] = []
    for date_str in (yesterday, today):
        try:
            events = log.read_all(date_str=date_str)
        except OSError:
            continue
        for ev in events:
            if ev.get("event") == "state_transition":
                transitions.append(ev)

    # Bucket transitions by destination state for a quick summary.
    counts: dict[str, int] = {}
    for ev in transitions:
        to = ev.get("to") or "?"
        counts[to] = counts.get(to, 0) + 1

    if not transitions:
        return CheckResult(
            name="(k) lifecycle history 24h",
            passed=True,
            detail="0 transitions in last 24h",
            status="PASS",
        )

    summary = ", ".join(f"{state}={n}" for state, n in sorted(counts.items()))
    return CheckResult(
        name="(k) lifecycle history 24h",
        passed=True,
        detail=f"{len(transitions)} transitions ({summary})",
        status="PASS",
    )


def check_l_sleep_cycle_status() -> CheckResult:
    """(l) sleep cycle quarantine status.

    L3 visibility. Reads ``lifecycle_state.json.quarantine``
    sub-record. Status rules:

      - PASS: ``quarantine`` is None / absent (sleep pipeline healthy).
      - PASS: ``quarantine`` present but ``until_ts`` already in the
        past (auto-recovery will clear it on next ``run()``).
      - WARN: ``quarantine`` active for less than 12 hours.
      - FAIL: ``quarantine`` active 12 hours or more (operator should
        run ``iai-mcp maintenance sleep-cycle --reset-quarantine``).
    """
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from iai_mcp.lifecycle_state import load_state

    state_path = _resolve_lifecycle_state_path()
    record = load_state(state_path)
    quarantine = record.get("quarantine")
    if quarantine is None:
        return CheckResult(
            name="(l) sleep cycle quarantine",
            passed=True,
            detail="no quarantine active",
            status="PASS",
        )

    reason = quarantine.get("reason", "?")
    until_ts = quarantine.get("until_ts", "?")
    since_ts = quarantine.get("since_ts", "?")

    # Compute age since quarantine entered.
    now = _dt.now(_tz.utc)
    try:
        since = _dt.fromisoformat(since_ts)
        if since.tzinfo is None:
            since = since.replace(tzinfo=_tz.utc)
        age_hours = (now - since).total_seconds() / 3600.0
    except (TypeError, ValueError):
        age_hours = 0.0

    # Auto-recovery branch: until_ts already in the past.
    try:
        until = _dt.fromisoformat(until_ts)
        if until.tzinfo is None:
            until = until.replace(tzinfo=_tz.utc)
        expired = until <= now
    except (TypeError, ValueError):
        expired = False

    if expired:
        return CheckResult(
            name="(l) sleep cycle quarantine",
            passed=True,
            detail=(
                f"quarantine expired (until={until_ts}); will clear on next "
                f"sleep-cycle run; reason={reason}"
            ),
            status="PASS",
        )

    detail = (
        f"quarantined for {age_hours:.1f}h; until={until_ts}; reason={reason}"
    )

    if age_hours >= 12.0:
        return CheckResult(
            name="(l) sleep cycle quarantine",
            passed=False,
            detail=(
                f"{detail}; run `iai-mcp maintenance sleep-cycle "
                "--reset-quarantine` to clear"
            ),
            status="FAIL",
        )
    return CheckResult(
        name="(l) sleep cycle quarantine",
        passed=True,  # WARN is advisory; does not flip exit code.
        detail=detail,
        status="WARN",
    )


def check_n_hid_idle_source() -> CheckResult:
    """(n) idle source health: PASS if any hardware idle signal present, WARN if not.

    L6 diagnostic row. Reports which hardware-grounded idle
    signals are reachable on the current host. ``HIDIdleTime`` (via
    ``ioreg -c IOHIDSystem``) is the primary signal on macOS; ``pmset -g log``
    is the secondary System/Display Sleep event source on macOS. On Linux,
    ``logind_idle`` (via ``loginctl show-session``) provides the idle time.

    Status rules:
      - PASS: ``available_signals`` is non-empty (any hardware source present).
      - WARN: signal list empty (will fall back to heartbeat-only L6 — the
        daemon stays correct but loses the hardware backstop). Advisory
        only — does NOT flip the doctor exit code (mirrors check_i WARN).

    Display includes the current idle value and available signal names so
    the user can see what the L6 sleep predicate is evaluating right now.
    """
    from iai_mcp.idle_detector import IdleDetector

    detector = IdleDetector()
    status = detector.status()

    idle_str = (
        f"{status.hid_idle_sec}s"
        if status.hid_idle_sec is not None
        else "unavailable"
    )
    suspend_str = "recent-sleep" if status.pmset_recent_sleep else "clean"
    signals_str = (
        ",".join(status.available_signals) if status.available_signals else "none"
    )
    detail = (
        f"idle: {idle_str}, suspend: {suspend_str}, available: {signals_str}"
    )

    if status.available_signals:
        return CheckResult(
            name="(n) HID idle source",
            passed=True,
            detail=detail,
            status="PASS",
        )
    return CheckResult(
        name="(n) HID idle source",
        passed=True,  # WARN — advisory only, does not flip exit code.
        detail=(
            f"{detail}; L6 will fall back to heartbeat-idle only"
        ),
        status="WARN",
    )


def _format_top_of_output_hint(results: list[CheckResult]) -> str | None:
    """Return a `> hint:` line for any WARN row from check_h, else None.

    the migration remediation must surface at the TOP of
    doctor's output (above the row-by-row print) so a user running
    ``iai-mcp doctor`` after upgrading from a Keychain-backed install
    sees the fix BEFORE they hit the eight-row checklist.

    The detail of the WARN row is multi-line (first line = state description,
    second line = actionable command). The hint flattens both lines into a
    single output line so the actionable command is visible at the top —
    a one-liner that omits the command would be useless.
    """
    for r in results:
        if r.name == "(h) crypto key file state" and r.status == "WARN":
            # Flatten the multi-line detail into a single hint line — strip
            # leading whitespace so the actionable command does not lose
            # readability when concatenated.
            flat = " ".join(line.strip() for line in r.detail.splitlines() if line.strip())
            return f"> hint: {flat}"
    return None


def run_diagnosis() -> list[CheckResult]:
    """Execute all checks in D7-11///07.14-03/10.4 order, returning the result list.

    R6 added (g) no dup binders as the 7th check.
    added (h) crypto key file state as the 8th check (placed
    after the network/process rows so the crypto-key check is most useful
    AFTER you know the daemon's filesystem side is healthy).
    [Wave2-Option-C] added (i) lance versions count as the 9th
    check (placed last; the records.lance pile is a slow-growing diagnostic
    rather than a hard failure mode and benefits from being seen alongside
    the file-backed-crypto state, since both are filesystem-shape signals).
    added (m) heartbeat scanner and (n) HID idle source as the
    10th and 11th checks for the daemon wake/sleep cycle.
    Task 1.3 added (j) lifecycle current state,
    (k) lifecycle history 24h, and (l) sleep cycle quarantine as the
    10th, 11th, and 12th checks (placed after (i) and before (m)/(n) so
    the lifecycle-machine rows form a contiguous block in the output).
    Final order: a, b, c, d, e, f, g, h, i, j, k, l, m, n -- 14 rows.
    """
    return [
        check_a_daemon_alive(),
        check_b_socket_fresh(),
        check_c_lock_healthy(),
        check_d_no_orphan_core(),
        check_e_state_file_valid(),
        check_f_lancedb_readable(),
        check_g_no_dup_binders(),
        check_h_crypto_file_state(),
        check_i_lance_versions_count(),
        # lifecycle visibility.
        check_j_lifecycle_current_state(),
        check_k_lifecycle_history_24h(),
        check_l_sleep_cycle_status(),
        # wake/sleep cycle rows.
        check_m_heartbeat_scanner(),
        check_n_hid_idle_source(),
    ]


def print_checklist(results: list[CheckResult]) -> None:
    """Print the PASS/WARN/FAIL checklist in the format documented in
    the PASS/WARN/FAIL checklist format.
    """
    print("IAI-MCP Doctor — daemon health check\n")
    for r in results:
        # WARN tag is distinct from PASS/FAIL so the user
        # sees the advisory state at a glance.
        if r.status == "WARN":
            tag = "[WARN]"
        elif r.passed:
            tag = "[PASS]"
        else:
            tag = "[FAIL]"
        print(f"  {tag} {r.name:<40} {r.detail}")


# -----------------------------------------------------------------------------
# 3 repair actions (D7-12 ordering)
# -----------------------------------------------------------------------------


def _kill_orphan_cores() -> tuple[bool, str, int]:
    """Action 1: SIGTERM every iai_mcp.core process (verified by cmdline match).

    Wrong-PID-kill mitigation: only kills processes whose psutil cmdline
    contains the literal substring 'iai_mcp.core'. A recycled PID belonging
    to an unrelated process is skipped (its cmdline differs).
    """
    import psutil

    t0 = time.monotonic()
    killed: list[int] = []
    failed: list[tuple[int, str]] = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cl = " ".join(p.info.get("cmdline") or [])
            if "iai_mcp.core" not in cl:
                continue
            pid = p.info["pid"]
            # Wrong-PID-kill mitigation: cmdline is verified above; signal
            # the live PID. SIGTERM (not SIGKILL) gives the core a chance to
            # finalize any in-flight LanceDB writes.
            os.kill(pid, signal.SIGTERM)
            killed.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except OSError as e:
            failed.append((p.info.get("pid", -1), str(e)))
    duration_ms = int((time.monotonic() - t0) * 1000)
    if failed:
        return (
            False,
            f"killed {len(killed)} ({killed}); FAILED on {failed}",
            duration_ms,
        )
    return True, f"killed {len(killed)} orphan(s): {killed}", duration_ms


def _unlink_stale_socket() -> tuple[bool, str, int]:
    """Action 2: unlink ~/.iai-mcp/.daemon.sock (or env-resolved path) if present.

    C4 CLEAN UNINSTALL: doctor only unlinks the socket file. Lock file +
    state file are owned by `iai-mcp daemon uninstall`.
    """
    socket_path = _resolve_socket_path()
    t0 = time.monotonic()
    if not socket_path.exists():
        return True, "no stale socket to unlink", int((time.monotonic() - t0) * 1000)
    try:
        socket_path.unlink()
        return True, f"unlinked {socket_path}", int((time.monotonic() - t0) * 1000)
    except OSError as e:
        return False, f"unlink failed: {e}", int((time.monotonic() - t0) * 1000)


def _respawn_daemon() -> tuple[bool, str, int]:
    """Action 3: spawn `python -m iai_mcp.daemon` detached.

    No-op-with-sleep when launchd plist is present AND we are using the
    default (home-derived) socket path: launchd's KeepAlive will respawn
    the daemon within 1-2s on macOS, so we yield rather than double-spawn.
    On Linux, if the systemd service unit is installed and using the default
    socket path, start the socket unit (idempotent socket activation) and
    yield to systemd.
    If IAI_DAEMON_SOCKET_PATH is set to a non-default value (test isolation
    or developer custom session), neither launchd nor systemd can resurrect
    THIS daemon — manual respawn is required.

    Manual respawn passes os.environ.copy() so IAI_DAEMON_SOCKET_PATH +
    IAI_MCP_STORE propagate to the child process. Without env propagation,
    test recovery would always spawn against the user's real ~/.iai-mcp/
    paths — the env-isolation contract from LOCK.
    """
    import platform as _plat

    from iai_mcp.cli import LAUNCHD_TARGET, SYSTEMD_TARGET

    t0 = time.monotonic()
    socket_path = _resolve_socket_path()

    # launchd-managed: yield to KeepAlive ONLY if the user is targeting the
    # default socket path. A custom IAI_DAEMON_SOCKET_PATH means launchd's
    # plist (which has no env overrides) cannot revive this daemon — fall
    # through to manual respawn.
    using_default_socket = os.environ.get("IAI_DAEMON_SOCKET_PATH") is None
    if (
        using_default_socket
        and LAUNCHD_TARGET
        and Path(LAUNCHD_TARGET).expanduser().exists()
    ):
        time.sleep(_LAUNCHD_REACT_DELAY_SEC)
        return (
            True,
            "launchd-managed (KeepAlive will respawn)",
            int((time.monotonic() - t0) * 1000),
        )

    # systemd-managed: call `systemctl --user start iai-mcp-daemon.socket`
    # which is idempotent and immediately triggers socket activation.
    if using_default_socket and _plat.system() == "Linux":
        try:
            _target_path = Path(SYSTEMD_TARGET).expanduser()
        except Exception:
            _target_path = None
        if _target_path and _target_path.exists():
            try:
                subprocess.run(
                    ["systemctl", "--user", "start", "iai-mcp-daemon.socket"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
            return (
                True,
                "systemd-managed (socket unit started, will activate daemon)",
                int((time.monotonic() - t0) * 1000),
            )

    try:
        subprocess.Popen(
            [sys.executable, "-m", "iai_mcp.daemon"],
            env=os.environ.copy(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:  # noqa: BLE001 — spawn failure is a recovery error
        return (
            False,
            f"respawn failed: {type(e).__name__}: {e}",
            int((time.monotonic() - t0) * 1000),
        )

    # Wait for the bind. bge-small first-load is 3-10s on cold cache plus
    # LanceDB open ~1s; an 8s budget covers most warm-cache machines and
    # is supplemented by a final re-check in cmd_doctor.
    deadline = time.monotonic() + _RESPAWN_BIND_TIMEOUT_SEC
    while time.monotonic() < deadline:
        if socket_path.exists():
            duration_ms = int((time.monotonic() - t0) * 1000)
            return (
                True,
                f"daemon respawned (socket bound in {duration_ms} ms)",
                duration_ms,
            )
        time.sleep(_RESPAWN_POLL_INTERVAL_SEC)
    duration_ms = int((time.monotonic() - t0) * 1000)
    return (
        False,
        f"daemon respawn timed out (socket not bound after {_RESPAWN_BIND_TIMEOUT_SEC}s)",
        duration_ms,
    )


def _kill_dup_binders() -> tuple[bool, str, int]:
    """repair action: keep oldest-etime binder, SIGKILL the rest.

    Identifies binders via lsof -F pn, sorts by psutil create_time ascending
    (oldest process = max etime = most accumulated client traffic), keeps
    that one, SIGKILLs the rest.

    Wrong-PID-kill mitigation: only kills processes whose psutil cmdline
    contains the literal substring 'iai_mcp.daemon' — anyone running 2 daemons
    against the SAME socket file is by definition violating singleton, but the
    cmdline filter still protects against PID reuse (a recycled PID belonging
    to an unrelated process is skipped).

    Race tolerance: processes that disappear between lsof enumeration and
    psutil.Process(pid) construction are silently skipped (NoSuchProcess /
    AccessDenied caught) — the natural concurrency between detection and
    repair MUST NOT crash the doctor.
    """
    import psutil

    t0 = time.monotonic()
    socket_path = _resolve_socket_path()
    try:
        result = subprocess.run(
            ["lsof", "-U", "-F", "pn"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return (
            False,
            f"lsof unavailable: {e}",
            int((time.monotonic() - t0) * 1000),
        )
    binder_pids = _extract_binder_pids(result.stdout, socket_path)
    if len(binder_pids) <= 1:
        return (
            True,
            f"{len(binder_pids)} dup binders to kill",
            int((time.monotonic() - t0) * 1000),
        )

    # Compute etime for each PID; "oldest" = max(time.time() - create_time).
    # Skip PIDs that disappear between lsof and psutil (race).
    pid_etimes: list[tuple[int, float]] = []
    for pid in binder_pids:
        try:
            p = psutil.Process(pid)
            create_time = p.create_time()  # epoch seconds
            pid_etimes.append((pid, time.time() - create_time))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not pid_etimes:
        return (
            False,
            "all binders disappeared between lsof and psutil",
            int((time.monotonic() - t0) * 1000),
        )

    # Sort longest-etime first; keep the oldest, kill the rest.
    pid_etimes.sort(key=lambda x: x[1], reverse=True)
    keep_pid = pid_etimes[0][0]
    kill_candidates = [pid for pid, _ in pid_etimes[1:]]

    killed: list[int] = []
    for pid in kill_candidates:
        try:
            p = psutil.Process(pid)
            cmdline = " ".join(p.cmdline() or [])
            if "iai_mcp.daemon" not in cmdline:
                # Wrong-PID-kill mitigation: never SIGKILL a non-daemon process,
                # even if lsof reported it bound to our socket path (PID reuse).
                continue
            p.kill()  # SIGKILL — these are stuck duplicate binders
            killed.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Let the kills settle so a follow-up check_g sees the post-kill state.
    time.sleep(_LAUNCHD_REACT_DELAY_SEC)
    return (
        True,
        f"kept PID {keep_pid} (oldest); killed {killed}",
        int((time.monotonic() - t0) * 1000),
    )


def _plan_repair_actions(results: list[CheckResult]) -> list[RepairAction]:
    """Map FAIL checks to repair actions in revised order.

     ordering (revises D7-12):
      1. unlink stale socket  (lets next bind succeed cleanly)
      2. kill dup binders     (NEW — R6 multi-binder cleanup)
      3. kill orphan cores    (frees lancedb write-locks held by stale cores)
      4. respawn daemon       (binds fresh)
    """
    actions: list[RepairAction] = []
    fail_names = {r.name for r in results if not r.passed}

    if "(b) socket file fresh" in fail_names:
        actions.append(
            RepairAction(
                label="unlink_stale_socket",
                description="unlink stale ~/.iai-mcp/.daemon.sock",
                destructive=True,
                execute=_unlink_stale_socket,
            )
        )

    if "(g) no dup binders" in fail_names:
        actions.append(
            RepairAction(
                label="kill_dup_binders",
                description="keep oldest-etime daemon binder, SIGKILL the rest",
                destructive=True,
                execute=_kill_dup_binders,
            )
        )

    if "(d) no orphan iai_mcp.core procs" in fail_names:
        actions.append(
            RepairAction(
                label="kill_orphan_cores",
                description="SIGTERM every orphan iai_mcp.core process",
                destructive=True,
                execute=_kill_orphan_cores,
            )
        )

    if "(a) daemon process alive" in fail_names:
        actions.append(
            RepairAction(
                label="respawn_daemon",
                description="spawn `python -m iai_mcp.daemon` detached",
                # Spawning a long-lived background process IS state-changing
                # (uses ~1.2GB RAM, holds the socket, runs REM cycles). Treat
                # as destructive so --apply (without --yes) prompts the user.
                # Without this, an unprompted respawn could surprise users who
                # ran `--apply` to see what it WOULD do.
                destructive=True,
                execute=_respawn_daemon,
            )
        )

    return actions


def _prompt_action(action: RepairAction) -> bool:
    """Strict 'y' confirmation prompt; EOFError-safe.

    Pattern lifted from cli.cmd_daemon_uninstall: EOFError on
    closed stdin returns empty string → False. Empty / 'n' / anything-else
    → False. Only literal lowercase 'y' (after strip) → True.
    """
    try:
        response = input(f"  [y/N] {action.description}: ")
    except EOFError:
        response = ""
    return response.strip().lower() == "y"


# -----------------------------------------------------------------------------
# CLI dispatch entry point
# -----------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    """R9/R6 dispatch: 8-check diagnosis + optional 4-action repair sequence
    (8th row + top-of-output migration hint)."""
    apply = bool(getattr(args, "apply", False))
    yes = bool(getattr(args, "yes", False))
    if yes and not apply:
        print(
            "[warn] --yes without --apply is meaningless; ignoring --yes.",
            file=sys.stderr,
        )

    # diagnosis (read-only, always runs).
    results = run_diagnosis()
    total = len(results)
    # surface the migration remediation at the TOP, before
    # the row-by-row print, so users upgrading from a Keychain-backed install
    # see the fix before they parse the checklist.
    hint = _format_top_of_output_hint(results)
    if hint is not None:
        print(hint)
        print()
    print_checklist(results)
    fail_count = sum(1 for r in results if not r.passed)

    if fail_count == 0:
        print("\nAll checks passed. Exit 0.")
        return 0

    if not apply:
        print(
            f"\n{fail_count}/{total} FAIL. Run with --apply to attempt recovery. Exit 1."
        )
        return 1

    # --apply repair sequence ( revised ordering).
    print(
        f"\n{fail_count}/{total} FAIL. Attempting recovery (--apply{' --yes' if yes else ''}):\n"
    )
    actions = _plan_repair_actions(results)
    if not actions:
        print(
            "(no automated repair actions for the FAILs above; manual intervention required)"
        )
    for action in actions:
        if action.destructive and not yes:
            if not _prompt_action(action):
                print(f"  [skipped] {action.description}")
                continue
        ok, msg, ms = action.execute()
        tag = "[done]" if ok else "[FAIL]"
        print(f"  {tag} {action.label}: {msg} ({ms} ms)")
        # Audit-trail event (D7-12). Audit must NEVER block recovery — wrap
        # in a broad try/except and silently swallow any failure (lancedb may
        # be unreadable per check (f) FAIL).
        try:
            from iai_mcp.events import write_event
            from iai_mcp.store import MemoryStore

            write_event(
                MemoryStore(),
                kind="doctor_action",
                data={
                    "action": action.label,
                    "target": action.description,
                    "success": ok,
                    "duration_ms": ms,
                    "detail": msg,
                },
            )
        except Exception:
            pass

    # re-run all checks.
    print("\nRe-running checks ...")
    final_results = run_diagnosis()
    print_checklist(final_results)
    final_fails = [r.name for r in final_results if not r.passed]
    if not final_fails:
        print(f"\nFIXED. All {len(final_results)} checks pass. Exit 0.")
        return 0
    print(f"\nSTILL BROKEN: {final_fails}. Exit 2.")
    return 2
