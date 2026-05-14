"""Wave 5 R9/A11 acceptance — `iai-mcp doctor --apply --yes`
recovers from `kill -9 <daemon_pid>`.

Flow:
  1. Spawn a real `python -m iai_mcp.daemon` against an isolated tmp socket
     (HIGH-4 LOCK pattern: IAI_DAEMON_SOCKET_PATH + IAI_MCP_STORE + HOME
     env propagation isolates state file too).
  2. Wait for socket bind + state file with daemon_pid populated.
  3. SIGKILL the daemon.
  4. Run `cmd_doctor(args)` with apply=True, yes=True.
  5. Assert: rc=0, post-recovery checks all PASS, doctor_action events
     written to the events ledger, total elapsed time within budget.

A11 budget: SPEC says ≤5 s recovery on warm cache. Test uses 15 s safety
budget to absorb cold-cache bge-small load (~3-10 s) + LanceDB store open
(~1 s) + harness overhead — same precedent as cold-start tests.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest


# ---------------------------------------------------------------------------
# Fixture: full HIGH-4 LOCK isolation including HOME for state file
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_daemon_paths(tmp_path, monkeypatch):
    """HOME + socket + store env overrides isolate the daemon completely.

    Setting HOME=tmp_path makes both the test process and any spawned
    subprocess agree that ~/.iai-mcp/ resolves to tmp_path/.iai-mcp/.
    `daemon_state.STATE_PATH` is also monkeypatched in-process because it
    was bound at module import time before our HOME override.

    Returns (sock_path, state_path, store_dir, lock_path).
    """
    # Real ~/.iai-mcp lives outside tmp; create the parallel iai dir under tmp.
    iai_dir = tmp_path / ".iai-mcp"
    iai_dir.mkdir(parents=True, exist_ok=True)

    state_path = iai_dir / ".daemon-state.json"
    lock_path = iai_dir / ".lock"
    store_dir = iai_dir / "store"
    store_dir.mkdir(parents=True, exist_ok=True)

    # Socket lives under /tmp/iai-rec-<pid>-<n>/ (AF_UNIX 104-byte cap).
    sock_dir = Path(f"/tmp/iai-rec-{os.getpid()}-{id(tmp_path)}")
    sock_dir.mkdir(parents=True, exist_ok=True)
    sock_path = sock_dir / "d.sock"

    # CRITICAL: capture the user's real HF cache BEFORE we override HOME.
    # Otherwise the spawned daemon's prewarm step (sentence-transformers
    # bge-small load) sees an empty HF cache under tmp HOME and tries to
    # download the model from HuggingFace — a 60+ second hang. By
    # propagating HF_HOME explicitly, the daemon reuses the user's already-
    # cached model and prewarm completes in <1s.
    real_hf_home = Path.home() / ".cache" / "huggingface"

    # HOME propagates to subprocesses via os.environ.copy() — daemon's
    # daemon_state module reads Path.home() at import, so subprocess sees
    # the tmp HOME and writes to tmp_path/.iai-mcp/.daemon-state.json.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HF_HOME", str(real_hf_home))
    monkeypatch.setenv("IAI_DAEMON_SOCKET_PATH", str(sock_path))
    monkeypatch.setenv("IAI_MCP_STORE", str(store_dir))
    monkeypatch.setenv("IAI_DAEMON_IDLE_SHUTDOWN_SECS", "99999")
    # CRITICAL: force the keyring "fail" backend in the test process too,
    # so the doctor's `_respawn_daemon` audit-event write — which goes
    # through MemoryStore()._key() → crypto.get_or_create() → keyring —
    # triggers the D-GUARD passphrase fallback rather than hanging on
    # the macOS Security framework's interactive keychain prompt under
    # fresh HOME. The fixture's finally clause resets keyring's cached
    # backend so this isolation does NOT leak to subsequent tests.
    monkeypatch.setenv(
        "PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring"
    )
    monkeypatch.setenv("IAI_MCP_CRYPTO_PASSPHRASE", "test-recovery-passphrase")
    # Reset keyring's already-imported backend cache so PYTHON_KEYRING_BACKEND
    # takes effect in this process (keyring resolves backend at first
    # access and caches; without this nudge, the prior cache wins).
    # MemoryStore's per-instance _cached_key is fresh on every MemoryStore()
    # construction, so no module-level crypto cache reset is needed.
    import keyring.core

    keyring.core._keyring_backend = None

    # In-process: daemon_state.STATE_PATH was bound at import. Override it
    # so the doctor (running in this process) reads the same file the
    # spawned daemon writes to.
    from iai_mcp import cli, daemon_state

    monkeypatch.setattr(daemon_state, "STATE_PATH", state_path)
    monkeypatch.setattr(cli, "LOCK_PATH", lock_path)
    monkeypatch.setattr(cli, "SOCKET_PATH", sock_path)

    try:
        yield sock_path, state_path, store_dir, lock_path
    finally:
        # Aggressive cleanup: kill any test-spawned daemon by env match
        # (avoids touching the user's real production daemon).
        _kill_test_daemons(sock_path)
        try:
            if sock_path.exists():
                sock_path.unlink()
        except OSError:
            pass
        try:
            sock_dir.rmdir()
        except OSError:
            pass
        # Reset keyring backend so the fail-backend cache doesn't leak
        # into subsequent tests in the same pytest process. monkeypatch
        # already restored the env var; we just need to force keyring to
        # re-resolve on next access.
        import keyring.core

        keyring.core._keyring_backend = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _spawn_daemon(sock_path: Path, store_dir: Path, home: Path) -> subprocess.Popen:
    """Spawn `python -m iai_mcp.daemon` with the test's env propagated.

    Adds PYTHON_KEYRING_BACKEND + IAI_MCP_CRYPTO_PASSPHRASE explicitly here
    (NOT in the test process env) so the spawned daemon's first write_event
    call uses the D-GUARD passphrase fallback instead of hanging on the
    macOS Security framework's interactive keychain prompt. Setting these
    in-process would poison the test's keyring module cache.
    """
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["IAI_DAEMON_SOCKET_PATH"] = str(sock_path)
    env["IAI_MCP_STORE"] = str(store_dir)
    env["IAI_DAEMON_IDLE_SHUTDOWN_SECS"] = "99999"
    # Force fail-backend → passphrase fallback in the daemon subprocess.
    env["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.Keyring"
    env["IAI_MCP_CRYPTO_PASSPHRASE"] = "test-recovery-passphrase"
    return subprocess.Popen(
        [sys.executable, "-m", "iai_mcp.daemon"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_for_socket_and_pid(
    sock_path: Path, state_path: Path, expected_pid: int, timeout_sec: float = 30.0
) -> bool:
    """Poll until socket binds AND state file has daemon_pid == expected_pid."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if sock_path.exists() and state_path.exists():
            try:
                state = json.loads(state_path.read_text())
                if state.get("daemon_pid") == expected_pid:
                    return True
            except (OSError, json.JSONDecodeError):
                pass
        time.sleep(0.1)
    return False


def _wait_for_socket_only(sock_path: Path, timeout_sec: float = 15.0) -> bool:
    """Poll until socket binds (used after respawn to detect new daemon)."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if sock_path.exists():
            return True
        time.sleep(0.1)
    return False


def _kill_test_daemons(sock_path: Path) -> None:
    """Match-by-env cleanup: SIGTERM any iai_mcp.daemon subprocess whose
    psutil environ has our IAI_DAEMON_SOCKET_PATH value.

    Avoids killing the user's real production daemon (which has no env
    override or a different socket path).
    """
    target = str(sock_path)
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cl = " ".join(p.info.get("cmdline") or [])
            if "iai_mcp.daemon" not in cl:
                continue
            try:
                env = p.environ()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            if env.get("IAI_DAEMON_SOCKET_PATH") == target:
                try:
                    p.send_signal(signal.SIGTERM)
                    p.wait(timeout=3)
                except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                    try:
                        p.send_signal(signal.SIGKILL)
                    except psutil.NoSuchProcess:
                        pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


# ---------------------------------------------------------------------------
# Test 1: kill -9 → --apply --yes recovers within budget, all PASS, exit 0
# ---------------------------------------------------------------------------


def test_apply_yes_recovers_from_kill(isolated_daemon_paths):
    """R9/A11 acceptance: simulate kill -9 → cmd_doctor(apply=True, yes=True) →
    daemon respawns, socket reappears, all 6 checks PASS, exit 0; doctor_action
    events emitted to the events ledger.
    """
    sock_path, state_path, store_dir, _ = isolated_daemon_paths

    # Boot daemon #1.
    proc = _spawn_daemon(sock_path, store_dir, home=Path(os.environ["HOME"]))
    try:
        assert _wait_for_socket_and_pid(
            sock_path, state_path, proc.pid, timeout_sec=30
        ), (
            f"daemon never bound socket + stamped daemon_pid={proc.pid} within 30s"
        )

        original_pid = proc.pid

        # Pre-condition: doctor (no flags) should report at least (a) and (b)
        # FAIL after the kill (other checks may also fail, but those two are
        # the minimum diagnostic surface per A11).
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=5)
        time.sleep(0.5)  # let psutil reflect death

        from iai_mcp.doctor import cmd_doctor, run_diagnosis

        pre_results = run_diagnosis()
        pre_fail_names = [r.name for r in pre_results if not r.passed]
        assert "(a) daemon process alive" in pre_fail_names, (
            f"after kill, check (a) should FAIL; got fails: {pre_fail_names}"
        )
        assert "(b) socket file fresh" in pre_fail_names, (
            f"after kill, check (b) should FAIL; got fails: {pre_fail_names}"
        )

        # Run the recovery and time it.
        t0 = time.monotonic()
        args = argparse.Namespace(apply=True, yes=True)
        rc = cmd_doctor(args)
        elapsed = time.monotonic() - t0

        assert rc == 0, (
            f"doctor recovery returned rc={rc}, elapsed={elapsed:.2f}s "
            "— expected exit 0 (all PASS after recovery)"
        )
        # 15s safety budget covers cold-cache bge-small + LanceDB open +
        # harness overhead; SPEC A11 5s budget is verified by Wave 6
        # acceptance against the production warm-cache daemon.
        assert elapsed < 15.0, (
            f"doctor recovery took {elapsed:.2f}s, exceeds 15s safety budget"
        )

        # Post-condition: state file has a NEW daemon_pid (respawn worked).
        # NOTE: relying on run_diagnosis returning all-PASS already guarantees
        # check_a found a live iai_mcp.daemon at the stamped PID; the
        # original_pid != new_pid sanity check is belt-and-suspenders.
        assert state_path.exists(), "respawned daemon never wrote state file"
        s2 = json.loads(state_path.read_text())
        new_pid = s2.get("daemon_pid")
        assert new_pid is not None, "respawned daemon did not stamp daemon_pid"
        assert new_pid != original_pid, (
            f"daemon was not actually respawned: same PID {new_pid} after recovery"
        )

        post_results = run_diagnosis()
        post_fails = [r.name for r in post_results if not r.passed]
        assert post_fails == [], f"post-recovery FAILs remain: {post_fails}"

        # Audit events: at least one doctor_action event for the respawn.
        from iai_mcp.events import query_events
        from iai_mcp.store import MemoryStore

        store = MemoryStore()
        recent = query_events(store, kind="doctor_action", limit=10)
        assert len(recent) >= 1, (
            "doctor_action events not written to ledger after --apply"
        )
        # At minimum the respawn_daemon action must be present.
        action_labels = {e["data"].get("action") for e in recent}
        assert "respawn_daemon" in action_labels, (
            f"respawn_daemon event missing; saw actions: {action_labels}"
        )
    finally:
        # Best-effort cleanup of the original (already dead) + any respawned daemon.
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGKILL)
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                pass
        # _kill_test_daemons is also called by the fixture's finally clause.


# ---------------------------------------------------------------------------
# Test 2: --apply WITHOUT --yes prompts for each destructive action;
#         'n' answer skips the action and the FAIL persists → rc=2.
# ---------------------------------------------------------------------------


def test_apply_no_yes_skips_destructive_action_on_n_response(
    isolated_daemon_paths, monkeypatch
):
    """R9 UX: --apply without --yes presents [y/N] prompts; user typing 'n'
    skips the destructive action; the unfixed FAIL persists → rc=2.

    Setup: monkeypatch psutil.process_iter to fabricate one orphan
    iai_mcp.core hit (so check (d) FAILs and triggers the kill action).
    Then patch builtins.input to return 'n' so the [y/N] prompt
    deflects.
    """
    sock_path, _, _, _ = isolated_daemon_paths

    # Synthetic orphan: causes check (d) to FAIL, which schedules the
    # kill_orphan_cores destructive action.
    import psutil

    class _FakeProc:
        def __init__(self, pid: int, cmdline: list[str]):
            self.info = {"pid": pid, "cmdline": cmdline}

    fake = _FakeProc(99_999, ["python", "-m", "iai_mcp.core"])
    monkeypatch.setattr(psutil, "process_iter", lambda *a, **kw: [fake])

    # Auto-decline every input prompt.
    monkeypatch.setattr("builtins.input", lambda *a, **kw: "n")

    from iai_mcp.doctor import cmd_doctor

    args = argparse.Namespace(apply=True, yes=False)
    rc = cmd_doctor(args)

    # The orphan FAIL persists (we declined to fix it) and check (a)/(b)
    # also fail (no daemon running in the tmp env), so re-check still has
    # FAILs → rc=2.
    assert rc == 2, (
        f"declining destructive action should leave FAILs unfixed → rc=2; got {rc}"
    )


# ---------------------------------------------------------------------------
# Test 3: Linux systemd respawn branch
# ---------------------------------------------------------------------------


def test_respawn_daemon_linux_yields_to_systemd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Linux with SYSTEMD_TARGET present, _respawn_daemon calls systemctl start socket."""
    import platform
    import iai_mcp.doctor as doctor_mod
    import iai_mcp.cli as cli_mod

    # Set up fake SYSTEMD_TARGET that exists
    fake_unit = tmp_path / "iai-mcp-daemon.service"
    fake_unit.write_text("[Service]\n")
    monkeypatch.setattr(cli_mod, "SYSTEMD_TARGET", fake_unit)

    # Simulate Linux platform
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    # Ensure no custom socket path (default socket path)
    monkeypatch.delenv("IAI_DAEMON_SOCKET_PATH", raising=False)

    calls: list[list[str]] = []

    def _fake_run(argv, **kw):
        calls.append(list(argv))
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(doctor_mod.subprocess, "run", _fake_run)

    ok, msg, duration_ms = doctor_mod._respawn_daemon()

    assert ok is True
    assert "systemd" in msg.lower()
    assert any("systemctl" in " ".join(c) and "iai-mcp-daemon.socket" in " ".join(c) for c in calls), calls
