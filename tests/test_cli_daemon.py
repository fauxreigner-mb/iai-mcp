"""-- iai-mcp daemon subcommand group tests ( + ).

Verifies dispatcher wiring, install/uninstall flow with consent banner,
launchd / systemd template rendering with sys.executable substitution
(Pitfall 5), version skew detection in `daemon status`, and C4 clean uninstall
(removes plist/unit + all 3 state files).

All subprocess calls (launchctl, systemctl, loginctl, tail, journalctl) are
monkeypatched so the suite never touches the host's actual launchd/systemd.

Socket-talking subcommands (status / force-rem / pause / logs) are exercised
against the `_ThreadedFakeDaemon` helper (lifted from
tests/test_core_bedtime_inject.py pattern -- a fake daemon that survives
multiple asyncio.run() teardowns by running on a dedicated background loop).
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import platform
import sys
import tempfile
import threading
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

import pytest

from iai_mcp import cli as cli_mod


# ---------------------------------------------------------------------------
# Threaded fake daemon (survives multiple asyncio.run teardowns)
# ---------------------------------------------------------------------------


class _ThreadedFakeDaemon:
    """Fake daemon NDJSON server on a background loop.

    Each request line is captured. Each request gets `reply` written back
    (or a per-request reply via `reply_fn(req)` if provided).
    """

    def __init__(
        self,
        path: Path,
        captured: list,
        reply: dict | None = None,
        reply_fn=None,
    ) -> None:
        self.path = path
        self.captured = captured
        self.reply = reply
        self.reply_fn = reply_fn
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self) -> None:
        def _run() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            async def _handle(reader, writer):
                try:
                    line = await reader.readline()
                    if line:
                        req = json.loads(line.decode("utf-8"))
                        self.captured.append(req)
                        if self.reply_fn is not None:
                            resp = self.reply_fn(req)
                        else:
                            resp = self.reply or {}
                        writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                        await writer.drain()
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            async def _serve():
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._server = await asyncio.start_unix_server(
                    _handle, path=str(self.path),
                )
                self._ready.set()
                async with self._server:
                    await self._server.serve_forever()

            try:
                self._loop.run_until_complete(_serve())
            except asyncio.CancelledError:
                pass
            finally:
                self._loop.close()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        assert self._ready.wait(timeout=5.0), "fake daemon failed to start"

    def stop(self) -> None:
        loop = self._loop
        if loop is None:
            return

        async def _shutdown():
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()

        try:
            asyncio.run_coroutine_threadsafe(_shutdown(), loop).result(timeout=5.0)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def short_socket(tmp_path: Path) -> Path:
    """Short unix-socket path (macOS ~104-byte limit)."""
    candidate = tmp_path / "d.sock"
    if len(str(candidate)) > 100:
        candidate = Path(tempfile.mkdtemp(prefix="iai-clitest-")) / "d.sock"
    return candidate


@pytest.fixture
def fake_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ~/.iai-mcp + ~/Library/LaunchAgents + ~/.config/systemd/user
    to tmp_path-rooted equivalents, so install/uninstall never touches the
    real host filesystem."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    # Re-resolve the constants after Path.home() is patched.
    monkeypatch.setattr(
        cli_mod, "LOCK_PATH", fake_home / ".iai-mcp" / ".lock",
    )
    monkeypatch.setattr(
        cli_mod, "SOCKET_PATH", fake_home / ".iai-mcp" / ".daemon.sock",
    )
    monkeypatch.setattr(
        cli_mod, "STATE_PATH", fake_home / ".iai-mcp" / ".daemon-state.json",
    )
    monkeypatch.setattr(
        cli_mod,
        "LAUNCHD_TARGET",
        fake_home / "Library" / "LaunchAgents" / "com.iai-mcp.daemon.plist",
    )
    monkeypatch.setattr(
        cli_mod,
        "SYSTEMD_TARGET",
        fake_home / ".config" / "systemd" / "user" / "iai-mcp-daemon.service",
    )
    monkeypatch.setattr(
        cli_mod,
        "SYSTEMD_SOCKET_TARGET",
        fake_home / ".config" / "systemd" / "user" / "iai-mcp-daemon.socket",
    )
    return fake_home


# ---------------------------------------------------------------------------
# Test 1: dry-run does NOT write any file
# ---------------------------------------------------------------------------


def test_install_dry_run_writes_no_file(
    fake_state_dir: Path,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    rc = cli_mod.main(["daemon", "install", "--dry-run", "--yes"])
    assert rc == 0
    assert not cli_mod.LAUNCHD_TARGET.exists()
    out = capsys.readouterr().out
    assert "Would install to" in out
    # sys.executable is substituted in dry-run output
    assert sys.executable in out


# ---------------------------------------------------------------------------
# Test 2: install on macOS writes plist with sys.executable + invokes launchctl
# ---------------------------------------------------------------------------


def test_install_macos_writes_plist_with_sys_executable(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    calls: list[list[str]] = []

    def _fake_run(argv, **kwargs):
        calls.append(list(argv))
        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()

    monkeypatch.setattr(cli_mod.subprocess, "run", _fake_run)

    rc = cli_mod.main(["daemon", "install", "--yes"])
    assert rc == 0
    assert cli_mod.LAUNCHD_TARGET.exists()
    contents = cli_mod.LAUNCHD_TARGET.read_text()
    # Pitfall 5: absolute sys.executable substituted into plist
    assert sys.executable in contents
    # USERNAME placeholder substituted (not present literally)
    assert "{USERNAME}" not in contents
    # launchctl bootstrap + kickstart called
    assert any("bootstrap" in " ".join(c) for c in calls), calls
    assert any("kickstart" in " ".join(c) for c in calls), calls


# ---------------------------------------------------------------------------
# Test 3: install on Linux writes systemd unit + invokes systemctl + loginctl
# ---------------------------------------------------------------------------


def test_install_linux_writes_unit_and_invokes_systemctl(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setenv("USER", "testuser")
    calls: list[list[str]] = []

    def _fake_run(argv, **kwargs):
        calls.append(list(argv))
        class _R:
            returncode = 0
            # Simulate Linger=no on the first show-user, then Linger=yes after enable
            _show_count = [0]
            stdout = (
                "Linger=no" if argv[:2] == ["loginctl", "show-user"]
                else ""
            )
            stderr = ""
        return _R()

    monkeypatch.setattr(cli_mod.subprocess, "run", _fake_run)

    rc = cli_mod.main(["daemon", "install", "--yes"])
    assert rc == 0
    assert cli_mod.SYSTEMD_TARGET.exists()
    contents = cli_mod.SYSTEMD_TARGET.read_text()
    assert sys.executable in contents
    # loginctl invoked at least twice (show + enable + re-verify)
    loginctl_calls = [c for c in calls if c and c[0] == "loginctl"]
    assert len(loginctl_calls) >= 2, loginctl_calls
    # systemctl --user daemon-reload AND enable --now invoked
    cmd_strs = [" ".join(c) for c in calls]
    assert any("systemctl --user daemon-reload" in s for s in cmd_strs), cmd_strs
    assert any("systemctl --user enable --now iai-mcp-daemon.socket" in s for s in cmd_strs), cmd_strs
    assert cli_mod.SYSTEMD_SOCKET_TARGET.exists(), "socket unit file should be written"


def test_install_linux_writes_both_service_and_socket_units(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Install on Linux writes both .service and .socket unit files."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setenv("USER", "testuser")
    monkeypatch.setattr(
        cli_mod.subprocess, "run",
        lambda argv, **kw: type("R", (), {"returncode": 0, "stdout": "Linger=yes", "stderr": ""})(),
    )
    rc = cli_mod.main(["daemon", "install", "--yes"])
    assert rc == 0
    assert cli_mod.SYSTEMD_TARGET.exists(), "service unit must be written"
    assert cli_mod.SYSTEMD_SOCKET_TARGET.exists(), "socket unit must be written"
    # Socket unit should contain the ListenStream directive
    socket_contents = cli_mod.SYSTEMD_SOCKET_TARGET.read_text()
    assert "ListenStream" in socket_contents
    assert ".daemon.sock" in socket_contents


# ---------------------------------------------------------------------------
# Test 4: consent banner blocks on stdin; non-`y` responses abort
# ---------------------------------------------------------------------------


def test_install_without_yes_prompts_consent_banner_aborts(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    # Don't actually call subprocess
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
    )

    # Strict gate: ONLY exact lowercase "y" (after .strip()) proceeds.
    # Everything else -- empty, "n", "N", "yes", "no", "true", numeric -- aborts.
    for response in ["", "n", "N", "yes", "no", "true", "1", "0", "yeah", "nope"]:
        monkeypatch.setattr(
            "builtins.input", lambda _prompt="", r=response: r,
        )
        rc = cli_mod.main(["daemon", "install"])
        assert rc == 1, f"non-strict-y response {response!r} should abort"
        # State file should not exist (install did not proceed)
        assert not cli_mod.LAUNCHD_TARGET.exists()

    err = capsys.readouterr().err
    # Banner must mention key phrases.
    # Banner phrasing was updated 2026-04-19 (bge-small-en pivot):
    # "rises to ~2 GB if the opt-in bge-m3 model is selected" — with space.
    assert "~2 GB" in err or "2 GB" in err
    assert "1%" in err
    assert "iai-mcp daemon uninstall" in err


def test_install_with_lowercase_y_proceeds(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    rc = cli_mod.main(["daemon", "install"])
    assert rc == 0
    assert cli_mod.LAUNCHD_TARGET.exists()


def test_install_consent_records_audit_trail(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D-10 audit trail: explicit consent writes a timestamped JSON receipt
    under ~/.iai-mcp/.consent-*.json so a later forensic review can confirm
    the user actually consented (not bypassed via --yes)."""
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    rc = cli_mod.main(["daemon", "install"])
    assert rc == 0
    consent_files = list((fake_state_dir / ".iai-mcp").glob(".consent-*.json"))
    assert consent_files, "expected at least one .consent-<ts>.json audit receipt"
    payload = json.loads(consent_files[0].read_text())
    assert payload.get("consent") is True
    assert "ts" in payload


# ---------------------------------------------------------------------------
# Test 5: macOS uninstall removes plist + all 3 state files
# ---------------------------------------------------------------------------


def test_uninstall_macos_removes_plist_and_all_state_files(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    # Pre-seed the plist + 3 state files
    cli_mod.LAUNCHD_TARGET.parent.mkdir(parents=True, exist_ok=True)
    cli_mod.LAUNCHD_TARGET.write_text("<plist></plist>")
    state_dir = fake_state_dir / ".iai-mcp"
    state_dir.mkdir(parents=True, exist_ok=True)
    cli_mod.LOCK_PATH.write_text("")
    cli_mod.SOCKET_PATH.write_text("")
    cli_mod.STATE_PATH.write_text("{}")

    rc = cli_mod.main(["daemon", "uninstall", "--yes"])
    assert rc == 0
    # C4 invariant: all 4 artefacts gone
    assert not cli_mod.LAUNCHD_TARGET.exists()
    assert not cli_mod.LOCK_PATH.exists()
    assert not cli_mod.SOCKET_PATH.exists()
    assert not cli_mod.STATE_PATH.exists()


# ---------------------------------------------------------------------------
# Test 6: Linux uninstall removes unit + all 3 state files
# ---------------------------------------------------------------------------


def test_uninstall_linux_removes_unit_and_all_state_files(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()),
    )

    cli_mod.SYSTEMD_TARGET.parent.mkdir(parents=True, exist_ok=True)
    cli_mod.SYSTEMD_TARGET.write_text("[Service]")
    cli_mod.SYSTEMD_SOCKET_TARGET.parent.mkdir(parents=True, exist_ok=True)
    cli_mod.SYSTEMD_SOCKET_TARGET.write_text("[Socket]")
    state_dir = fake_state_dir / ".iai-mcp"
    state_dir.mkdir(parents=True, exist_ok=True)
    cli_mod.LOCK_PATH.write_text("")
    cli_mod.SOCKET_PATH.write_text("")
    cli_mod.STATE_PATH.write_text("{}")

    rc = cli_mod.main(["daemon", "uninstall", "--yes"])
    assert rc == 0
    assert not cli_mod.SYSTEMD_TARGET.exists()
    assert not cli_mod.SYSTEMD_SOCKET_TARGET.exists(), "socket unit should be removed"
    assert not cli_mod.LOCK_PATH.exists()
    assert not cli_mod.SOCKET_PATH.exists()
    assert not cli_mod.STATE_PATH.exists()
    cmd_strs = [" ".join(c) for c in calls]
    assert any("systemctl --user disable --now iai-mcp-daemon.service" in s for s in cmd_strs), cmd_strs
    assert any("systemctl --user disable --now iai-mcp-daemon.socket" in s for s in cmd_strs), cmd_strs


# ---------------------------------------------------------------------------
# Test 7: status round-trip + daemon-down message
# ---------------------------------------------------------------------------


def test_status_socket_round_trip(
    short_socket: Path,
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(cli_mod, "SOCKET_PATH", short_socket)
    captured: list[dict] = []
    daemon = _ThreadedFakeDaemon(
        short_socket,
        captured,
        reply={
            "ok": True,
            "state": "WAKE",
            "uptime_sec": 42.5,
            "version": "0.1.0",
        },
    )
    daemon.start()
    try:
        rc = cli_mod.main(["daemon", "status"])
        assert rc == 0
    finally:
        daemon.stop()

    out = capsys.readouterr().out
    assert "WAKE" in out
    assert "42" in out
    # request was sent
    assert captured == [{"type": "status"}]


def test_status_daemon_down(
    short_socket: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(cli_mod, "SOCKET_PATH", short_socket)
    assert not short_socket.exists()
    rc = cli_mod.main(["daemon", "status"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "daemon not running" in out


# ---------------------------------------------------------------------------
# Test 8: status version skew warns when daemon != installed
# ---------------------------------------------------------------------------


def test_status_warns_on_version_skew(
    short_socket: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(cli_mod, "SOCKET_PATH", short_socket)
    captured: list[dict] = []
    daemon = _ThreadedFakeDaemon(
        short_socket,
        captured,
        reply={
            "ok": True,
            "state": "WAKE",
            "version": "0.0.1-OLD",
        },
    )
    daemon.start()
    try:
        rc = cli_mod.main(["daemon", "status"])
        assert rc == 0
    finally:
        daemon.stop()

    err = capsys.readouterr().err
    assert "version" in err.lower()
    assert "0.0.1-OLD" in err
    assert "restart" in err.lower()


# ---------------------------------------------------------------------------
# Test 9: configure subcommands persist to state file
# ---------------------------------------------------------------------------


def test_configure_set_budget_persists(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # daemon_state.STATE_PATH must mirror our fake home for save_state to land
    # in the right place. We patch BOTH cli_mod.STATE_PATH AND the daemon_state
    # module's constant in one shot.
    from iai_mcp import daemon_state
    monkeypatch.setattr(daemon_state, "STATE_PATH", cli_mod.STATE_PATH)
    cli_mod.STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

    rc = cli_mod.main(["daemon", "configure", "set-budget", "0.02"])
    assert rc == 0
    state = json.loads(cli_mod.STATE_PATH.read_text())
    assert state["daily_quota_pct_override"] == pytest.approx(0.02)


def test_configure_set_cycle_count_persists(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iai_mcp import daemon_state
    monkeypatch.setattr(daemon_state, "STATE_PATH", cli_mod.STATE_PATH)
    cli_mod.STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    rc = cli_mod.main(["daemon", "configure", "set-cycle-count", "5"])
    assert rc == 0
    state = json.loads(cli_mod.STATE_PATH.read_text())
    assert state["cycle_count_override"] == 5


def test_configure_disable_host_persists(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iai_mcp import daemon_state
    monkeypatch.setattr(daemon_state, "STATE_PATH", cli_mod.STATE_PATH)
    cli_mod.STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    rc = cli_mod.main(["daemon", "configure", "disable-claude"])
    assert rc == 0
    state = json.loads(cli_mod.STATE_PATH.read_text())
    assert state["claude_enabled"] is False


# ---------------------------------------------------------------------------
# Test 10: force-rem socket message
# ---------------------------------------------------------------------------


def test_force_rem_sends_correct_message(
    short_socket: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_mod, "SOCKET_PATH", short_socket)
    captured: list[dict] = []
    daemon = _ThreadedFakeDaemon(
        short_socket, captured, reply={"ok": True, "cycles_completed": 1},
    )
    daemon.start()
    try:
        rc = cli_mod.main(["daemon", "force-rem"])
        assert rc == 0
    finally:
        daemon.stop()
    assert captured == [{"type": "force_rem"}]


# ---------------------------------------------------------------------------
# Test 11: pause N
# ---------------------------------------------------------------------------


def test_pause_sends_seconds_arg(
    short_socket: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_mod, "SOCKET_PATH", short_socket)
    captured: list[dict] = []
    daemon = _ThreadedFakeDaemon(short_socket, captured, reply={"ok": True})
    daemon.start()
    try:
        rc = cli_mod.main(["daemon", "pause", "300"])
        assert rc == 0
    finally:
        daemon.stop()
    assert captured == [{"type": "pause", "seconds": 300}]


def test_resume_sends_resume_message(
    short_socket: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_mod, "SOCKET_PATH", short_socket)
    captured: list[dict] = []
    daemon = _ThreadedFakeDaemon(short_socket, captured, reply={"ok": True})
    daemon.start()
    try:
        rc = cli_mod.main(["daemon", "resume"])
        assert rc == 0
    finally:
        daemon.stop()
    assert captured == [{"type": "resume"}]


# ---------------------------------------------------------------------------
# Test 12: start / stop dispatch correct argv on each platform
# ---------------------------------------------------------------------------


def test_start_macos_uses_launchctl_kickstart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0})()),
    )
    rc = cli_mod.main(["daemon", "start"])
    assert rc == 0
    cmd_strs = [" ".join(c) for c in calls]
    assert any("launchctl kickstart" in s for s in cmd_strs), cmd_strs


def test_stop_macos_uses_launchctl_kill_sigterm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0})()),
    )
    rc = cli_mod.main(["daemon", "stop"])
    assert rc == 0
    cmd_strs = [" ".join(c) for c in calls]
    assert any("launchctl kill SIGTERM" in s for s in cmd_strs), cmd_strs


def test_start_linux_uses_systemctl_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0})()),
    )
    rc = cli_mod.main(["daemon", "start"])
    assert rc == 0
    assert any(c[:4] == ["systemctl", "--user", "start", "iai-mcp-daemon.socket"] for c in calls), calls


def test_start_linux_uses_socket_unit(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """daemon start on Linux starts the socket unit, not the service."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess, "run",
        lambda argv, **kw: calls.append(list(argv)) or type("R", (), {"returncode": 0})(),
    )
    rc = cli_mod.main(["daemon", "start"])
    assert rc == 0
    assert any("iai-mcp-daemon.socket" in " ".join(c) for c in calls), calls


def test_stop_linux_uses_systemctl_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0})()),
    )
    rc = cli_mod.main(["daemon", "stop"])
    assert rc == 0
    assert any(c[:4] == ["systemctl", "--user", "stop", "iai-mcp-daemon.service"] for c in calls), calls


# ---------------------------------------------------------------------------
# Test 13: logs dispatches tail (macOS) or journalctl (Linux)
# ---------------------------------------------------------------------------


def test_logs_macos_invokes_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0})()),
    )
    rc = cli_mod.main(["daemon", "logs", "-n", "50"])
    assert rc == 0
    assert any(c and c[0] == "tail" for c in calls), calls


def test_logs_linux_invokes_journalctl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        cli_mod.subprocess,
        "run",
        lambda argv, **k: (calls.append(list(argv)) or type("R", (), {"returncode": 0})()),
    )
    rc = cli_mod.main(["daemon", "logs", "-n", "100"])
    assert rc == 0
    assert any(
        c[:5] == ["journalctl", "--user", "-u", "iai-mcp-daemon.service", "-n"]
        for c in calls
    ), calls


# ---------------------------------------------------------------------------
# Idempotency: install + install does not error
# ---------------------------------------------------------------------------


def test_install_twice_is_idempotent(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    assert cli_mod.main(["daemon", "install", "--yes"]) == 0
    assert cli_mod.main(["daemon", "install", "--yes"]) == 0
    assert cli_mod.LAUNCHD_TARGET.exists()


def test_uninstall_twice_is_idempotent(
    fake_state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    assert cli_mod.main(["daemon", "uninstall", "--yes"]) == 0
    assert cli_mod.main(["daemon", "uninstall", "--yes"]) == 0


# ---------------------------------------------------------------------------
# Help output sanity
# ---------------------------------------------------------------------------


def test_daemon_help_lists_all_subcommands(
    capsys: pytest.CaptureFixture,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_mod.main(["daemon", "--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    for sub in (
        "install",
        "uninstall",
        "start",
        "stop",
        "status",
        "logs",
        "force-rem",
        "pause",
        "resume",
        "configure",
    ):
        assert sub in out, f"missing {sub} in daemon --help output"
