"""— comprehensive tests for ``IdleDetector``.

Covers the 11-test matrix from CONTEXT 10.4:
- HIDIdleTime parses ioreg output (ns -> sec).
- HIDIdleTime returns None when ioreg missing (FileNotFoundError).
- pmset detects sleep event within window.
- pmset returns False when no recent sleep within window.
- pmset returns False when pmset binary missing.
- sleep_eligible heartbeat-idle path (heartbeat_idle_30min=True).
- sleep_eligible HID idle path (HIDIdleTime >= 30 min).
- sleep_eligible pmset path (pmset_recent_sleep=True).
- sleep_eligible all-False path.
- status() reports IdleStatus shape with all signals available.
- status() when signals missing reports empty available_signals.

All subprocess interactions are mocked so the suite is deterministic and
runs on non-macOS hosts as well — real ioreg / pmset spawns would make
the suite host-dependent.
"""
from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from iai_mcp.idle_detector import IdleDetector, IdleStatus


# ---------------------------------------------------------------- fixtures


def _completed_process(
    stdout: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    """Build a fake ``CompletedProcess`` for subprocess.run mocks."""
    proc: subprocess.CompletedProcess[str] = subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=""
    )
    return proc


def _ioreg_stdout(idle_ns: int) -> str:
    """Build a minimal ioreg-shaped stdout containing a HIDIdleTime line.

    The real ioreg output is a deeply nested I/O-Registry tree; we only
    need the literal token the parser searches for.
    """
    return (
        "+-o IOHIDSystem  <class IOHIDSystem, id 0x100000abc, registered>\n"
        f'    | "HIDIdleTime" = {idle_ns}\n'
        '    | "DisplayWrangler" = 1\n'
    )


def _pmset_log_stdout(events: list[tuple[str, str]]) -> str:
    """Build a fake pmset -g log stdout from ``[(timestamp, marker), ...]``.

    Each event becomes a line in the format the real pmset emits — the
    timestamp regex anchors the line, and the marker substring is what
    ``_PMSET_SLEEP_MARKERS`` searches for.
    """
    lines = []
    for ts, marker in events:
        lines.append(f"{ts} {marker} Notification clientId=foo")
    return "\n".join(lines) + ("\n" if lines else "")


def _now_pmset_ts(offset_min: int) -> str:
    """Return a pmset-formatted UTC timestamp ``offset_min`` minutes ago.

    The real log uses local-time timestamps with explicit offsets; using
    ``+0000`` (UTC) here is well-defined and the parser handles any
    offset uniformly.
    """
    ts = datetime.now(timezone.utc) - timedelta(minutes=offset_min)
    return ts.strftime("%Y-%m-%d %H:%M:%S +0000")


# ---------------------------------------------------------------- HIDIdleTime


def test_hid_idle_time_sec_parses_ioreg_output() -> None:
    """``HIDIdleTime = 612000000000`` (ns) -> 612 seconds."""
    fake = _completed_process(stdout=_ioreg_stdout(idle_ns=612_000_000_000))
    with patch("iai_mcp.idle_detector.subprocess.run", return_value=fake):
        result = IdleDetector().hid_idle_time_sec()
    assert result == 612


def test_hid_idle_time_sec_returns_none_when_ioreg_missing() -> None:
    """FileNotFoundError on ioreg -> None (graceful fallback)."""
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=FileNotFoundError(2, "No such file"),
    ):
        result = IdleDetector().hid_idle_time_sec()
    assert result is None


def test_hid_idle_time_sec_returns_none_on_nonzero_exit() -> None:
    """ioreg exits non-zero -> None (treat as unavailable)."""
    fake = _completed_process(stdout="", returncode=1)
    with patch("iai_mcp.idle_detector.subprocess.run", return_value=fake):
        result = IdleDetector().hid_idle_time_sec()
    assert result is None


def test_hid_idle_time_sec_returns_none_on_timeout() -> None:
    """ioreg timeout -> None (don't block the lifecycle TICK)."""
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["ioreg"], timeout=5),
    ):
        result = IdleDetector().hid_idle_time_sec()
    assert result is None


# ---------------------------------------------------------------- pmset


def test_pmset_recent_sleep_detects_event_within_window() -> None:
    """Sleep event 2 min ago, window=5 -> True."""
    log = _pmset_log_stdout([
        (_now_pmset_ts(offset_min=2), "System Sleep"),
    ])
    fake = _completed_process(stdout=log)
    with patch("iai_mcp.idle_detector.subprocess.run", return_value=fake):
        result = IdleDetector().pmset_recent_sleep(window_min=5)
    assert result is True


def test_pmset_recent_sleep_detects_display_off_event() -> None:
    """'Display is turned off' marker also counts (per CONTEXT 10.4)."""
    log = _pmset_log_stdout([
        (_now_pmset_ts(offset_min=1), "Display is turned off"),
    ])
    fake = _completed_process(stdout=log)
    with patch("iai_mcp.idle_detector.subprocess.run", return_value=fake):
        result = IdleDetector().pmset_recent_sleep(window_min=5)
    assert result is True


def test_pmset_recent_sleep_returns_false_when_no_recent_event() -> None:
    """Sleep events older than window -> False."""
    log = _pmset_log_stdout([
        (_now_pmset_ts(offset_min=60), "System Sleep"),
        (_now_pmset_ts(offset_min=120), "Display is turned off"),
    ])
    fake = _completed_process(stdout=log)
    with patch("iai_mcp.idle_detector.subprocess.run", return_value=fake):
        result = IdleDetector().pmset_recent_sleep(window_min=5)
    assert result is False


def test_pmset_recent_sleep_returns_false_when_pmset_missing() -> None:
    """FileNotFoundError on pmset -> False (graceful fallback)."""
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=FileNotFoundError(2, "No such file"),
    ):
        result = IdleDetector().pmset_recent_sleep()
    assert result is False


# ---------------------------------------------------------------- sleep_eligible disjunction


def test_sleep_eligible_heartbeat_idle_path() -> None:
    """heartbeat_idle_30min=True alone short-circuits to True.

    Importantly, the implementation must NOT spawn ioreg/pmset when this
    path triggers — we patch subprocess.run to fail loudly to verify.
    """
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=AssertionError("must not spawn when heartbeat-idle is True"),
    ):
        result = IdleDetector().sleep_eligible(heartbeat_idle_30min=True)
    assert result is True


def test_sleep_eligible_hid_idle_path() -> None:
    """HIDIdleTime=1900s (>30 min), heartbeat False -> True via HID disjunct."""
    # First call: ioreg returns HIDIdleTime=1900s. Second call would be
    # pmset but should not happen because hid_idle path short-circuits.
    fake_ioreg = _completed_process(
        stdout=_ioreg_stdout(idle_ns=1900 * 1_000_000_000)
    )
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        return_value=fake_ioreg,
    ) as run_mock:
        result = IdleDetector().sleep_eligible(heartbeat_idle_30min=False)
    assert result is True
    # ioreg called once; pmset must NOT have been called (short-circuit).
    assert run_mock.call_count == 1


def test_sleep_eligible_pmset_path() -> None:
    """heartbeat False, HID below threshold, pmset event recent -> True."""
    fake_ioreg = _completed_process(
        stdout=_ioreg_stdout(idle_ns=10 * 1_000_000_000)  # 10s -- below threshold
    )
    fake_pmset = _completed_process(
        stdout=_pmset_log_stdout([
            (_now_pmset_ts(offset_min=2), "System Sleep"),
        ])
    )
    # subprocess.run is called twice: ioreg, then pmset.
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=[fake_ioreg, fake_pmset],
    ):
        result = IdleDetector().sleep_eligible(heartbeat_idle_30min=False)
    assert result is True


def test_sleep_eligible_all_false() -> None:
    """All three disjuncts False -> overall False."""
    fake_ioreg = _completed_process(
        stdout=_ioreg_stdout(idle_ns=10 * 1_000_000_000)
    )
    fake_pmset = _completed_process(stdout="")  # empty log
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=[fake_ioreg, fake_pmset],
    ):
        result = IdleDetector().sleep_eligible(heartbeat_idle_30min=False)
    assert result is False


# ---------------------------------------------------------------- status() snapshot


def test_status_for_doctor_row_all_signals_available() -> None:
    """status() reports both signals when ioreg + pmset both succeed.

    Three subprocess.run calls expected:
      1. ioreg (hid_idle_time_sec)
      2. pmset -g log (pmset_recent_sleep)
      3. pmset -g (responsiveness probe inside _pmset_responsive)
    """
    fake_ioreg = _completed_process(
        stdout=_ioreg_stdout(idle_ns=42 * 1_000_000_000)
    )
    fake_pmset_log = _completed_process(stdout="")
    fake_pmset_g = _completed_process(stdout="Now drawing from 'AC Power'\n")
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=[fake_ioreg, fake_pmset_log, fake_pmset_g],
    ):
        status = IdleDetector().status()

    assert isinstance(status, IdleStatus)
    assert status.hid_idle_sec == 42
    assert status.pmset_recent_sleep is False
    assert "HIDIdleTime" in status.available_signals
    assert "pmset" in status.available_signals


def test_status_when_signals_missing() -> None:
    """All subprocess calls fail -> available_signals == []."""
    with patch(
        "iai_mcp.idle_detector.subprocess.run",
        side_effect=FileNotFoundError(2, "No such file"),
    ):
        status = IdleDetector().status()
    assert status.hid_idle_sec is None
    assert status.pmset_recent_sleep is False
    assert status.available_signals == []


# ---------------------------------------------------------------- subprocess hardening


def test_subprocess_uses_array_form_not_shell() -> None:
    """Verify all subprocess calls use array form with shell=False.

    Captures the actual ``args`` and ``kwargs`` passed to ``subprocess.run``
    and asserts:
      - ``args[0]`` (the command) is a list, not a string.
      - ``kwargs.get("shell", False)`` is False (or missing).
      - A finite ``timeout`` is set on every call.
    """
    fake = _completed_process(stdout="")
    captured: list[tuple[tuple, dict]] = []

    def _capture(*args, **kwargs):
        captured.append((args, kwargs))
        return fake

    with patch(
        "iai_mcp.idle_detector.subprocess.run", side_effect=_capture
    ):
        IdleDetector().status()

    assert len(captured) >= 1
    for args, kwargs in captured:
        # First positional arg is the command. Must be a list.
        assert isinstance(args[0], list), (
            f"subprocess.run command must be a list (array form), got: {args[0]!r}"
        )
        # shell defaults to False when unset; explicitly assert it's not True.
        assert kwargs.get("shell", False) is False, (
            "subprocess.run must NOT use shell=True (PATH-injection risk)"
        )
        # Timeout must be set so a hung tool can't block the TICK.
        assert "timeout" in kwargs and kwargs["timeout"] > 0, (
            f"subprocess.run must set a finite timeout, got: {kwargs}"
        )


# ---------------------------------------------------------------------------
# Linux logind backend tests
# ---------------------------------------------------------------------------


def _loginctl_stdout(idle_hint: str = "yes", idle_since_hint_us: int = 0) -> str:
    """Build fake loginctl show-session output."""
    return f"IdleHint={idle_hint}\nIdleSinceHint={idle_since_hint_us}\n"


class TestLinuxLogindBackend:
    """Tests for _LinuxLogindBackend — all subprocess calls mocked."""

    def test_hid_idle_time_sec_parses_loginctl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """IdleSinceHint µs → seconds since last activity computed correctly."""
        import time
        import iai_mcp.idle_detector as _mod

        # Simulate: last activity was 45 minutes ago (in µs since epoch)
        idle_sec = 45 * 60
        idle_since_us = int((time.time() - idle_sec) * 1_000_000)
        fake_stdout = f"IdleHint=yes\nIdleSinceHint={idle_since_us}\n"

        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            return_value=_completed_process(stdout=fake_stdout),
        ):
            backend = _mod._LinuxLogindBackend()
            result = backend.hid_idle_time_sec()

        assert result is not None
        # Allow ±5s slop for test execution time
        assert abs(result - idle_sec) < 5, f"expected ~{idle_sec}s, got {result}s"

    def test_hid_idle_time_sec_returns_none_on_file_not_found(self) -> None:
        """FileNotFoundError (loginctl absent) → None."""
        import iai_mcp.idle_detector as _mod
        with patch("iai_mcp.idle_detector.subprocess.run", side_effect=FileNotFoundError("loginctl not found")):
            backend = _mod._LinuxLogindBackend()
            assert backend.hid_idle_time_sec() is None

    def test_hid_idle_time_sec_returns_none_on_timeout(self) -> None:
        """Timeout → None."""
        import iai_mcp.idle_detector as _mod
        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="loginctl", timeout=5),
        ):
            backend = _mod._LinuxLogindBackend()
            assert backend.hid_idle_time_sec() is None

    def test_hid_idle_time_sec_returns_none_on_parse_failure(self) -> None:
        """Unparseable output → None."""
        import iai_mcp.idle_detector as _mod
        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            return_value=_completed_process(stdout="garbage output\n"),
        ):
            backend = _mod._LinuxLogindBackend()
            assert backend.hid_idle_time_sec() is None

    def test_recent_suspend_always_false(self) -> None:
        """recent_suspend always returns False — container can't see host suspend."""
        import iai_mcp.idle_detector as _mod
        backend = _mod._LinuxLogindBackend()
        assert backend.recent_suspend() is False

    def test_available_signals_logind_idle_on_success(self) -> None:
        """available_signals returns ['logind_idle'] when loginctl responds."""
        import iai_mcp.idle_detector as _mod
        fake_stdout = "IdleHint=yes\nIdleSinceHint=1000000\n"
        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            return_value=_completed_process(stdout=fake_stdout),
        ):
            backend = _mod._LinuxLogindBackend()
            assert backend.available_signals() == ["logind_idle"]

    def test_available_signals_empty_on_failure(self) -> None:
        """available_signals returns [] when loginctl is absent."""
        import iai_mcp.idle_detector as _mod
        with patch("iai_mcp.idle_detector.subprocess.run", side_effect=FileNotFoundError):
            backend = _mod._LinuxLogindBackend()
            assert backend.available_signals() == []

    def test_status_available_signals_populated_on_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """IdleDetector.status() on Linux populates available_signals from logind."""
        import time
        import iai_mcp.idle_detector as _mod

        idle_since_us = int((time.time() - 1800) * 1_000_000)  # 30 min ago
        fake_stdout = f"IdleHint=yes\nIdleSinceHint={idle_since_us}\n"
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            return_value=_completed_process(stdout=fake_stdout),
        ):
            detector = _mod.IdleDetector()
            status = detector.status()
        assert "logind_idle" in status.available_signals

    def test_sleep_eligible_full_path_on_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """sleep_eligible() returns True on Linux when logind reports ≥30 min idle."""
        import time
        import iai_mcp.idle_detector as _mod

        idle_sec = 35 * 60  # 35 minutes - above the 30-min threshold
        idle_since_us = int((time.time() - idle_sec) * 1_000_000)
        fake_stdout = f"IdleHint=yes\nIdleSinceHint={idle_since_us}\n"
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            return_value=_completed_process(stdout=fake_stdout),
        ):
            detector = _mod.IdleDetector()
            result = detector.sleep_eligible(heartbeat_idle_30min=False)
        assert result is True

    def test_sleep_eligible_false_when_not_idle_on_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """sleep_eligible() returns False on Linux when logind reports <30 min idle."""
        import time
        import iai_mcp.idle_detector as _mod

        idle_sec = 5 * 60  # only 5 minutes — below threshold
        idle_since_us = int((time.time() - idle_sec) * 1_000_000)
        fake_stdout = f"IdleHint=yes\nIdleSinceHint={idle_since_us}\n"
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch(
            "iai_mcp.idle_detector.subprocess.run",
            return_value=_completed_process(stdout=fake_stdout),
        ):
            detector = _mod.IdleDetector()
            result = detector.sleep_eligible(heartbeat_idle_30min=False)
        assert result is False


# ---------------------------------------------------------------------------
# Backend dispatch tests
# ---------------------------------------------------------------------------


class TestIdleDetectorBackendDispatch:
    """Verify IdleDetector.__init__ selects the correct backend per platform."""

    def test_darwin_selects_macos_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import iai_mcp.idle_detector as _mod
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        detector = _mod.IdleDetector()
        assert isinstance(detector._backend, _mod._MacOSBackend)

    def test_linux_selects_logind_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import iai_mcp.idle_detector as _mod
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        detector = _mod.IdleDetector()
        assert isinstance(detector._backend, _mod._LinuxLogindBackend)

    def test_other_platform_selects_null_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import iai_mcp.idle_detector as _mod
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        detector = _mod.IdleDetector()
        assert isinstance(detector._backend, _mod._NullBackend)
