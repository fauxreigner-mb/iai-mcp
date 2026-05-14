#!/usr/bin/env bash
# scripts/install.sh — first-time setup for collaborators.
#
# Usage (from repo root or anywhere inside the clone):
#   bash scripts/install.sh
#
# Does:
#   1. creates .venv if missing
#   2. installs iai-mcp editable into the venv
#   3. builds the TS MCP wrapper
#   4. symlinks ~/.local/bin/iai-mcp -> .venv/bin/iai-mcp so the CLI is
#      callable from anywhere without activating the venv
#   5. optionally installs the sleep daemon (launchd on macOS, systemd on Linux)
#
# Idempotent. Safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '   \033[0;32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[0;33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Detect install mode.
# On Linux, prefer pipx when available — it provides a stable venv path
# independent of the repo checkout and follows XDG/freedesktop conventions.
# Override: IAI_USE_PIPX=0 forces the manual venv path.
# ---------------------------------------------------------------------------
USE_PIPX=0
if [[ "${IAI_USE_PIPX:-auto}" != "0" ]] && [[ "$(uname)" == "Linux" ]] && command -v pipx >/dev/null 2>&1; then
    USE_PIPX=1
fi

# ---------------------------------------------------------------------------
# Sections 1-4: build / venv / pip / npm / symlink.
#
# IAI_TEST_SKIP_BUILD=1 short-circuits the whole bootstrap so the LaunchAgent
# section (6) can be exercised in isolation by tests/test_install_uninstall.py
# (Plan 07.1-03 Task 3) without spending ~30s on venv + npm.
# ---------------------------------------------------------------------------
if [[ "${IAI_TEST_SKIP_BUILD:-0}" == "1" ]]; then
    step "build skip (IAI_TEST_SKIP_BUILD=1)"
    ok "skipping sections 1-4 (venv/pip/npm/symlink) — test mode"
elif [[ "${USE_PIPX}" == "1" ]]; then
    # -----------------------------------------------------------------------
    # 1-4 (pipx path): pipx manages venv + ~/.local/bin entry point.
    # -----------------------------------------------------------------------
    step "python install (pipx)"
    # --editable installs from the current checkout so local edits are live.
    # --force ensures re-running is idempotent even if already installed.
    if ! pipx install --editable . --force 2>&1; then
        warn "pipx --editable failed (pipx < 1.0?), falling back to non-editable install"
        warn "source edits will NOT be live without re-running install.sh"
        pipx install . --force
    fi
    ok "iai-mcp installed via pipx"
    ok "venv: ${HOME}/.local/share/pipx/venvs/iai-mcp/"
    ok "CLI:  ${HOME}/.local/bin/iai-mcp"

    # -----------------------------------------------------------------------
    # 3. TS wrapper build (always needed regardless of install mode)
    # -----------------------------------------------------------------------
    step "TS wrapper build"
    if [ -d mcp-wrapper ]; then
        pushd mcp-wrapper >/dev/null
        if [ -f package-lock.json ]; then
            npm ci --silent --no-audit --no-fund
        else
            npm install --silent --no-audit --no-fund
        fi
        npm run build --silent
        popd >/dev/null
        ok "mcp-wrapper/dist built"
    else
        warn "mcp-wrapper/ missing — skipping"
    fi

    # PATH sanity check
    step "PATH check"
    LOCAL_BIN="${HOME}/.local/bin"
    if echo ":${PATH}:" | grep -q ":${LOCAL_BIN}:"; then
        ok "${LOCAL_BIN} is in PATH"
    else
        warn "${LOCAL_BIN} is NOT in your PATH"
        warn "add this to ~/.bashrc or ~/.zshrc and restart your shell:"
        warn "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    fi
else
    # -----------------------------------------------------------------------
    # 1-4 (venv path): manual venv + editable install + symlink
    # -----------------------------------------------------------------------
    step "python venv"
    if [ ! -d .venv ]; then
        python3 -m venv .venv
        ok ".venv created"
    else
        ok ".venv already exists"
    fi

    step "editable install (pip -e .)"
    .venv/bin/pip install --quiet --upgrade pip
    .venv/bin/pip install --quiet -e .
    ok "iai-mcp python package installed into venv"

    step "TS wrapper build"
    if [ -d mcp-wrapper ]; then
        pushd mcp-wrapper >/dev/null
        if [ -f package-lock.json ]; then
            npm ci --silent --no-audit --no-fund
        else
            npm install --silent --no-audit --no-fund
        fi
        npm run build --silent
        popd >/dev/null
        ok "mcp-wrapper/dist built"
    else
        warn "mcp-wrapper/ missing — skipping"
    fi

    step "global CLI symlink"
    LOCAL_BIN="${HOME}/.local/bin"
    LINK_PATH="${LOCAL_BIN}/iai-mcp"
    TARGET="${REPO_ROOT}/.venv/bin/iai-mcp"

    [ -x "${TARGET}" ] || die "venv entry point not found at ${TARGET}"

    mkdir -p "${LOCAL_BIN}"

    if [ -e "${LINK_PATH}" ] && [ ! -L "${LINK_PATH}" ]; then
        die "${LINK_PATH} exists and is NOT a symlink. move it aside and re-run."
    fi
    ln -sf "${TARGET}" "${LINK_PATH}"
    ok "${LINK_PATH} -> ${TARGET}"

    # PATH sanity check using python (grep is hook-blocked in this dev env).
    PATH_HAS_LOCAL_BIN="$(.venv/bin/python - <<PY
import os
print("1" if "${LOCAL_BIN}" in os.environ.get("PATH", "").split(":") else "0")
PY
)"
    if [ "${PATH_HAS_LOCAL_BIN}" != "1" ]; then
        warn "${LOCAL_BIN} is NOT in your PATH"
        warn "add this to ~/.zshrc or ~/.bashrc and restart your shell:"
        warn "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    else
        ok "${LOCAL_BIN} is in PATH"
    fi
fi

# ---------------------------------------------------------------------------
# 5. optional daemon install
# ---------------------------------------------------------------------------
step "sleep daemon (optional)"
if command -v iai-mcp >/dev/null 2>&1; then
    INSTALLED_PATH="$(command -v iai-mcp)"
    ok "iai-mcp globally reachable at ${INSTALLED_PATH}"
    echo
    echo "   to run the background sleep daemon (recommended — REM cycles +"
    echo "   overnight consolidation on your local Claude subscription):"
    echo
    echo "     iai-mcp daemon install --yes"
    echo "     iai-mcp daemon start"
    echo
    echo "   or skip for now and install later."
else
    warn "iai-mcp not on PATH yet — add ~/.local/bin to PATH first, then run:"
    warn "  iai-mcp daemon install --yes"
fi

# ---------------------------------------------------------------------------
# 6. LaunchAgent registration (Phase 7.1 — socket-activated singleton)
#
# Section 6 (Phase 7.1) — socket-activated LaunchAgent. REPLACES the eager
# RunAtLoad=true plist that Plan 04-05 `iai-mcp daemon install` writes.
# The two flows compete for ~/Library/LaunchAgents/com.iai-mcp.daemon.plist;
# whichever ran most recently wins. Phase 7.1 install.sh always wins because
# it overwrites + reloads on every invocation (idempotent by design).
# ---------------------------------------------------------------------------
step "daemon registration"
if [[ "$(uname)" == "Darwin" ]]; then
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        ok "DRY_RUN=1 — skipping launchctl calls (test mode)"
    else
        PYTHON_PATH="${REPO_ROOT}/.venv/bin/python"
        if [ ! -x "${PYTHON_PATH}" ]; then
            warn "venv python not found at ${PYTHON_PATH} — falling back to $(command -v python3)"
            PYTHON_PATH="$(command -v python3)"
        fi
        LA_DIR="${HOME}/Library/LaunchAgents"
        LA_PATH="${LA_DIR}/com.iai-mcp.daemon.plist"
        TEMPLATE="${REPO_ROOT}/scripts/com.iai-mcp.daemon.plist.template"
        [ -f "${TEMPLATE}" ] || die "plist template missing at ${TEMPLATE}"
        mkdir -p "${LA_DIR}" "${HOME}/.iai-mcp/logs" "${HOME}/.iai-mcp"
        # Substitute placeholders using sed; HOME/PYTHON_PATH may contain forward
        # slashes so we use `|` as the sed separator (not `/`).
        sed -e "s|{PYTHON_PATH}|${PYTHON_PATH}|g" -e "s|{HOME}|${HOME}|g" "${TEMPLATE}" > "${LA_PATH}"
        if [ ! -f "${HOME}/.iai-mcp/.crypto.key" ] && [ -z "${IAI_MCP_CRYPTO_PASSPHRASE:-}" ]; then
            if "${REPO_ROOT}/.venv/bin/iai-mcp" crypto init >/dev/null 2>&1; then
                ok "crypto key generated (~/.iai-mcp/.crypto.key)"
            else
                warn "crypto init failed — run \`iai-mcp crypto init\` manually"
            fi
        fi
        # Idempotent: unload prior registration if any, then load fresh. -w persists across reboots.
        launchctl unload -w "${LA_PATH}" 2>/dev/null || true
        if ! launchctl load -w "${LA_PATH}"; then
            warn "launchctl load reported non-zero — checking registration anyway"
        fi
        if launchctl list | grep -q "com.iai-mcp.daemon"; then
            ok "LaunchAgent registered (first MCP call will socket-activate the daemon)"
        else
            die "LaunchAgent NOT registered after launchctl load — investigate ${HOME}/.iai-mcp/logs/launchd-stderr.log"
        fi
    fi
elif [[ "$(uname)" == "Linux" ]]; then
    # -------------------------------------------------------------------------
    # Linux: install systemd user units + enable socket activation
    # -------------------------------------------------------------------------
    SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
    SERVICE_FILE="${SYSTEMD_USER_DIR}/iai-mcp-daemon.service"
    SOCKET_FILE="${SYSTEMD_USER_DIR}/iai-mcp-daemon.socket"
    SERVICE_TEMPLATE="${REPO_ROOT}/deploy/systemd/iai-mcp-daemon.service"
    SOCKET_TEMPLATE="${REPO_ROOT}/deploy/systemd/iai-mcp-daemon.socket"

    # Verify systemd user session is available
    if ! systemctl --user status >/dev/null 2>&1; then
        warn "systemd user session not active"
        warn "if running inside a distrobox, try: distrobox-enter <boxname>"
        warn "on the host, enable linger first: loginctl enable-linger \$USER"
        warn "then re-run this script"
    else
        mkdir -p "${SYSTEMD_USER_DIR}"

        # Derive Python path: pipx venv if pipx-managed, repo venv otherwise.
        if [[ "${USE_PIPX}" == "1" ]]; then
            PYTHON_PATH="${HOME}/.local/share/pipx/venvs/iai-mcp/bin/python3"
            [ -x "${PYTHON_PATH}" ] || PYTHON_PATH="$(command -v python3 || command -v python)"
        else
            PYTHON_PATH="${REPO_ROOT}/.venv/bin/python"
            [ -x "${PYTHON_PATH}" ] || PYTHON_PATH="$(command -v python3 || command -v python)"
        fi

        [ -f "${SERVICE_TEMPLATE}" ] || die "service template missing at ${SERVICE_TEMPLATE}"
        [ -f "${SOCKET_TEMPLATE}" ]  || die "socket template missing at ${SOCKET_TEMPLATE}"

        sed "s|/usr/bin/python3|${PYTHON_PATH}|g" "${SERVICE_TEMPLATE}" > "${SERVICE_FILE}"
        cp "${SOCKET_TEMPLATE}" "${SOCKET_FILE}"
        ok "unit files written to ${SYSTEMD_USER_DIR}"

        # Crypto key
        if [ ! -f "${HOME}/.iai-mcp/.crypto.key" ] && [ -z "${IAI_MCP_CRYPTO_PASSPHRASE:-}" ]; then
            IAI_MCP_CMD="${REPO_ROOT}/.venv/bin/iai-mcp"
            [[ "${USE_PIPX}" == "1" ]] && IAI_MCP_CMD="iai-mcp"
            if "${IAI_MCP_CMD}" crypto init >/dev/null 2>&1; then
                ok "crypto key generated (~/.iai-mcp/.crypto.key)"
            else
                warn "crypto init failed — run \`iai-mcp crypto init\` manually"
            fi
        fi

        systemctl --user daemon-reload

        # Enable socket unit (socket activation: daemon spawns on first connect)
        if ! systemctl --user enable --now iai-mcp-daemon.socket; then
            warn "systemctl enable --now iai-mcp-daemon.socket returned non-zero"
        fi

        # Linger: allow user services to survive logout
        if loginctl enable-linger "${USER}" 2>/dev/null; then
            ok "linger enabled for ${USER}"
        else
            warn "loginctl enable-linger failed — daemon may stop at logout"
            warn "run manually: loginctl enable-linger \$USER"
        fi

        # Verify
        if systemctl --user is-enabled iai-mcp-daemon.socket 2>/dev/null | grep -q "enabled"; then
            ok "socket unit enabled (daemon activates on first MCP call)"
        else
            warn "socket unit does not appear enabled — check: systemctl --user status iai-mcp-daemon.socket"
        fi

        echo
        echo "   next:   iai-mcp doctor        (verify daemon health)"
        echo "   logs:   journalctl --user -u iai-mcp-daemon.service -f"
    fi
else
    warn "unsupported OS ($(uname)) — skipping daemon registration"
    warn "install the daemon manually after verifying your init system"
fi

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------
step "done"
ok "iai-mcp installed at $(git rev-parse --short HEAD)"
echo
echo "   next:   bash scripts/uninstall.sh    (to roll back; preserves data unless --purge-data)"
echo "   update: bash scripts/update.sh        (pull + rebuild + restart daemon)"
