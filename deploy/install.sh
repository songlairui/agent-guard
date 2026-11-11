#!/usr/bin/env bash
# Install agent-guard as user-level systemd units (Linux) or a LaunchAgent (macOS).
#   ./deploy/install.sh              install + enable + start
#   ./deploy/install.sh --uninstall  stop + remove
# Everything is rendered with absolute paths, so the repo can live anywhere.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${AGENT_GUARD_PYTHON:-$(command -v python3)}"
TICK_MINUTES="${AGENT_GUARD_TICK_MINUTES:-10}"
PORT="${AGENT_GUARD_PORT:-7788}"

die() { echo "install.sh: $*" >&2; exit 1; }

[[ -x "$PYTHON" ]] || die "找不到 python3（可用 AGENT_GUARD_PYTHON 指定）"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "需要 Python >= 3.11，当前 $("$PYTHON" -V 2>&1)"

uninstall() {
  for unit in agent-guard.tick.timer agent-guard.tick.service agent-guard.board.service; do
    systemctl --user disable --now "$unit" 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/$unit"
  done
  systemctl --user daemon-reload || true
  if [[ "$(uname -s)" == "Darwin" ]]; then
    plist="$HOME/Library/LaunchAgents/agent-guard.board.plist"
    launchctl unload "$plist" 2>/dev/null || true
    rm -f "$plist"
  fi
  echo "agent-guard: 已卸载（数据保留在 ~/.local/state/agent-guard/）"
}

if [[ "${1:-}" == "--uninstall" ]]; then
  uninstall
  exit 0
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  mkdir -p "$HOME/Library/LaunchAgents"
  cat >"$HOME/Library/LaunchAgents/agent-guard.board.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>agent-guard.board</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string><string>-m</string><string>agent_guard.cli</string>
    <string>serve</string><string>--ticker</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO</string>
  <key>EnvironmentVariables</key>
  <dict><key>PYTHONPATH</key><string>$REPO</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$HOME/.local/state/agent-guard/board.log</string>
  <key>StandardErrorPath</key><string>$HOME/.local/state/agent-guard/board.err</string>
</dict>
</plist>
PLIST
  mkdir -p "$HOME/.local/state/agent-guard"
  launchctl unload "$HOME/Library/LaunchAgents/agent-guard.board.plist" 2>/dev/null || true
  launchctl load "$HOME/Library/LaunchAgents/agent-guard.board.plist"
  echo "agent-guard: 看板 http://127.0.0.1:$PORT/ （LaunchAgent 自带采样）"
  exit 0
fi

command -v systemctl >/dev/null || die "没有 systemctl；请手动定时运行：$PYTHON -m agent_guard.cli tick"
UNIT_DIR="$HOME/.config/systemd/user"
mkdir -p "$UNIT_DIR" "$HOME/.local/state/agent-guard"

cat >"$UNIT_DIR/agent-guard.tick.service" <<UNIT
[Unit]
Description=agent-guard: one sampling tick (rules, safe remediation, escalation)
Documentation=file:$REPO/README.md
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$REPO
Environment=PYTHONPATH=$REPO
Nice=10
TimeoutStartSec=5min
ExecStart=$PYTHON -m agent_guard.cli tick
UNIT

cat >"$UNIT_DIR/agent-guard.tick.timer" <<UNIT
[Unit]
Description=Run agent-guard tick every ${TICK_MINUTES} minutes

[Timer]
OnBootSec=${TICK_MINUTES}min
OnUnitActiveSec=${TICK_MINUTES}min
AccuracySec=1min
RandomizedDelaySec=0
Unit=agent-guard.tick.service

[Install]
WantedBy=timers.target
UNIT

cat >"$UNIT_DIR/agent-guard.board.service" <<UNIT
[Unit]
Description=agent-guard: operations board (read-only view of the state database)
Documentation=file:$REPO/README.md
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO
Environment=PYTHONPATH=$REPO
ExecStart=$PYTHON -m agent_guard.cli serve
Restart=on-failure
RestartSec=3
Nice=5

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable --now agent-guard.board.service
systemctl --user enable --now agent-guard.tick.timer
echo
echo "agent-guard 已安装"
echo "  看板     http://127.0.0.1:$PORT/"
echo "  采样     每 ${TICK_MINUTES} 分钟（systemctl --user list-timers | grep agent-guard）"
echo "  日志     journalctl --user -u agent-guard.tick -n 50"
echo "  配置     ~/.config/agent-guard/config.json（python3 -m agent_guard.cli init-config）"