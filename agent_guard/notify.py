"""Escalation: the board is free, a chat channel is not.

A guard that pings people every tick gets muted, and a muted channel is worse
than no channel — it teaches everyone that the signal is noise.  So the board
shows everything, and this module only escalates what is *both* severe and still
unacknowledged after a grace period, at most once per cooldown.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from pathlib import Path

from .config import Config
from .store import Store

MAX_BODY_CHARS = 3500


def _format(incidents: list[dict], host: str) -> str:
    lines = [f"**🩺 {host} 未处理告警**  {time.strftime('%m-%d %H:%M')}", ""]
    for inc in incidents:
        minutes = max(0, int((time.time() - inc["first_seen"]) / 60))
        lines += [
            f"**[{inc['severity']}] {inc['title']}**（已持续 {minutes} 分钟，未认领）",
            inc["body"],
            "",
        ]
    lines.append("_在 `agent-guard` 看板上点「认领」即可停止升级。_")
    return "\n".join(lines)[:MAX_BODY_CHARS]


def deliver(cfg: Config, incidents: list[dict], host: str) -> tuple[bool, str]:
    """Run the configured escalation command.  Returns (ok, detail)."""
    if not cfg.escalation_command:
        return False, "escalation_command 未配置"
    message = _format(incidents, host)
    try:
        parts = shlex.split(cfg.escalation_command)
    except ValueError as exc:
        return False, f"escalation_command 解析失败: {exc}"
    if any("{message}" in part for part in parts):
        parts = [part.replace("{message}", message) for part in parts]
        stdin = ""
    else:
        stdin = message
    try:
        res = subprocess.run(parts, input=stdin, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"升级命令执行失败: {exc}"
    if res.returncode != 0:
        return False, f"升级命令退出码 {res.returncode}: {res.stderr.strip()[:200]}"
    return True, "已升级"


def escalate_due(store: Store, cfg: Config) -> list[dict]:
    due = store.escalations_due(cfg)
    if not due:
        return []
    host = Path("/etc/hostname").read_text().strip() if Path("/etc/hostname").exists() else "host"
    ok, detail = deliver(cfg, due, host)
    print(f"agent-guard: escalation {'ok' if ok else 'failed'} ({detail})")
    if ok:
        store.mark_escalated([inc["key"] for inc in due])
    return due if ok else []