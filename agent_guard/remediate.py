"""Remediation with visible rails.

A guard is only worth installing if it never destroys work.  Killing a process
that a human or an agent still owns is a much worse failure than missing one that
should have died, so every precondition is re-checked *at kill time* (not at
detection time), and each refusal is recorded with its reason so the board can
show why nothing was done.

Rails, in order:
  1. comm must be a known browser binary        (a daemon with --headless is not)
  2. uid must be ours                           (never touch another user's tree)
  3. argv must look like browser automation     (--headless plus profile/port)
  4. no live debugging client                   (someone is talking to it)
  5. not a supervised systemd unit              (systemd owns its lifecycle)
  6. parent must still be gone                  (the driver may have come back)
"""

from __future__ import annotations

import os
import re
import signal
import time
from dataclasses import dataclass
from pathlib import Path

from . import procfs
from .config import Config
from .rules import BROWSER_COMMS, BROWSER_RE, DEBUG_PORT_RE, USER_DATA_DIR_RE, OrphanCandidate

# Exit statuses we consider "the process is gone" beyond plain success.
_DEAD_STATES = {"Z", "X"}


@dataclass(slots=True)
class Action:
    ts: float
    kind: str  # reap | skip
    target: str
    detail: str
    ok: bool

    def as_dict(self) -> dict:
        return {
            "ts": self.ts,
            "kind": self.kind,
            "target": self.target,
            "detail": self.detail,
            "ok": self.ok,
        }


def fill_client_counts(candidates: list[OrphanCandidate]) -> None:
    for cand in candidates:
        if cand.port:
            cand.clients = procfs.listening_client_count(int(cand.port))


def _still_orphaned(pid: int) -> bool:
    info = procfs.parse_linux_stat(pid) if procfs.HAVE_PROC else None
    if info is None:
        return False
    if info.ppid <= 1:
        return True
    parent = procfs.parse_linux_stat(info.ppid)
    return parent is None or parent.comm == "systemd"


def _supervised(pid: int) -> str:
    """Return the unit name when systemd really owns this pid, else "".

    Being in a ``.scope`` is not ownership: scopes group processes that someone
    launched (an agent's browser lands in ``app-com.google.Chrome-<pid>.scope``
    exactly like a supervised one).  Only ``.service`` units supervise, and only
    the service's MainPID is the process systemd itself started.
    """
    unit = procfs.cgroup_unit(pid)
    if not unit:
        return ""
    if unit.endswith(".scope"):
        return ""
    if not unit.endswith(".service"):
        return unit  # unknown shape: fail closed
    main = procfs.unit_main_pid(unit)
    if main is None:
        return unit  # cannot tell → treat as supervised
    return unit if main == pid else ""


def _kill(pid: int, grace: float) -> bool:
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 2.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        deadline = time.time() + wait
        while time.time() < deadline:
            if not Path(f"/proc/{pid}").exists():
                return True
            time.sleep(0.2)
    return not Path(f"/proc/{pid}").exists()


def assess(cand: OrphanCandidate, protected: set[str], my_uid: int) -> str:
    """Return the reason this candidate must be left alone, or "" when it is safe."""
    comm = cand.comm.split("/")[-1].lower()
    if comm not in BROWSER_COMMS:
        return f"`{cand.comm}` 不是已知浏览器进程"
    if comm in protected:
        return "受保护进程名单"
    if cand.uid not in (-1, my_uid):
        return f"属于其他用户 (uid {cand.uid})"
    if not BROWSER_RE.search(cand.cmdline):
        return "命令行里没有 headless 标记"
    if not (USER_DATA_DIR_RE.search(cand.cmdline) or DEBUG_PORT_RE.search(cand.cmdline)):
        return "不像自动化启动（没有 profile 目录或调试端口）"
    if cand.clients:
        return f"调试端口 :{cand.port} 仍连着 {cand.clients} 个客户端"
    unit = _supervised(cand.pid)
    if unit:
        return f"由 systemd 单元 {unit} 管理"
    if not _still_orphaned(cand.pid):
        return "父进程已恢复"
    return ""


def reap_orphan_browsers(candidates: list[OrphanCandidate], cfg: Config) -> list[Action]:
    actions: list[Action] = []
    if not cfg.fix_enabled or not candidates:
        return actions

    fill_client_counts(candidates)
    protected = {name.split("/")[-1].lower() for name in cfg.protected_names}
    my_uid = os.getuid()
    mine = {os.getpid(), os.getppid()}

    for cand in candidates[: cfg.fix_max_per_tick]:
        target = f"{cand.comm}:{cand.pid}"
        if cand.pid in mine:
            actions.append(Action(time.time(), "skip", target, "是本进程或父进程", True))
            continue
        reason = assess(cand, protected, my_uid)
        if reason:
            actions.append(Action(time.time(), "skip", target, reason, True))
            continue
        ok = _kill(cand.pid, cfg.fix_kill_grace_seconds)
        actions.append(
            Action(
                time.time(),
                "reap",
                target,
                f"孤儿 headless 浏览器，存活 {cand.age_seconds / 60:.0f} 分钟，已清理",
                ok,
            )
        )
    return actions