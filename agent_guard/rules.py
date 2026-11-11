"""Rules: what "the machine is being eaten" looks like, expressed as data.

Every rule answers three questions up front: which process (or the host itself),
how long it must persist before it counts, and how loud it is.  A rule that fires
on a single spiky sample is a rule nobody will keep installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Config
from .sampler import ProcessSample, Snapshot

# Only these are browsers.  Anything else with a "--headless" flag (CLI servers,
# daemons, ducter-style background processes) must never be treated as one.
BROWSER_COMMS = {
    "chrome",
    "chromium",
    "google-chrome",
    "google-chrome-stable",
    "chromium-browser",
    "headless_shell",
    "msedge",
    "brave",
    "brave-browser",
}
BROWSER_RE = re.compile(r"--headless=new|--headless|--remote-debugging-port")
USER_DATA_DIR_RE = re.compile(r"--user-data-dir=(\S+)")
DEBUG_PORT_RE = re.compile(r"--remote-debugging-port=(\d+)")
# Chromium's subprocesses share the parent's argv; only the browser process owns
# the debugging port and the driver relationship.
CHROMIUM_CHILD_RE = re.compile(r"--type=(\w[\w-]*)")


@dataclass(slots=True)
class Finding:
    key: str
    kind: str
    severity: str
    title: str
    body: str
    hint: str = ""
    pid: int | None = None
    value: float = 0.0
    meta: dict = field(default_factory=dict)


@dataclass(slots=True)
class OrphanCandidate:
    pid: int
    age_seconds: float
    comm: str
    port: str
    clients: int
    cmdline: str
    uid: int = -1


def _persisted(state: dict, key: str, needed: int) -> bool:
    streaks = state.setdefault("streaks", {})
    streaks[key] = streaks.get(key, 0) + 1
    return streaks[key] >= needed


def _decay(state: dict, live: set[str]) -> None:
    streaks = state.setdefault("streaks", {})
    for key in list(streaks):
        if key not in live:
            streaks.pop(key, None)


def looks_like_browser(proc: ProcessSample) -> bool:
    """Browser binary *and* browser-shaped argv.  Both halves are required.

    The comm allowlist is the load-bearing check: a daemon that happens to run
    with ``--headless`` is not a browser, and killing it would be indefensible.
    """
    comm = proc.comm.split("/")[-1].lower()
    if comm not in BROWSER_COMMS:
        return False
    if not BROWSER_RE.search(proc.cmdline):
        return False
    # Automation always pins a profile dir or a debugging port; a human's browser
    # does neither, so this keeps the user's own Chrome out of scope.
    return bool(USER_DATA_DIR_RE.search(proc.cmdline) or DEBUG_PORT_RE.search(proc.cmdline))


def find_orphan_browsers(snap: Snapshot, cfg: Config) -> list[OrphanCandidate]:
    """Headless browsers whose driver is gone — the classic agent leftover."""
    out: list[OrphanCandidate] = []
    for proc in snap.processes:
        if not looks_like_browser(proc):
            continue
        if CHROMIUM_CHILD_RE.search(proc.cmdline):
            continue  # zygote / gpu-process / renderer: children of the browser
        if not proc.parent_dead:
            continue  # a live driver still owns it
        if proc.age_seconds < cfg.orphan_age_seconds:
            continue
        match = DEBUG_PORT_RE.search(proc.cmdline)
        out.append(
            OrphanCandidate(
                pid=proc.pid,
                age_seconds=proc.age_seconds,
                comm=proc.comm,
                port=match.group(1) if match else "",
                clients=0,  # filled in by the caller, which can afford the ss call
                cmdline=proc.cmdline,
                uid=proc.uid,
            )
        )
    return out


def _fd_chains(snap: Snapshot, cfg: Config) -> list[Finding]:
    """Group fd pressure by inheritance chain.

    Children share the parent's whole fd table, so one leak surfaces as ten
    findings.  Report the root of the chain once, with the tightest headroom.
    """
    parents = {p.pid: p.ppid for p in snap.processes}
    big = {p.pid: p for p in snap.processes if p.fd_count and p.fd_count >= cfg.fd_min}
    hot = {
        pid: p
        for pid, p in big.items()
        if p.fd_limit and p.fd_count and p.fd_count / p.fd_limit * 100.0 >= cfg.fd_pct
    }
    if not hot:
        return []

    def root_of(pid: int) -> int:
        seen: set[int] = set()
        while (ppid := parents.get(pid)) in big and ppid not in seen:
            seen.add(ppid)
            pid = ppid
        return pid

    groups: dict[int, list[ProcessSample]] = {}
    for pid, proc in hot.items():
        groups.setdefault(root_of(pid), []).append(proc)

    findings = []
    for root, members in sorted(groups.items(), key=lambda kv: -(big[kv[0]].fd_count or 0))[:3]:
        worst = max(members, key=lambda p: p.fd_ratio)
        inherited = f"，另有 {len(members) - 1} 个继承该 fd 表的进程" if len(members) > 1 else ""
        findings.append(
            Finding(
                key=f"fd:{root}",
                kind="fd",
                severity=cfg.fd.severity,
                title="文件描述符逼近上限",
                body=(
                    f"`{worst.comm}` (pid {worst.pid}) 持有 **{big[root].fd_count}** 个 fd"
                    f"{inherited}，占其 soft limit {worst.fd_limit} 的 **{worst.fd_ratio * 100:.0f}%**"
                ),
                hint=f"ls -l /proc/{worst.pid}/fd | awk '{{print $NF}}' | sort | uniq -c | sort -rn | head",
                pid=worst.pid,
                value=worst.fd_ratio * 100,
            )
        )
    return findings


def evaluate(snap: Snapshot, cfg: Config, state: dict) -> tuple[list[Finding], list[OrphanCandidate]]:
    """Apply every enabled rule.  Returns findings plus orphan candidates to act on."""
    findings: list[Finding] = []
    live_keys: set[str] = set()

    if cfg.cpu_hog.enabled:
        for proc in snap.top(limit=12):
            if proc.cpu_pct < cfg.cpu_hog_pct:
                continue
            key = f"cpu:{proc.comm}:{proc.pid}"
            live_keys.add(key)
            if not _persisted(state, key, cfg.cpu_hog.ticks):
                continue
            findings.append(
                Finding(
                    key=key,
                    kind="cpu_hog",
                    severity=cfg.cpu_hog.severity,
                    title="CPU 长跑",
                    body=(
                        f"`{proc.comm}` (pid {proc.pid}) 持续占用 **{proc.cpu_pct:.0f}%**"
                        f"（≈{proc.cpu_pct / 100:.1f} 核，已存活 {proc.age_seconds / 3600:.1f} 小时）"
                    ),
                    hint=f"ps -o pid,pcpu,etime,args -p {proc.pid}",
                    pid=proc.pid,
                    value=proc.cpu_pct,
                )
            )

    if cfg.load.enabled:
        key = "load"
        live_keys.add(key)
        if snap.load_ratio >= cfg.load_mult and _persisted(state, key, cfg.load.ticks):
            findings.append(
                Finding(
                    key=key,
                    kind="load",
                    severity=cfg.load.severity,
                    title="负载过高",
                    body=(
                        f"load1 **{snap.load1:.1f}** = {snap.load_ratio:.1f}×{snap.cores} 核，"
                        f"持续 {cfg.load.ticks} 次采样"
                    ),
                    hint="ps -eo pcpu,comm --sort=-pcpu | head",
                    value=snap.load1,
                )
            )

    if cfg.pressure.enabled:
        key = "pressure"
        live_keys.add(key)
        if snap.pressure_some_avg300 >= cfg.pressure_pct and _persisted(
            state, key, cfg.pressure.ticks
        ):
            findings.append(
                Finding(
                    key=key,
                    kind="pressure",
                    severity=cfg.pressure.severity,
                    title="CPU 压力",
                    body=(
                        f"PSI some avg300 = **{snap.pressure_some_avg300:.0f}%**"
                        f"（阈值 {cfg.pressure_pct:.0f}%）—— 任务在排队等 CPU"
                    ),
                    hint="uptime; head -1 /proc/pressure/cpu",
                    value=snap.pressure_some_avg300,
                )
            )

    if cfg.io.enabled:
        for proc in snap.processes:
            if proc.read_gib is None or proc.read_gib < cfg.io_gb:
                continue
            key = f"io:{proc.comm}:{proc.pid}"
            live_keys.add(key)
            if not _persisted(state, key, cfg.io.ticks):
                continue
            findings.append(
                Finding(
                    key=key,
                    kind="io",
                    severity=cfg.io.severity,
                    title="磁盘读取离谱",
                    body=(
                        f"`{proc.comm}` (pid {proc.pid}) 单次采样读了 **{proc.read_gib:.1f} GiB**"
                        f"（阈值 {cfg.io_gb:g} GiB）—— 典型的死循环读"
                    ),
                    hint=f"cat /proc/{proc.pid}/io",
                    pid=proc.pid,
                    value=proc.read_gib,
                )
            )

    if cfg.fd.enabled:
        fd_findings = _fd_chains(snap, cfg)
        for finding in fd_findings:
            live_keys.add(finding.key)
            if _persisted(state, finding.key, cfg.fd.ticks):
                findings.append(finding)

    if cfg.mem.enabled:
        key = "mem"
        live_keys.add(key)
        if snap.mem_ratio * 100 >= cfg.mem_pct and _persisted(state, key, cfg.mem.ticks):
            findings.append(
                Finding(
                    key=key,
                    kind="mem",
                    severity=cfg.mem.severity,
                    title="内存吃紧",
                    body=(
                        f"内存 **{snap.mem_ratio * 100:.0f}%** 已用"
                        f"（{snap.mem_used_mb}/{snap.mem_total_mb} MiB），"
                        f"swap {snap.swap_used_mb}/{snap.swap_total_mb} MiB"
                    ),
                    hint="free -h; ps -eo rss,comm --sort=-rss | head",
                    value=snap.mem_ratio * 100,
                )
            )

    _decay(state, live_keys)

    orphans: list[OrphanCandidate] = []
    if cfg.orphan.enabled:
        orphans = find_orphan_browsers(snap, cfg)
        for cand in orphans:
            live_keys.add(f"orphan:{cand.pid}")
        # Streak bookkeeping happens in the caller for orphans, because a
        # remediated orphan is reported (and removed) in the same tick.
    return findings, orphans