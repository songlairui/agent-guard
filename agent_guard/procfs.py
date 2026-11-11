"""Read host and process state without third-party packages.

Linux is the primary target and uses ``/proc`` directly.  Other POSIX hosts fall
back to ``ps`` for the process table (no per-process IO / fd counters); the
samplers degrade instead of lying.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

HAVE_PROC = Path("/proc/self/stat").exists()


@dataclass(slots=True)
class ProcessInfo:
    pid: int
    comm: str
    ppid: int
    state: str
    cpu_ticks: int = 0  # utime + stime, only meaningful on Linux
    starttime_ticks: int = 0
    rss_kb: int = 0
    fd_count: int | None = None
    fd_soft_limit: int | None = None
    read_bytes: int | None = None
    cmdline: str = ""
    extra: dict = field(default_factory=dict)


def _read(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def clock_ticks() -> int:
    return os.sysconf("SC_CLK_TCK")


def uptime_seconds() -> float:
    try:
        return float(_read("/proc/uptime").split()[0])
    except (IndexError, ValueError):
        try:
            import time

            return time.clock_gettime(time.CLOCK_BOOTTIME)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return 0.0


def cpu_count() -> int:
    return os.cpu_count() or 1


def parse_linux_stat(pid: int) -> ProcessInfo | None:
    raw = _read(f"/proc/{pid}/stat")
    if not raw:
        return None
    head, _, tail = raw.rpartition(")")
    fields = tail.split()
    if len(fields) < 20:
        return None
    comm = head[head.find("(") + 1 :] if "(" in head else head
    return ProcessInfo(
        pid=pid,
        comm=comm,
        state=fields[0],
        ppid=int(fields[1]),
        cpu_ticks=int(fields[11]) + int(fields[12]),
        starttime_ticks=int(fields[19]),
    )


def parse_linux_fd(pid: int) -> tuple[int | None, int | None]:
    try:
        fd_count = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        fd_count = None
    limit = None
    for line in _read(f"/proc/{pid}/limits").splitlines():
        if line.startswith("Max open files"):
            parts = line.split()
            if len(parts) >= 4:
                limit = int(parts[3])
            break
    return fd_count, limit


def parse_linux_io(pid: int) -> int | None:
    for line in _read(f"/proc/{pid}/io").splitlines():
        if line.startswith("rchar:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def cmdline_of(pid: int) -> str:
    raw = _read(f"/proc/{pid}/cmdline")
    if raw:
        # Chromium rewrites its argv into one space-joined string, so NULs are
        # not guaranteed.  Normalise both shapes to a space-separated view.
        return raw.replace("\0", " ").strip()
    # macOS / other hosts: ps is the only cheap source.
    if not shutil.which("ps"):
        return ""
    try:
        out = subprocess.run(
            ["ps", "-o", "args=", "-p", str(pid)], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip()


def all_pids() -> list[int]:
    if HAVE_PROC:
        return [int(p) for p in os.listdir("/proc") if p.isdigit()]
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid="], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    return [int(line) for line in out.stdout.split() if line.isdigit()]


def memory() -> dict[str, int | float]:
    """MemTotal / MemAvailable / SwapTotal / SwapFree in MiB, plus load averages."""
    info: dict[str, int | float] = {}
    meminfo = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        if rest:
            try:
                meminfo[key] = int(rest.split()[0]) // 1024  # MiB
            except (IndexError, ValueError):
                continue
    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    info.update(
        mem_total_mb=total,
        mem_available_mb=available,
        mem_used_mb=max(total - available, 0),
        swap_total_mb=meminfo.get("SwapTotal", 0),
        swap_free_mb=meminfo.get("SwapFree", 0),
    )
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = 0.0
    info.update(load1=load1, load5=load5, load15=load15, cores=cpu_count())
    return info


def cpu_pressure() -> dict[str, float]:
    """/proc/pressure/cpu averages, or zeros where PSI is unavailable."""
    out = {"some_avg10": 0.0, "some_avg60": 0.0, "some_avg300": 0.0}
    for line in _read("/proc/pressure/cpu").splitlines():
        if not line.startswith("some"):
            continue
        for token in line.split():
            for key in out:
                name = key.replace("some_", "")
                if token.startswith(f"{name}="):
                    out[key] = float(token.split("=")[1])
    return out


def listening_client_count(port: int) -> int:
    """How many TCP peers are connected to ``port`` (0 when nothing is attached)."""
    if not shutil.which("ss"):
        return 0
    try:
        out = subprocess.run(
            ["ss", "-Htn", f"( sport = :{port} )"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    return len([ln for ln in out.stdout.splitlines() if ln.strip()])

def owner_uid(pid: int) -> int:
    """Owning uid of a process, or -1 when it cannot be read."""
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except OSError:
        return -1


def cgroup_unit(pid: int) -> str:
    """The systemd unit a process belongs to, or "" when it is not supervised."""
    raw = _read(f"/proc/{pid}/cgroup")
    for line in raw.splitlines():
        path = line.split(":", 2)[-1].strip()
        if not path:
            continue
        leaf = path.rstrip("/").rsplit("/", 1)[-1]
        if leaf.endswith(".service") or leaf.endswith(".scope"):
            return leaf
    return ""


def unit_is_active(unit: str) -> bool | None:
    """True/False for an active unit, None when the answer cannot be trusted."""
    if not unit:
        return None
    if not shutil.which("systemctl"):
        return None
    for scope in (["--user"], []):
        try:
            res = subprocess.run(
                ["systemctl", *scope, "is-active", unit], capture_output=True, text=True, timeout=5
            )
        except (OSError, subprocess.SubprocessError):
            continue
        state = res.stdout.strip()
        if state == "active":
            return True
        if state in ("inactive", "failed"):
            return False
    return None


def unit_main_pid(unit: str) -> int | None:
    """MainPID of a unit, or None when it cannot be determined."""
    if not unit or not shutil.which("systemctl"):
        return None
    for scope in (["--user"], []):
        try:
            res = subprocess.run(
                ["systemctl", *scope, "show", unit, "--property=MainPID", "--value"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        value = res.stdout.strip()
        if value.isdigit():
            return int(value)
    return None
