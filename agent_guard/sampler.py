"""One sampling tick: what the host looks like *now*, and the delta since last time.

The delta matters more than the absolute numbers: ``ps`` reports CPU averaged over
a process' whole lifetime, which hides exactly the incident this project exists for
(a process burning 15 cores for 12 hours looks "fine" if it started that way).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import procfs


@dataclass(slots=True)
class ProcessSample:
    pid: int
    comm: str
    ppid: int
    age_seconds: float
    cpu_pct: float  # instantaneous, from the tick delta
    rss_mb: float
    fd_count: int | None
    fd_limit: int | None
    read_gib: float | None  # since the previous tick
    cmdline: str
    parent_dead: bool
    uid: int = -1

    @property
    def fd_ratio(self) -> float:
        if not self.fd_count or not self.fd_limit:
            return 0.0
        return self.fd_count / self.fd_limit


@dataclass(slots=True)
class Snapshot:
    ts: float
    interval: float
    cores: int
    load1: float
    load5: float
    load15: float
    pressure_some_avg300: float
    mem_used_mb: int
    mem_total_mb: int
    swap_used_mb: int
    swap_total_mb: int
    processes: list[ProcessSample] = field(default_factory=list)
    prev: dict = field(default_factory=dict)

    @property
    def mem_ratio(self) -> float:
        return self.mem_used_mb / self.mem_total_mb if self.mem_total_mb else 0.0

    @property
    def load_ratio(self) -> float:
        return self.load1 / self.cores if self.cores else 0.0

    def top(self, limit: int = 8, floor: float = 0.5) -> list[ProcessSample]:
        """Busiest processes.  Kernel threads (empty cmdline) and idle processes are
        noise in a table whose only job is "who is eating the machine"."""
        busy = [p for p in self.processes if p.cmdline and p.cpu_pct >= floor]
        return sorted(busy, key=lambda p: p.cpu_pct, reverse=True)[:limit]


def collect(cfg, counters: dict | None = None) -> Snapshot:
    """Build a snapshot.  ``counters`` carries the previous tick's per-pid numbers."""
    prior = counters or {}
    prior_pids: dict[str, list] = prior.get("pids", {})
    prior_ts: float = prior.get("ts", 0.0)
    now = time.time()
    interval = max(now - prior_ts, 1.0) if prior_ts else 1.0

    tick = procfs.clock_ticks()
    uptime = procfs.uptime_seconds()
    mem = procfs.memory()
    pressure = procfs.cpu_pressure()

    samples: list[ProcessSample] = []
    current: dict[str, list] = {}
    for pid in procfs.all_pids():
        info = procfs.parse_linux_stat(pid) if procfs.HAVE_PROC else None
        if info is None:
            continue
        cmd = procfs.cmdline_of(pid)
        fd_count, fd_limit = (procfs.parse_linux_fd(pid) if procfs.HAVE_PROC else (None, None))
        read_bytes = procfs.parse_linux_io(pid) if procfs.HAVE_PROC else None
        old = prior_pids.get(str(pid))
        cpu_pct = 0.0
        read_gib = None
        if old is not None:
            delta = info.cpu_ticks - old[0]
            if delta > 0:
                cpu_pct = delta / tick / interval * 100.0
            if read_bytes is not None and old[1] is not None and read_bytes >= old[1]:
                read_gib = (read_bytes - old[1]) / 1024**3
        current[str(pid)] = [info.cpu_ticks, read_bytes]

        uid = procfs.owner_uid(pid)
        parent_comm = procfs.parse_linux_stat(info.ppid).comm if info.ppid > 1 and procfs.HAVE_PROC else ""
        parent_dead = info.ppid == 1 or parent_comm == "systemd"
        age = uptime - info.starttime_ticks / tick if procfs.HAVE_PROC else 0.0
        rss_kb = 0
        for line in procfs._read(f"/proc/{pid}/status").splitlines():
            if line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
                break
        samples.append(
            ProcessSample(
                pid=pid,
                comm=info.comm,
                ppid=info.ppid,
                age_seconds=max(age, 0.0),
                cpu_pct=cpu_pct,
                rss_mb=rss_kb / 1024,
                fd_count=fd_count,
                fd_limit=fd_limit,
                read_gib=read_gib,
                cmdline=cmd,
                parent_dead=parent_dead,
                uid=uid,
            )
        )

    counter_out = {"ts": now, "pids": current}
    if counters is not None:
        counters.clear()
        counters.update(counter_out)

    return Snapshot(
        ts=now,
        interval=interval,
        cores=int(mem.get("cores", 1)),
        load1=float(mem.get("load1", 0.0)),
        load5=float(mem.get("load5", 0.0)),
        load15=float(mem.get("load15", 0.0)),
        pressure_some_avg300=pressure["some_avg300"],
        mem_used_mb=int(mem.get("mem_used_mb", 0)),
        mem_total_mb=int(mem.get("mem_total_mb", 0)),
        swap_used_mb=int(mem.get("swap_total_mb", 0)) - int(mem.get("swap_free_mb", 0)),
        swap_total_mb=int(mem.get("swap_total_mb", 0)),
        processes=samples,
        prev=counter_out,
    )