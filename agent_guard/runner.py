"""One tick, start to finish: sample, judge, act, record, escalate.

Kept separate from the CLI so the same function can be driven by a systemd timer
(one process per tick) or by the board's own thread (one long-lived process).
"""

from __future__ import annotations

import time

from . import notify, rules, sampler
from .config import Config
from .remediate import reap_orphan_browsers
from .rules import Finding
from .store import Store


def tick_once(
    cfg: Config,
    store: Store,
    counters: dict,
    state: dict,
    dry_run: bool = False,
    fix: bool = False,
) -> dict:
    started = time.monotonic()
    snap = sampler.collect(cfg, counters)
    findings, orphans = rules.evaluate(snap, cfg, state)

    actions = []
    # A dry run must never touch the system, whatever --fix says.
    acted = fix and not dry_run and bool(orphans)
    if orphans:
        actions = reap_orphan_browsers(orphans, cfg) if acted else []

    if acted:
        for action in actions:
            if action.kind == "reap" and action.ok:
                findings.append(
                    Finding(
                        key=f"reaped:{action.target}",
                        kind="reaped",
                        severity="info",
                        title="已自动清理孤儿浏览器",
                        body=f"`{action.target}` — {action.detail}",
                        hint="",
                    )
                )
            elif action.kind == "skip":
                pid = int(action.target.rsplit(":", 1)[-1]) if action.target.rsplit(":", 1)[-1].isdigit() else None
                findings.append(
                    Finding(
                        key=f"orphan:{action.target}",
                        kind="orphan",
                        severity=cfg.orphan.severity,
                        title="孤儿浏览器（未处理）",
                        body=f"`{action.target}` — {action.detail}",
                        hint="agent-guard status",
                        pid=pid,
                    )
                )
    else:
        for cand in orphans:
            findings.append(
                Finding(
                    key=f"orphan:{cand.pid}",
                    kind="orphan",
                    severity=cfg.orphan.severity,
                    title="孤儿 headless 浏览器",
                    body=(
                        f"`{cand.comm}` (pid {cand.pid}) 存活 {cand.age_seconds / 60:.0f} 分钟，"
                        f"驱动进程已退出，调试端口 :{cand.port or '-'}"
                    ),
                    hint="agent-guard tick --fix    # 或手动 kill -TERM <pid>",
                    pid=cand.pid,
                )
            )

    duration_ms = int((time.monotonic() - started) * 1000)
    result = {
        "ts": snap.ts,
        "load1": snap.load1,
        "cores": snap.cores,
        "mem_ratio": round(snap.mem_ratio * 100, 1),
        "pressure": snap.pressure_some_avg300,
        "findings": [f.key for f in findings],
        "actions": [a.as_dict() for a in actions],
        "duration_ms": duration_ms,
        "dry_run": dry_run,
    }

    if dry_run:
        result["detail"] = [
            {"key": f.key, "severity": f.severity, "title": f.title, "body": f.body} for f in findings
        ]
        return result

    store.record_tick(snap, duration_ms)
    new, closed = store.sync_incidents(findings)
    store.record_actions(actions)
    escalated = notify.escalate_due(store, cfg)

    result.update(
        new=[f.key for f in new],
        closed=closed,
        escalated=[inc["key"] for inc in escalated],
    )
    return result