"""Command line: ``agent-guard <command>``."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import board, config, notify, procfs, rules, sampler
from .config import Config, load_config
from .runner import tick_once
from .store import Store

STATE: dict = {"streaks": {}}


def _human_age(seconds: float) -> str:
    seconds = max(0, seconds)
    if seconds < 3600:
        return f"{seconds / 60:.0f} 分钟"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} 小时"
    return f"{seconds / 86400:.1f} 天"


def cmd_tick(args, cfg: Config) -> int:
    store = Store()
    result = tick_once(
        cfg,
        store,
        counters={},
        state=STATE,
        dry_run=args.dry_run,
        # --dry-run wins over everything: nothing may be touched.
        fix=cfg.fix_enabled and not args.no_fix and not args.dry_run,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.dry_run:
        findings = result.get("detail", [])
        if not findings:
            print("agent-guard: 本次采样无需告警")
        for finding in findings:
            print(f"[{finding['severity']}] {finding['title']}: {finding['body']}")
        print(json.dumps({"findings": result["findings"]}, ensure_ascii=False))
        return 0
    print(
        f"agent-guard: tick ok  load1={result['load1']:.2f}  mem={result['mem_ratio']}%"
        f"  pressure={result['pressure']:.0f}%  findings={len(result['findings'])}"
        f"  actions={len(result['actions'])}  {result['duration_ms']}ms"
    )
    for action in result["actions"]:
        print(f"  {action['kind']}: {action['target']} — {action['detail']}")
    if result.get("new"):
        print(f"  新告警: {', '.join(result['new'])}")
    if result.get("closed"):
        print(f"  已恢复: {', '.join(result['closed'])}")
    return 0


def cmd_serve(args, cfg: Config) -> int:
    if args.port:
        cfg.board_port = args.port
    if args.host:
        cfg.board_host = args.host
    board.serve(Store(), cfg, with_ticker=args.ticker)
    return 0


def cmd_status(args, cfg: Config) -> int:
    store = Store()
    incidents = store.open_incidents()
    ticks = store.recent_ticks(1)
    latest = ticks[-1] if ticks else None
    if latest:
        age = time.time() - latest["ts"]
        print(
            f"最近一次采样: {age / 60:.1f} 分钟前  load1={latest['load1']:.2f}"
            f"  mem={latest['mem_used_mb']}/{latest['mem_total_mb']} MiB"
            f"  pressure={latest['pressure']:.0f}%"
        )
    else:
        print("还没有采样记录，先跑一次 `agent-guard tick`")
    if not incidents:
        print("当前无未处理告警")
        return 0
    print(f"未处理告警 {len(incidents)} 条:")
    now = time.time()
    for inc in incidents:
        acked = "已认领" if inc["acked_at"] else "未认领"
        print(
            f"  [{inc['severity']}] {inc['title']}  key={inc['key']}"
            f"  已持续 {_human_age(now - inc['first_seen'])} · {acked}"
        )
        print(f"      {inc['body']}")
        if inc["hint"]:
            print(f"      → {inc['hint']}")
    return 0


def cmd_ack(args, cfg: Config) -> int:
    ok = Store().ack(args.key, who="cli")
    print("已认领" if ok else f"没有这条未处理告警: {args.key}")
    return 0 if ok else 1


def cmd_doctor(args, cfg: Config) -> int:
    checks = [
        ("读取 /proc", procfs.HAVE_PROC),
        ("/proc/pressure（PSI）", Path("/proc/pressure/cpu").exists()),
        ("ss（判断调试端口客户端）", bool(__import__("shutil").which("ss"))),
        ("sqlite3 存储位置", True),
    ]
    print(f"agent-guard doctor  主机 {__import__('os').uname().nodename}")
    for name, ok in checks:
        print(f"  {'✓' if ok else '✗'} {name}")
    print(f"  配置: {config.CONFIG_PATH} ({'存在' if config.CONFIG_PATH.exists() else '未创建，使用默认值'})")
    print(f"  状态: {config.STATE_DIR}")
    if not procfs.HAVE_PROC:
        print("  注意: 非 Linux 主机只会采样进程名与 CPU，fd / IO / PSI 规则自动跳过")
    return 0


def cmd_init_config(args, cfg: Config) -> int:
    path = config.write_default_config()
    print(f"已写入默认配置: {path}")
    return 0


def cmd_snapshot(args, cfg: Config) -> int:
    snap = sampler.collect(cfg, {})
    print(json.dumps(
        {
            "ts": snap.ts,
            "cores": snap.cores,
            "load": [snap.load1, snap.load5, snap.load15],
            "pressure_some_avg300": snap.pressure_some_avg300,
            "mem": [snap.mem_used_mb, snap.mem_total_mb],
            "top": [
                {"pid": p.pid, "comm": p.comm, "cpu": round(p.cpu_pct, 1)} for p in snap.top(10)
            ],
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-guard",
        description="Keep the machine usable while AI agents run.",
    )
    parser.add_argument("--config", type=Path, default=None, help="配置文件路径")
    sub = parser.add_subparsers(dest="command", required=True)

    tick = sub.add_parser("tick", help="执行一次采样 + 判定 + 处置（timer / cron 用）")
    tick.add_argument("--dry-run", action="store_true", help="只打印，不写库、不处置")
    tick.add_argument("--no-fix", action="store_true", help="只报警，不自动清理")
    tick.add_argument("--json", action="store_true", help="输出 JSON")
    tick.set_defaults(func=cmd_tick)

    serve = sub.add_parser("serve", help="启动操作看板")
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--host", default=None)
    serve.add_argument("--ticker", action="store_true", help="由本进程自己按 tick 间隔采样")
    serve.set_defaults(func=cmd_serve)

    status = sub.add_parser("status", help="终端里看当前告警")
    status.set_defaults(func=cmd_status)

    ack = sub.add_parser("ack", help="认领一条告警，停止升级")
    ack.add_argument("key")
    ack.set_defaults(func=cmd_ack)

    sub.add_parser("doctor", help="检查平台能力").set_defaults(func=cmd_doctor)
    sub.add_parser("init-config", help="写出默认配置文件").set_defaults(func=cmd_init_config)
    sub.add_parser("snapshot", help="打印一次原始采样").set_defaults(func=cmd_snapshot)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    try:
        return args.func(args, cfg)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())