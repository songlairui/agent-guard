"""Configuration: defaults in code, overrides in ``~/.config/agent-guard/config.json``.

Every threshold is written where a reader can see what it means in wall-clock
terms, because the whole product is about *sustained* waste, not spikes.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("AGENT_GUARD_CONFIG", Path.home() / ".config/agent-guard/config.json"))
STATE_DIR = Path(os.environ.get("AGENT_GUARD_STATE", Path.home() / ".local/state/agent-guard"))


@dataclass(slots=True)
class RuleConfig:
    """One check.  ``ticks`` is deliberately expressed in samples, not seconds."""

    enabled: bool = True
    ticks: int = 2  # consecutive samples before the rule speaks
    severity: str = "warn"  # info | warn | critical


@dataclass(slots=True)
class Config:
    # Sampling
    tick_seconds: int = 600
    history_ticks: int = 288  # ~2 days at 10 min
    top_processes: int = 8

    # cpu_hog: one process eating N% of a single core, sustained.
    cpu_hog_pct: float = 300.0
    cpu_hog: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=2, severity="critical"))

    # load: load1 over N x cores, sustained.
    load_mult: float = 2.0
    load: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=2, severity="warn"))

    # pressure: PSI "some avg300" over a percentage.
    pressure_pct: float = 50.0
    pressure: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=1, severity="warn"))

    # io: single process reading N GiB within one tick.
    io_gb: float = 20.0
    io: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=1, severity="warn"))

    # fd: process holding N% of its own soft limit.
    fd_pct: float = 75.0
    fd_min: int = 2000
    fd: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=1, severity="warn"))

    # orphan: a browser automation child whose driver is gone.
    orphan_age_seconds: int = 300
    orphan: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=1, severity="critical"))

    # memory: used ratio of RAM + swap pressure.
    mem_pct: float = 92.0
    mem: RuleConfig = field(default_factory=lambda: RuleConfig(ticks=2, severity="warn"))

    # Remediation
    fix_enabled: bool = True
    fix_max_per_tick: int = 10
    fix_kill_grace_seconds: float = 4.0
    protected_names: list[str] = field(
        default_factory=lambda: ["sshd", "systemd", "systemd-journald", "dbus-daemon", "Xorg"]
    )

    # Board
    board_host: str = "127.0.0.1"
    board_port: int = 7788

    # Escalation: the board is free; a chat channel is not.
    escalation_enabled: bool = False
    escalation_command: str = ""  # e.g. "lark-cli im +messages-send --as bot --user-id ou_xxx --markdown"
    escalate_severities: list[str] = field(default_factory=lambda: ["critical"])
    escalate_after_unacked_seconds: int = 1800
    escalate_cooldown_seconds: int = 6 * 3600

    def rule(self, name: str) -> RuleConfig:
        return getattr(self, name, RuleConfig())

    def to_dict(self) -> dict:
        return asdict(self)


def _merge(base: Config, raw: dict) -> Config:
    known = {f.name for f in fields(Config)}
    for key, value in raw.items():
        if key not in known:
            continue
        current = getattr(base, key)
        if isinstance(current, RuleConfig) and isinstance(value, dict):
            setattr(base, key, RuleConfig(**{**asdict(current), **value}))
        else:
            setattr(base, key, value)
    return base


def load_config(path: Path | None = None, overrides: dict | None = None) -> Config:
    cfg = Config()
    target = path or CONFIG_PATH
    if target.exists():
        try:
            _merge(cfg, json.loads(target.read_text()))
        except (OSError, json.JSONDecodeError) as exc:
            # A broken config must never stop the guard from guarding.
            print(f"agent-guard: ignoring unreadable config {target}: {exc}", flush=True)
    if overrides:
        _merge(cfg, overrides)
    return cfg


def write_default_config(path: Path | None = None) -> Path:
    target = path or CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(Config().to_dict(), indent=2) + "\n")
    return target