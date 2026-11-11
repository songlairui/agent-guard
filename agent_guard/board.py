"""The ops board: one page, one API, no build step.

Anyone who has watched a machine melt under an agent knows the failure mode is
not "no data" — it is "the data is in a chat log nobody reads".  The board exists
so the state of the host, the incidents, and every action taken on the user's
behalf are on one screen that answers: *what is eating the box right now, and has
anything been done about it?*
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .config import Config
from .store import Store

WEB_DIR = Path(__file__).parent.parent / "web"


def snapshot(store: Store, cfg: Config) -> dict:
    ticks = store.recent_ticks(cfg.history_ticks)
    incidents = store.open_incidents()
    actions = store.recent_actions(50)
    latest = ticks[-1] if ticks else None
    return {
        "host": os.uname().nodename,
        "now": time.time(),
        "tick_seconds": cfg.tick_seconds,
        "fix_enabled": cfg.fix_enabled,
        "latest": latest,
        "history": [
            {
                "ts": t["ts"],
                "load1": t["load1"],
                "cores": t["cores"],
                "mem_used_mb": t["mem_used_mb"],
                "mem_total_mb": t["mem_total_mb"],
                "pressure": t["pressure"],
            }
            for t in ticks
        ],
        "top": json.loads(latest["top_json"]) if latest and latest.get("top_json") else [],
        "incidents": incidents,
        "history_incidents": store.recent_incidents(30),
        "actions": actions,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "agent-guard"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        store: Store = self.server.store  # type: ignore[attr-defined]
        cfg: Config = self.server.cfg  # type: ignore[attr-defined]
        if self.path.startswith("/api/snapshot"):
            payload = json.dumps(snapshot(store, cfg), ensure_ascii=False).encode()
            self._send(200, payload, "application/json; charset=utf-8")
            return
        page = WEB_DIR / "index.html"
        if self.path in ("/", "/index.html") and page.exists():
            self._send(200, page.read_bytes(), "text/html; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        store: Store = self.server.store  # type: ignore[attr-defined]
        if self.path.startswith("/api/incidents/") and self.path.endswith("/ack"):
            key = unquote(self.path[len("/api/incidents/") : -len("/ack")])
            ok = store.ack(key)
            body = json.dumps({"ok": ok, "key": key}).encode()
            self._send(200 if ok else 404, body, "application/json; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def log_message(self, fmt: str, *args) -> None:  # keep journald readable
        print(f"agent-guard board: {fmt % args}", flush=True)


def make_server(store: Store, cfg: Config) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((cfg.board_host, cfg.board_port), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    httpd.cfg = cfg  # type: ignore[attr-defined]
    return httpd


def serve(store: Store, cfg: Config, with_ticker: bool = False) -> None:
    httpd = make_server(store, cfg)
    if with_ticker:
        from .runner import tick_once

        state: dict = {}
        counters: dict = {}

        def loop() -> None:
            while True:
                try:
                    tick_once(cfg, store, counters, state, dry_run=False, fix=cfg.fix_enabled)
                except Exception as exc:  # noqa: BLE001 - the ticker must outlive a bad tick
                    print(f"agent-guard: tick failed: {exc}", flush=True)
                time.sleep(cfg.tick_seconds)

        threading.Thread(target=loop, name="ticker", daemon=True).start()
    print(f"agent-guard board: http://{cfg.board_host}:{cfg.board_port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()