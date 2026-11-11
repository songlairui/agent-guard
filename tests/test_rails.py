"""Rails that decide whether agent-guard may kill something.

These exist because the first version *did* kill an innocent process: a user
daemon whose command line happened to contain ``--headless``.  Every test here
corresponds to a way that could happen again.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from agent_guard import procfs, remediate, rules
from agent_guard.config import Config
from agent_guard.rules import OrphanCandidate
from agent_guard.sampler import ProcessSample


def proc(comm: str, cmdline: str, **kw) -> ProcessSample:
    return ProcessSample(
        pid=kw.get("pid", 1000),
        comm=comm,
        ppid=kw.get("ppid", 1),
        age_seconds=kw.get("age_seconds", 900.0),
        cpu_pct=kw.get("cpu_pct", 0.0),
        rss_mb=0.0,
        fd_count=None,
        fd_limit=None,
        read_gib=None,
        cmdline=cmdline,
        parent_dead=kw.get("parent_dead", True),
        uid=kw.get("uid", os.getuid()),
    )


CHROME_HEADLESS = (
    "/opt/google/chrome/chrome --headless=new --remote-debugging-port=9333 "
    "--user-data-dir=/tmp/probe --use-angle=swiftshader-webgl about:blank"
)


class TestLooksLikeBrowser(unittest.TestCase):
    def test_chrome_automation_is_a_browser(self) -> None:
        self.assertTrue(rules.looks_like_browser(proc("chrome", CHROME_HEADLESS)))

    def test_daemon_with_headless_flag_is_not_a_browser(self) -> None:
        # The ducter incident: `ducter up --headless --port 7777`.
        daemon = proc("ducter", "/home/u/.local/bin/ducter up --headless --port 7777")
        self.assertFalse(rules.looks_like_browser(daemon))

    def test_browser_without_automation_flags_is_out_of_scope(self) -> None:
        # A human's own Chrome: no profile dir, no debugging port.
        self.assertFalse(rules.looks_like_browser(proc("chrome", "/opt/google/chrome/chrome")))

    def test_headless_shell_counts(self) -> None:
        shell = proc("headless_shell", "/x/headless_shell --headless --user-data-dir=/tmp/a")
        self.assertTrue(rules.looks_like_browser(shell))


class TestFindOrphans(unittest.TestCase):
    def test_live_driver_is_never_a_candidate(self) -> None:
        snap = mock.Mock(processes=[proc("chrome", CHROME_HEADLESS, parent_dead=False)])
        self.assertEqual(rules.find_orphan_browsers(snap, Config()), [])

    def test_young_orphan_is_skipped(self) -> None:
        cfg = Config()
        snap = mock.Mock(
            processes=[proc("chrome", CHROME_HEADLESS, age_seconds=cfg.orphan_age_seconds - 1)]
        )
        self.assertEqual(rules.find_orphan_browsers(snap, cfg), [])

    def test_old_orphan_is_a_candidate(self) -> None:
        cfg = Config()
        snap = mock.Mock(processes=[proc("chrome", CHROME_HEADLESS, age_seconds=900)])
        found = rules.find_orphan_browsers(snap, cfg)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].port, "9333")


class TestAssess(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = Config()
        self.cand = OrphanCandidate(
            pid=4242,
            age_seconds=900,
            comm="chrome",
            port="9333",
            clients=0,
            cmdline=CHROME_HEADLESS,
            uid=os.getuid(),
        )

    def test_clean_candidate_passes(self) -> None:
        with mock.patch.object(remediate, "_supervised", return_value=""), mock.patch.object(
            remediate, "_still_orphaned", return_value=True
        ):
            self.assertEqual(remediate.assess(self.cand, set(), os.getuid()), "")

    def test_non_browser_comm_is_refused(self) -> None:
        self.cand.comm = "ducter"
        reason = remediate.assess(self.cand, set(), os.getuid())
        self.assertIn("不是已知浏览器进程", reason)

    def test_foreign_uid_is_refused(self) -> None:
        self.cand.uid = os.getuid() + 1
        self.assertIn("其他用户", remediate.assess(self.cand, set(), os.getuid()))

    def test_live_client_is_refused(self) -> None:
        self.cand.clients = 2
        self.assertIn("客户端", remediate.assess(self.cand, set(), os.getuid()))

    def test_supervised_unit_is_refused(self) -> None:
        with mock.patch.object(remediate, "_supervised", return_value="ducter.service"):
            self.assertIn("systemd 单元", remediate.assess(self.cand, set(), os.getuid()))

    def test_returning_parent_is_refused(self) -> None:
        with mock.patch.object(remediate, "_supervised", return_value=""), mock.patch.object(
            remediate, "_still_orphaned", return_value=False
        ):
            self.assertIn("父进程已恢复", remediate.assess(self.cand, set(), os.getuid()))


class TestSupervision(unittest.TestCase):
    def test_scope_is_not_supervision(self) -> None:
        # An agent's browser lands in a transient scope; that is not ownership.
        with mock.patch.object(procfs, "cgroup_unit", return_value="app-com.google.Chrome-173871.scope"):
            self.assertEqual(remediate._supervised(173871), "")

    def test_service_main_pid_is_supervision(self) -> None:
        with mock.patch.object(procfs, "cgroup_unit", return_value="ducter.service"), mock.patch.object(
            procfs, "unit_main_pid", return_value=42
        ):
            self.assertEqual(remediate._supervised(42), "ducter.service")
            self.assertEqual(remediate._supervised(43), "")

    def test_unknown_unit_fails_closed(self) -> None:
        with mock.patch.object(procfs, "cgroup_unit", return_value="ducter.service"), mock.patch.object(
            procfs, "unit_main_pid", return_value=None
        ):
            self.assertEqual(remediate._supervised(99), "ducter.service")


class TestReap(unittest.TestCase):
    def test_fix_disabled_does_nothing(self) -> None:
        cfg = Config()
        cfg.fix_enabled = False
        cand = OrphanCandidate(1, 900, "chrome", "9333", 0, CHROME_HEADLESS, os.getuid())
        with mock.patch.object(remediate, "_kill") as kill:
            self.assertEqual(remediate.reap_orphan_browsers([cand], cfg), [])
            kill.assert_not_called()

    def test_refusal_is_recorded_not_silent(self) -> None:
        cfg = Config()
        cand = OrphanCandidate(1, 900, "ducter", "7777", 0, "ducter up --headless", os.getuid())
        with mock.patch.object(remediate, "_kill") as kill:
            actions = remediate.reap_orphan_browsers([cand], cfg)
            kill.assert_not_called()
        self.assertEqual(actions[0].kind, "skip")
        self.assertIn("不是已知浏览器进程", actions[0].detail)

    def test_safe_candidate_is_killed(self) -> None:
        cfg = Config()
        cand = OrphanCandidate(4242, 900, "chrome", "9333", 0, CHROME_HEADLESS, os.getuid())
        with mock.patch.object(remediate, "_supervised", return_value=""), mock.patch.object(
            remediate, "_still_orphaned", return_value=True
        ), mock.patch.object(remediate, "_kill", return_value=True) as kill:
            actions = remediate.reap_orphan_browsers([cand], cfg)
            kill.assert_called_once()
        self.assertEqual(actions[0].kind, "reap")
        self.assertTrue(actions[0].ok)


if __name__ == "__main__":
    unittest.main()