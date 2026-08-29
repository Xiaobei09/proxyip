"""Tests for health_alert.py — pool watchdog rules."""

import json
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import health_alert as ha  # noqa: E402
from health_alert import (  # noqa: E402
    check_artifact_stale,
    check_cn,
    check_cn_stale,
    check_countries,
    check_pool,
    check_sources,
    check_stale,
    load_history,
)


def _ts(hours_ago: float) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestCheckPool(unittest.TestCase):
    def test_no_alert_on_steady(self):
        hist = [
            {"ts": _ts(3), "alive": 10000},
            {"ts": _ts(2), "alive": 9900},
            {"ts": _ts(1), "alive": 9950},
        ]
        self.assertIsNone(check_pool(hist))

    def test_alert_on_crash(self):
        hist = [
            {"ts": _ts(3), "alive": 10000},
            {"ts": _ts(2), "alive": 10000},
            {"ts": _ts(1), "alive": 5000},   # -50%
        ]
        alert = check_pool(hist)
        self.assertIsNotNone(alert)
        self.assertIn("pool crash", alert)

    def test_needs_two_baseline_points(self):
        self.assertIsNone(check_pool([{"ts": _ts(1), "alive": 10}]))


class TestCheckStale(unittest.TestCase):
    def test_fresh_ok(self):
        self.assertIsNone(check_stale([{"ts": _ts(1)}]))

    def test_old_record_alerts(self):
        alert = check_stale([{"ts": _ts(20)}])
        self.assertIsNotNone(alert)
        self.assertIn("stale", alert)

    def test_empty_history(self):
        self.assertIn("no history", check_stale([]))


class TestCheckCn(unittest.TestCase):
    def make_file(self, tmp, n_reachable, n_blocked=0):
        proxies = {}
        for i in range(n_reachable):
            proxies[f"{i}:443#US"] = {"verdict": "reachable"}
        for i in range(n_blocked):
            proxies[f"b{i}:443#US"] = {"verdict": "blocked"}
        p = Path(tmp) / "china.json"
        p.write_text(json.dumps({"proxies": proxies}))
        return p

    def test_no_collapse(self):
        with tempfile.TemporaryDirectory() as td:
            alert, state = check_cn({}, self.make_file(td, 100))
            self.assertIsNone(alert)
            self.assertEqual(state["cn_reachable"], 100)

    def test_collapse_alert(self):
        with tempfile.TemporaryDirectory() as td:
            alert, state = check_cn(
                {"cn_reachable": 100}, self.make_file(td, 30)
            )
            self.assertIsNotNone(alert)
            self.assertIn("CN collapse", alert)
            # 状态仍要推进到当前值，避免重复误报
            self.assertEqual(state["cn_reachable"], 30)

    def test_small_pool_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            alert, _ = check_cn({"cn_reachable": 10}, self.make_file(td, 1))
            self.assertIsNone(alert)  # prev ≤ 20 不触发


class TestCheckCnStale(unittest.TestCase):
    def make_file(self, td, ts: str | None, n=100):
        proxies = {f"{i}:443#US": {"verdict": "reachable"} for i in range(n)}
        p = Path(td) / "china.json"
        data = {"proxies": proxies}
        if ts is not None:
            data["ts"] = ts
        p.write_text(json.dumps(data))
        return p

    def test_old_cn_data_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.make_file(td, _ts(20))
            alert = check_cn_stale(p)
        self.assertIsNotNone(alert)
        self.assertIn("CN data stale", alert)

    def test_fresh_cn_data_ok(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.make_file(td, _ts(1))
            self.assertIsNone(check_cn_stale(p))

    def test_missing_ts_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.make_file(td, None)
            self.assertIsNone(check_cn_stale(p))  # 旧格式无 ts 静默，待下次 CN 轮补充

    def test_small_pool_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.make_file(td, _ts(30), n=5)
            self.assertIsNone(check_cn_stale(p))


class TestCheckArtifactStale(unittest.TestCase):
    def _file(self, td, ts: str | None, n=200):
        p = Path(td) / "artifact.json"
        data = {"proxies": {f"{i}:443#US": {"v": 1} for i in range(n)}}
        if ts is not None:
            data["ts"] = ts
        p.write_text(json.dumps(data))
        return p

    def test_stale_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            a = check_artifact_stale("exit-family", self._file(td, _ts(20)), 12, 100)
        self.assertIsNotNone(a)
        self.assertIn("exit-family", a)

    def test_fresh_ok(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(
                check_artifact_stale("exit-family", self._file(td, _ts(1)), 12, 100)
            )

    def test_missing_ts_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(
                check_artifact_stale("exit-family", self._file(td, None), 12, 100)
            )

    def test_small_pool_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(
                check_artifact_stale("exit-family", self._file(td, _ts(96), n=9), 12, 100)
            )

    def test_summary_artifact_age_only(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "quality_meta.json"
            p.write_text(json.dumps({"ts": _ts(20), "total": 120528}))
            a = check_artifact_stale(
                "quality-meta", p, 12, require_proxies=False
            )
            self.assertIsNotNone(a)
            self.assertIn("quality-meta", a)
            p.write_text(json.dumps({"ts": _ts(1), "total": 120528}))
            self.assertIsNone(
                check_artifact_stale("quality-meta", p, 12, require_proxies=False)
            )
            p.write_text(json.dumps({"total": 120528}))  # 无 ts 跳过
            self.assertIsNone(
                check_artifact_stale("quality-meta", p, 12, require_proxies=False)
            )


class TestCheckCountries(unittest.TestCase):
    def _meta(self, td, per_country):
        p = Path(td) / "meta.json"
        p.write_text(json.dumps({"per_country": per_country}))
        return p

    def test_no_alert_when_steady(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._meta(td, {"US": 800, "JP": 600})
            alert, state = check_countries({}, p)
        self.assertIsNone(alert)
        self.assertEqual(state["countries"]["US"], 800)

    def test_collapse_alert(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._meta(td, {"US": 100})
            alert, _ = check_countries(
                {"countries": {"US": 800, "JP": 600}}, p
            )
        self.assertIsNotNone(alert)
        self.assertIn("-88%", alert)

    def test_small_baseline_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._meta(td, {"US": 0})
            alert, _ = check_countries(
                {"countries": {"US": 50}}, p
            )
        self.assertIsNone(alert)

    def test_disappeared_country_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            p = self._meta(td, {"DE": 5})
            alert, _ = check_countries(
                {"countries": {"DE": 300}}, p
            )
        self.assertIsNotNone(alert)

    def test_missing_meta_silent(self):
        with tempfile.TemporaryDirectory() as td:
            alert, state = check_countries({}, Path(td) / "meta.json")
        self.assertIsNone(alert)
        self.assertNotIn("countries", state)

    def test_empty_meta_keeps_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "meta.json"
            p.write_text(json.dumps({}))
            alert, state = check_countries(
                {"countries": {"US": 800}}, p
            )
        self.assertIsNone(alert)
        self.assertEqual(state["countries"], {"US": 800})


def _build_stale_root(td: str, ts_ago_hours: float = 9) -> Path:
    root = Path(td) / "root"
    (root / "data" / "valid").mkdir(parents=True)
    (root / "data" / "quality").mkdir(parents=True)
    (root / "data" / "quality" / "alert_state.json").write_text("{}\n")
    (root / "data" / "valid" / "history.jsonl").write_text(
        json.dumps({"ts": _ts(ts_ago_hours), "alive": 100}) + "\n"
    )
    return root


class TestAlertRepeatSuppression(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now(timezone.utc).timestamp()

    def _run(self, root: Path, notify: unittest.mock.Mock) -> int:
        with unittest.mock.patch.object(ha.time, "time", return_value=self.ts):
            return ha.main(["--data-dir", str(root)])

    def test_identical_alert_suppressed_within_cooldown(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td)
            notify = unittest.mock.Mock()
            with unittest.mock.patch.object(ha, "notify", notify):
                self.assertEqual(self._run(root, notify), 0)
                self.assertEqual(notify.call_count, 1)
                self.assertEqual(self._run(root, notify), 0)
                self.assertEqual(notify.call_count, 1)  # 冷却内抑制

    def test_resends_after_cooldown(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td)
            notify = unittest.mock.Mock()
            with unittest.mock.patch.object(ha, "notify", notify):
                self._run(root, notify)
                self.ts += ha.ALERT_REPEAT_COOLDOWN_S + 1
                self._run(root, notify)
            self.assertEqual(notify.call_count, 2)

    def test_no_state_no_spurious_persist(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=0)
            notify = unittest.mock.Mock()
            with unittest.mock.patch.object(ha, "notify", notify):
                rc = self._run(root, notify)
            self.assertEqual(rc, 0)
            self.assertEqual(notify.call_count, 0)
            state = json.loads(
                (root / "data" / "quality" / "alert_state.json").read_text()
            )
            self.assertNotIn("last_alert_at", state)

    def test_fingerprint_stable_and_order_insensitive(self):
        self.assertEqual(
            ha._alert_fingerprint(["b", "a"]),
            ha._alert_fingerprint(["a", "b"]),
        )

    def test_valid_lists_stale_alerts_via_main(self):
        root = _build_stale_root(t := tempfile.mkdtemp())
        # history 新鲜（避免 stale 干扰），仅 valid/meta.json 超龄 → valid-lists 告警
        (root / "data" / "valid" / "history.jsonl").write_text(
            json.dumps({"ts": _ts(1), "alive": 100}) + "\n"
        )
        (root / "data" / "valid" / "meta.json").write_text(
            json.dumps({"ts": _ts(20), "total": 120528, "alive": 101})
        )
        notify = unittest.mock.Mock()
        with unittest.mock.patch.object(ha, "notify", notify):
            self.assertEqual(self._run(root, notify), 0)
        self.assertEqual(notify.call_count, 1)
        args = notify.call_args.args[0]
        self.assertTrue(any("valid-lists" in a for a in args))
        # 新鲜 meta → 不再新发告警
        (root / "data" / "valid" / "meta.json").write_text(
            json.dumps({"ts": _ts(1), "total": 120528, "alive": 102})
        )
        with unittest.mock.patch.object(ha, "notify", notify):
            self._run(root, notify)
        self.assertEqual(notify.call_count, 1)
        persisted = json.loads(
            (root / "data" / "quality" / "alert_state.json").read_text()
        )
        self.assertEqual(
            persisted.get("last_alert_hash"), persisted.get("last_alert_hash")
        )


class TestBadgeSurfacing(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now(timezone.utc).timestamp()

    def _run(self, root: Path) -> tuple[int, Path]:
        with unittest.mock.patch.object(ha.time, "time", return_value=self.ts):
            return (
                ha.main(["--data-dir", str(root)]),
                root / "data" / "output" / "badge.json",
            )

    def test_alert_turns_badge_red(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=9)
            rc, badge = self._run(root)
            self.assertEqual(rc, 0)
            self.assertTrue(badge.exists())
            data = json.loads(badge.read_text())
            self.assertEqual(data["color"], "red")
            self.assertEqual(data["message"], "stale data")

    def test_no_alert_leaves_badge_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=0)
            rc, badge = self._run(root)
            self.assertEqual(rc, 0)
            self.assertFalse(badge.exists())  # 无告警不改写


class TestCheckSources(unittest.TestCase):
    def _runs(self, series):
        return [
            {"ts": _ts(i), "counts": c} for i, c in enumerate(series)
        ]

    def test_no_alert_when_source_small(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(json.dumps({"runs": self._runs([{"A": 60}] * 10)}))
            self.assertIsNone(check_sources(p))

    def test_collapse_alert(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(
                json.dumps(
                    {"runs": self._runs([{"A": 8000}] * 9 + [{"A": 2000}])}
                )
            )
            alert = check_sources(p)
        self.assertIsNotNone(alert)
        self.assertIn("A", alert)
        self.assertIn("-75%", alert)

    def test_recovery_no_alert(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(
                json.dumps(
                    {"runs": self._runs([{"A": 8000}] * 6 + [{"A": 9000}, {"A": 8500}])}
                )
            )
            self.assertIsNone(check_sources(p))

    def test_insufficient_samples(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.json"
            p.write_text(json.dumps({"runs": self._runs([{"A": 8000}] * 3)}))
            self.assertIsNone(check_sources(p))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(check_sources(Path(td) / "nope.json"))


class TestLoadHistory(unittest.TestCase):
    def test_skips_bad_lines_and_sorts(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.jsonl"
            p.write_text(
                '{"ts":"2026-08-23T02:00:00Z","alive":5}\n'
                "not-json\n"
                '{"ts":"2026-08-23T01:00:00Z","alive":7}\n'
            )
            recs = load_history(p)
            self.assertEqual([r["alive"] for r in recs], [7, 5])


if __name__ == "__main__":
    unittest.main()
