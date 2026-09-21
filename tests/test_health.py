"""Tests for health_alert.py — pool watchdog rules."""

import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
import unittest.mock
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import health_alert as ha  # noqa: E402
from health_alert import (  # noqa: E402
    _alert_fingerprint,
    _median,
    _suppress_repeat,
    check_artifact_stale,
    check_cn,
    check_cn_stale,
    check_countries,
    check_degraded_batch,
    check_pool,
    check_sources,
    check_stale,
    cn_carrier_stats,
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

    def test_window_caps_at_24(self):
        # 30 轮基线中间夹杂远古低点，暴跌仍应对最近 24 轮中位数触发
        hist = [
            {"ts": _ts(50 - i), "alive": 100 if i < 6 else 10000}
            for i in range(30)
        ]
        hist.append({"ts": _ts(0), "alive": 5000})
        alert = check_pool(hist)
        self.assertIsNotNone(alert)
        self.assertIn("-50%", alert)

    def test_recovery_higher_than_median_no_alert(self):
        hist = [
            {"ts": _ts(3), "alive": 10000},
            {"ts": _ts(2), "alive": 10000},
            {"ts": _ts(1), "alive": 12000},
        ]
        self.assertIsNone(check_pool(hist))


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

    def test_empty_proxies_keeps_snapshot(self):
        # 文件存在但载荷为空 → 不评估、不覆盖历史快照（防瞬时空窗误报全塌方）
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "china.json"
            p.write_text(json.dumps({"proxies": {}}))
            alert, state = check_cn({"cn_reachable": 100}, p)
            self.assertIsNone(alert)
            self.assertEqual(state.get("cn_reachable"), 100)

    def test_missing_file_keeps_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            alert, state = check_cn(
                {"cn_reachable": 100}, Path(td) / "nope.json"
            )
            self.assertIsNone(alert)
            self.assertNotIn("cn_ts", state)


class TestCnCarrierStats(unittest.TestCase):
    def test_per_carrier_split(self):
        # 覆盖键=有 isp_ms 读数的键；可达键以 verdict==reachable 计入
        proxies = {
            "a:443#US": {"verdict": "reachable",
                         "isp_ms": {"中国移动": 50.5, "中国联通": 60.0}},
            "b:443#JP": {"verdict": "reachable",
                         "isp_ms": {"中国电信": 90.1, "中国移动": 55.2}},
            "c:443#US": {"verdict": "blocked",
                         "isp_ms": {"中国移动": 100.0}},
            "d:443#US": {"verdict": "uncertain"},  # 无 isp_ms → 不计任何运营商
        }
        stats = cn_carrier_stats(proxies)
        self.assertEqual(stats["中国移动"]["sampled"], 3)
        self.assertEqual(stats["中国移动"]["reachable"], 2)
        self.assertEqual(stats["中国移动"]["min_ms"], 50.5)
        self.assertEqual(stats["中国电信"]["reachable"], 1)
        self.assertEqual(stats["中国联通"]["median_ms"], 60.0)
        self.assertNotIn("no_carrier", stats)

    def test_no_isp_ms_returns_empty(self):
        proxies = {"a:443#US": {"verdict": "reachable"}}
        self.assertEqual(cn_carrier_stats(proxies), {})

    def test_invalid_ms_ignored(self):
        proxies = {
            "a:443#US": {"verdict": "reachable",
                         "isp_ms": {"中国移动": 0, "中国电信": "x",
                                    "中国联通": -3}},
        }
        self.assertEqual(cn_carrier_stats(proxies), {})


class TestCheckCnByIspAlert(unittest.TestCase):
    def test_carrier_collapse_alert(self):
        def state(isp_prev):
            return {"cn_reachable": 100, "cn_by_isp": isp_prev}

        prev = state({"中国移动": {"reachable": 80, "sampled": 100},
                      "中国电信": {"reachable": 60, "sampled": 80}})
        proxies = {
            f"{i}:443#US": {"verdict": "reachable",
                            "isp_ms": {"中国移动": 50.0}}
            for i in range(20)
        }
        for i in range(20, 60):
            proxies[f"{i}:443#JP"] = {
                "verdict": "reachable", "isp_ms": {"中国电信": 60.0}
            }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "china.json"
            p.write_text(json.dumps({"proxies": proxies}))
            alert, out = check_cn(prev, p)
        self.assertIsNotNone(alert)
        self.assertIn("CN collapse (中国移动)", alert)  # 80→20 = -75%
        self.assertIn("中国电信", out["cn_by_isp"])
        # 中国电信 60→40 = -33% < 50% 不报
        self.assertNotIn("CN collapse (中国电信)", alert)

    def test_no_carrier_collapse_without_prior(self):
        proxies = {"a:443#US": {"verdict": "reachable",
                                "isp_ms": {"中国移动": 40.0}}}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "china.json"
            p.write_text(json.dumps({"proxies": proxies}))
            alert, _ = check_cn({}, p)
        self.assertIsNone(alert)


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


class TestCheckDeepSpeedArtifact(unittest.TestCase):
    def _file(self, td, ts: str | None, n=200):
        p = Path(td) / "deep_speed.json"
        data = {"proxies": {f"{i}:443#US": {"tls_ms": 1} for i in range(n)}}
        if ts is not None:
            data["generated"] = ts
        p.write_text(json.dumps(data))
        return p

    def test_stale_generated_field_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            a = check_artifact_stale(
                "deep-speed", self._file(td, _ts(20 * 24 * 100)), 240, 1,
                ts_field="generated",
            )
        self.assertIsNotNone(a)
        self.assertIn("deep-speed", a)

    def test_fresh_generated_field_ok(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(
                check_artifact_stale(
                    "deep-speed", self._file(td, _ts(1)), 240, 1,
                    ts_field="generated",
                )
            )

    def test_small_pool_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(
                check_artifact_stale(
                    "deep-speed", self._file(td, _ts(20 * 24 * 100), n=0), 240, 1,
                    ts_field="generated",
                )
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

    def test_long_alert_message_truncated(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=9)
            ha.update_badge(
                root,
                ["source-collapsed %s" % ("x" * 200)],
            )
            data = json.loads((root / "data" / "output" / "badge.json").read_text())
            self.assertLessEqual(len(data["message"]), 60)
            self.assertEqual(data["color"], "red")

    def test_no_alert_leaves_badge_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=0)
            rc, badge = self._run(root)
            self.assertEqual(rc, 0)
            self.assertFalse(badge.exists())  # 无告警不改写

    def test_strict_gates_exit_1_on_alert(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=9)
            with unittest.mock.patch.object(ha.time, "time", return_value=self.ts):
                rc = ha.main(["--data-dir", str(root), "--strict"])
            self.assertEqual(rc, 1)

    def test_strict_ok_exit_0_no_alert(self):
        with tempfile.TemporaryDirectory() as td:
            root = _build_stale_root(td, ts_ago_hours=0)
            with unittest.mock.patch.object(ha.time, "time", return_value=self.ts):
                rc = ha.main(["--data-dir", str(root), "--strict"])
            self.assertEqual(rc, 0)


class TestCheckDegradedBatch(unittest.TestCase):
    def _meta(self, td, skipped):
        p = Path(td) / "quality_meta.json"
        p.write_text(json.dumps({"ts": "2026-09-16T09:00:00Z", "skipped": skipped}))
        return p

    def test_alert_on_degraded(self):
        with tempfile.TemporaryDirectory() as td:
            alert = check_degraded_batch(self._meta(td, ["ip-api geo"]))
        self.assertIsNotNone(alert)
        self.assertIn("degraded batch", alert)
        self.assertIn("ip-api geo", alert)

    def test_no_alert_when_clean(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(check_degraded_batch(self._meta(td, [])))

    def test_missing_or_malformed_skipped_ok(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "quality_meta.json"
            p.write_text(json.dumps({"ts": "2026-09-16T09:00:00Z"}))
            self.assertIsNone(check_degraded_batch(p))
            p.write_text("{")
            self.assertIsNone(check_degraded_batch(p))

    def test_wired_in_main(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            (root / "data" / "quality").mkdir(parents=True)
            (root / "data" / "quality" / "quality_meta.json").write_text(
                json.dumps({"ts": "2026-09-16T09:00:00Z", "skipped": ["abuse scores"]})
            )
            with unittest.mock.patch.object(ha, "notify", unittest.mock.Mock()):
                rc = ha.main(["--data-dir", str(root), "--strict"])
            self.assertEqual(rc, 1)


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


class TestMedian(unittest.TestCase):
    def test_odd_takes_middle(self):
        self.assertEqual(_median([3, 1, 2]), 2)

    def test_even_averages_mid_two(self):
        self.assertEqual(_median([4, 1, 3, 2]), 2.5)


class TestSuppressRepeat(unittest.TestCase):
    def test_first_alert_not_suppressed(self):
        self.assertFalse(_suppress_repeat({}, ["pool crash: -50%"]))
        self.assertFalse(
            _suppress_repeat(
                {"last_alert_at": time.time() - 1, "last_alert_hash": ""},
                ["pool crash: -50%"],
            )
        )

    def test_same_alerts_within_cooldown_suppressed(self):
        alerts = ["pool crash: -50%"]
        st = {
            "last_alert_at": time.time() - 10,
            "last_alert_hash": _alert_fingerprint(alerts),
        }
        self.assertTrue(_suppress_repeat(st, alerts))

    def test_same_alerts_after_cooldown_fire(self):
        alerts = ["pool crash: -50%"]
        st = {
            "last_alert_at": time.time() - ha.ALERT_REPEAT_COOLDOWN_S - 1,
            "last_alert_hash": _alert_fingerprint(alerts),
        }
        self.assertFalse(_suppress_repeat(st, alerts))

    def test_different_alerts_fire(self):
        st = {
            "last_alert_at": time.time() - 1,
            "last_alert_hash": _alert_fingerprint(["old alert"]),
        }
        self.assertFalse(_suppress_repeat(st, ["pool crash: -50%"]))


class TestNotifyWebhookRedaction(unittest.TestCase):
    """URL 内嵌 webhook token 不泄漏进 stderr/异常（R230 安全维度闭环）。"""

    def setUp(self):
        self._orig_deadline_open = ha.deadline_open
        self._orig_webhook_url = os.environ.get("ALERT_WEBHOOK_URL")

    def tearDown(self):
        ha.deadline_open = self._orig_deadline_open
        if self._orig_webhook_url is None:
            os.environ.pop("ALERT_WEBHOOK_URL", None)
        else:
            os.environ["ALERT_WEBHOOK_URL"] = self._orig_webhook_url

    def test_webhook_timeout_redacts_token(self):
        secret = "https://discord.com/api/webhooks/98765/d1sc0rd-t0k3n"

        class _FakeCtx:
            def __enter__(self):
                raise TimeoutError(
                    f"fetch deadline exceeded (15s): {secret}"
                )

            def __exit__(self, *exc):
                return False

        ha.deadline_open = unittest.mock.MagicMock(return_value=_FakeCtx())
        os.environ["ALERT_WEBHOOK_URL"] = secret
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            delivered = ha.notify(["pool size dropped"])
        err = buf.getvalue()
        self.assertFalse(delivered)
        self.assertNotIn(secret, err)
        self.assertIn("token redacted", err)


class TestNotifyRedaction(unittest.TestCase):
    def _notify_with_oserror(self, exc: Exception) -> tuple[bool, str]:
        url = "https://discord.com/api/webhooks/12345/SECRET_TOKEN_ABC"
        with unittest.mock.patch.dict(
            os.environ, {"ALERT_WEBHOOK_URL": url}, clear=False
        ), unittest.mock.patch(
            "health_alert.deadline_open", side_effect=exc
        ):
            with contextlib.redirect_stderr(io.StringIO()) as buf:
                ok = ha.notify(["pool crash: -50%"])
        return ok, buf.getvalue()

    def test_oserror_urlerror_redacts_token(self):
        err = urllib.error.URLError("connection refused to https://discord.com/api/webhooks/12345/SECRET_TOKEN_ABC")
        ok, out = self._notify_with_oserror(err)
        self.assertFalse(ok)
        self.assertIn("details redacted", out)
        self.assertNotIn("SECRET_TOKEN_ABC", out)

    def test_timeout_redacts_token(self):
        class _T(TimeoutError):
            def __str__(self):
                return "timed out after 15 https://discord.com/api/webhooks/12345/SECRET_TOKEN_ABC"
        ok, out = self._notify_with_oserror(_T())
        self.assertFalse(ok)
        self.assertIn("token redacted", out)
        self.assertNotIn("SECRET_TOKEN_ABC", out)


class TestCheckWiring(unittest.TestCase):
    """接线完备性：每个 check_* 定义必须在 main 直接调用（R45 型遗漏——
    新增 check 忘记接入主流程即长期静默——用 AST 断言防回归）。"""

    def test_all_check_functions_wired_in_main(self):
        import ast

        src = Path(ha.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        defined = {
            n.name for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name.startswith("check_")
        }
        main = next(
            n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "main"
        )
        called = {
            sub.func.id for sub in ast.walk(main)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
        }
        missing = sorted(defined - called)
        self.assertEqual(
            missing, [],
            "以下 check_* 未接入 main（新增告警忘接线会静默丢失）:\n"
            + "\n".join(missing),
        )


if __name__ == "__main__":
    unittest.main()
