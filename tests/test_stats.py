"""Tests for generate_stats.py helpers and chart builders."""

import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import generate_stats as gs


def svg_ok(svg: str) -> bool:
    ET.fromstring(svg)
    return True


class TestTicks(unittest.TestCase):
    def test_nice_ticks_from_zero(self):
        self.assertEqual(gs.nice_ticks(7500), [0, 2000, 4000, 6000])
        self.assertEqual(gs.nice_ticks(0), [0])

    def test_fmt_tick(self):
        self.assertEqual(gs.fmt_tick(2500), "2500")
        self.assertEqual(gs.fmt_tick(98.8), "98.8")
        self.assertEqual(gs.fmt_tick(99.0), "99")


class TestTimeHelpers(unittest.TestCase):
    def test_to_epoch(self):
        self.assertEqual(gs.to_epoch("2026-08-12T00:00:00Z"), 1786492800)
        self.assertIsNone(gs.to_epoch(""))
        self.assertIsNone(gs.to_epoch("garbage"))

    def test_fmt_ago(self):
        self.assertEqual(gs.fmt_ago(35), "35s ago")
        self.assertEqual(gs.fmt_ago(90), "1m ago")
        self.assertEqual(gs.fmt_ago(5400), "1h 30m ago")
        self.assertEqual(gs.fmt_ago(3600), "1h ago")
        self.assertEqual(gs.fmt_ago(2 * 86400 + 3600), "2d ago")


class TestBuilders(unittest.TestCase):
    HISTORY = [
        {"ts": "2026-08-12T00:00:00Z", "unique": 100, "total": 200, "countries": 5, "ports": 3, "sets": {}, "added": 10, "removed": 5},
        {"ts": "2026-08-12T01:00:00Z", "unique": 110, "total": 210, "countries": 5, "ports": 3, "sets": {}, "added": 12, "removed": 2},
    ]
    VALID_HISTORY = [
        {"ts": "2026-08-12T00:30:00Z", "total": 200, "checked": 200, "alive": 195, "dead": 5},
        {"ts": "2026-08-12T01:30:00Z", "total": 210, "checked": 210, "alive": 205, "dead": 5},
    ]
    META = {
        "alive": 205,
        "checked": 210,
        "sets": {"all": 205, "europe": 90, "hot": 160, "asia": 50},
        "per_country": {"US": 100, "JP": 60, "DE": 45},
        "per_port": {"443": 120, "8443": 85},
        "latency": {"avg_ms": 300.0, "median_ms": 280.0, "p90_ms": 500.0, "max_ms": 1000.0},
        "latency_dist": {"0-100": 20, "100-200": 50, "500-1000": 30},
        "speed": {"avg_mbps": 0.8, "median_mbps": 0.7, "p90_mbps": 1.5, "max_mbps": 5.0},
        "speed_dist": {"0-0.5": 30, "0.5-1": 100, "1-2": 60, "2-5": 15},
    }
    CN_DATA = {
        "proxies": {
            "1.1.1.1:80#US": {"verdict": "reachable"},
            "2.2.2.2:80#JP": {"verdict": "skipped"},
            "3.3.3.3:80#DE": {"verdict": "reachable"},
            "4.4.4.4:80#FR": {"verdict": "uncertain"},
        }
    }
    FAMILY_DATA = {
        "proxies": {
            "1.1.1.1:80#US": {"family": "ipv4"},
            "2.2.2.2:80#JP": {"family": "ipv6"},
            "3.3.3.3:80#DE": {"family": "ipv6"},
            "4.4.4.4:80#FR": {"family": "unknown"},
        }
    }
    REP_DATA = {
        "proxies": {
            "1.1.1.1:80#US": {"score": 95, "sources": ["ipquery", "ffraud", "netcoffee"]},
            "2.2.2.2:80#JP": {"score": 80, "sources": ["ipquery", "ffraud"]},
            "3.3.3.3:80#DE": {"score": 80, "sources": ["ipquery", "ffraud", "netcoffee", "ncgy"]},
            "4.4.4.4:80#FR": {"score": 50, "sources": ["ipquery", "ffraud", "ipdata"]},
        }
    }
    SOURCE_STATS = {
        "sources": {
            "cm": {"total": 500, "unique": 300, "overlap": 200},
            "sp": {"total": 400, "unique": 250, "overlap": 150},
            "kr": {"total": 200, "unique": 150, "overlap": 50},
        }
    }
    QUALITY_META = {
        "by_type": {"DC": 50, "RES": 100, "MOB": 30, "PROXY": 25},
    }

    def test_all_charts_valid_svg(self):
        builders = {
            "chart_combo.svg": gs.build_combo(self.HISTORY, self.VALID_HISTORY),
            "chart_country.svg": gs.build_country(self.META),
            "chart_port.svg": gs.build_port(self.META),
            "chart_churn.svg": gs.build_churn(self.HISTORY),
            "chart_latency_speed.svg": gs.build_latency_speed(self.META),
            "chart_sets.svg": gs.build_sets(self.META),
            "chart_cn.svg": gs.build_cn(self.CN_DATA),
            "chart_family.svg": gs.build_family(self.FAMILY_DATA),
            "chart_source_avail.svg": gs.build_source_avail(self.REP_DATA),
            "chart_rep.svg": gs.build_rep(self.REP_DATA),
            "chart_source_stats.svg": gs.build_source_stats(self.SOURCE_STATS),
        }
        for name, svg in builders.items():
            with self.subTest(name=name):
                svg_ok(svg)

    def test_empty_inputs_placeholders(self):
        self.assertIn("暂无数据", gs.build_combo([], []))
        self.assertIn("暂无延迟/速度", gs.build_latency_speed({}))
        self.assertIn("暂无子集数据", gs.build_sets({}))
        self.assertIn("暂无大陆可达性", gs.build_cn({}))
        self.assertIn("暂无出口族数据", gs.build_family({}))
        self.assertIn("暂无信誉分数据", gs.build_rep({}))
        self.assertIn("暂无信誉源数据", gs.build_source_avail({}))
        self.assertIn("暂无信誉源统计", gs.build_source_stats({}))

    def test_chart_latency_speed_has_bars_and_labels(self):
        svg = gs.build_latency_speed(self.META)
        svg_ok(svg)
        self.assertIn("0-100", svg)
        self.assertIn("500-1000", svg)
        self.assertIn("0-0.5", svg)
        self.assertIn("2-5", svg)
        self.assertGreaterEqual(svg.count("<rect"), 6)

    def test_escapes_labels(self):
        svg = gs.build_churn([{"ts": '2026-08-12T00:00:00Z&"<x>', "added": 1, "removed": 0}])
        svg_ok(svg)

    def test_legend_shows_latest_value(self):
        svg = gs.build_combo(self.HISTORY, self.VALID_HISTORY)
        self.assertIn("去重 110", svg)
        self.assertIn("存活率", svg)

    def test_cn_chart_sorted_by_count(self):
        svg = gs.build_cn(self.CN_DATA)
        svg_ok(svg)
        self.assertIn("可达", svg)
        self.assertIn("uncertain", svg)


class TestMain(unittest.TestCase):
    def test_end_to_end_writes_all_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            data_dir = base / "data"
            (data_dir / "valid").mkdir(parents=True)
            (data_dir / "quality").mkdir(parents=True)
            (data_dir / "quality" / "history.jsonl").write_text(
                "\n".join(json.dumps(r) for r in TestBuilders.HISTORY) + "\n"
            )
            (data_dir / "valid" / "history.jsonl").write_text(
                "\n".join(json.dumps(r) for r in TestBuilders.VALID_HISTORY) + "\n"
            )
            (data_dir / "valid" / "meta.json").write_text(
                json.dumps(TestBuilders.META)
            )
            (data_dir / "quality" / "quality_meta.json").write_text(
                json.dumps(TestBuilders.QUALITY_META)
            )
            (data_dir / "quality" / "china.json").write_text(
                json.dumps(TestBuilders.CN_DATA)
            )
            (data_dir / "quality" / "exit_family.json").write_text(
                json.dumps(TestBuilders.FAMILY_DATA)
            )
            (data_dir / "quality" / "reputation.json").write_text(
                json.dumps(TestBuilders.REP_DATA)
            )
            (data_dir / "quality" / "source_stats.json").write_text(
                json.dumps({})
            )
            out = base / "out"
            rc = gs.main(["--data-dir", str(data_dir), "--out", str(out)])
            self.assertEqual(rc, 0)
            stats = json.loads((out / "stats.json").read_text())
            self.assertEqual(stats["unique"], 110)
            self.assertEqual(stats["alive"], 205)
            self.assertEqual(stats["alive_rate"], 0.9762)
            self.assertIn("age_s", stats)
            self.assertIn("updated_ago", stats)
            self.assertIn("stale", stats)
            badge = json.loads((out / "badge.json").read_text())
            self.assertEqual(badge["label"], "status")
            self.assertIn(badge["color"], ("brightgreen", "red"))
            for f in (
                "chart_combo.svg", "chart_country.svg", "chart_port.svg",
                "chart_churn.svg", "chart_latency_speed.svg",
                "chart_sets.svg", "chart_cn.svg", "chart_family.svg",
                "chart_source_avail.svg", "chart_rep.svg",
                "chart_source_stats.svg",
            ):
                self.assertTrue((out / f).exists(), f)
                svg_ok((out / f).read_text())

    def test_missing_inputs_ok(self):
        with tempfile.TemporaryDirectory() as td:
            rc = gs.main(["--data-dir", td, "--out", td])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
