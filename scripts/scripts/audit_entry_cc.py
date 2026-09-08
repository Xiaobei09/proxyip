#!/usr/bin/env python3
"""Audit entry-country label accuracy of the valid pool.

订阅标签（行内 ``#CC``）的准确性此前无从验证。本脚本以两个独立信号交叉审计：

1. **入口 IP 地理**（ip-api batch，``countryCode`` + ``as``）——与订阅标签对比；
   入口为 Cloudflare 边缘（AS13335）时标签无法经入口验证（源站在 CF 之后）。
2. **出口国观测**（``common.build_exit_cc_map`` 四源汇聚）——区分
   "标签错" 与正常的 "出口漂移"。

判定（verdict）：

- ``ok``            标签 == 入口实测，且出口观测缺失或一致
- ``ok_with_drift`` 标签 == 入口实测，但出口在别国（正常漂移，非标签错误）
- ``tag_mismatch``  标签 != 入口实测（原始标签可疑）
- ``cf_fronted``    入口为 CF 边缘（AS13335），入口验证不适用
- ``domain_entry``  入口为域名，无入口 IP 可查
- ``entry_unknown`` 入口 geo 查询失败

结果写 ``data/quality/entry_audit.json`` 并打印汇总；只读不改行，
不影响任何门控。

Usage::

    python scripts/audit_entry_cc.py [--data-dir data]
        [--source data/valid/all.txt] [--timeout 10] [--delay 1.5]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import DATA_DIR, line_to_key, parse_ltd_line, read_json, build_exit_cc_map, deadline_open

IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_BATCH_SIZE = 100
IPAPI_BATCH_DELAY = 1.5
CF_ASN = 13335


def is_literal_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def lookup_geo(
    ips: list[str], timeout: int = 15, delay: float = IPAPI_BATCH_DELAY,
    retries: int = 2,
) -> dict[str, dict]:
    """Batch ip-api 查询 → ``{ip: {"cc", "asn"}}``。

    单批失败重试 ``retries`` 次后跳过该批继续（审计宁缺毋滥，
    不因个别批失败放弃全量）。
    """
    found: dict[str, dict] = {}
    fields = ["status", "query", "countryCode", "as"]
    for start in range(0, len(ips), IPAPI_BATCH_SIZE):
        chunk = [{"query": ip, "fields": fields} for ip in ips[start:start + IPAPI_BATCH_SIZE]]
        data = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(
                    IPAPI_BATCH_URL,
                    data=json.dumps(chunk).encode("utf-8"),
                    headers={"Content-Type": "application/json",
                             "User-Agent": "proxyip-audit/1.0"},
                    method="POST",
                )
                with deadline_open(req, timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                break
            except Exception as exc:  # noqa: BLE001
                if attempt == retries:
                    print(f"ip-api batch @{start} failed ({exc}); skipping",
                          file=sys.stderr)
                else:
                    time.sleep(delay * 2)
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict) or item.get("status") != "success":
                continue
            q = item.get("query")
            cc, as_ = item.get("countryCode"), item.get("as") or ""
            asn = int(as_.split()[0][2:]) if as_.startswith("AS") else None
            if isinstance(q, str):
                found[q] = {"cc": cc if isinstance(cc, str) and cc else None,
                            "asn": asn}
        if start + IPAPI_BATCH_SIZE < len(ips):
            time.sleep(delay)
    return found


def classify(listed: str, geo: dict | None, exit_cc: str | None) -> str:
    """三方对比 → verdict（见模块 docstring）。"""
    if not geo or not geo.get("cc"):
        return "entry_unknown"
    if geo.get("asn") == CF_ASN:
        return "cf_fronted"
    entry_cc = geo["cc"]
    if entry_cc != listed:
        return "tag_mismatch"
    if exit_cc and exit_cc != listed:
        return "ok_with_drift"
    return "ok"


def audit(source: Path, quality_dir: Path, timeout: int, delay: float) -> dict:
    lines = [l.strip() for l in source.read_text(encoding="utf-8").splitlines()
             if l.strip()]
    exit_map = build_exit_cc_map(
        read_json(quality_dir / "ipinfo.json"),
        read_json(quality_dir / "external_check.json"),
        read_json(quality_dir / "upstream_meta.json"),
        read_json(quality_dir / "exit_family.json"),
    )
    rows: list[dict] = []
    pending_ips: set[str] = set()
    for ln in lines:
        parsed = parse_ltd_line(ln)
        key = line_to_key(ln)
        listed = parsed[3] if parsed else "?"
        host = ln.rsplit(":", 1)[0].rsplit("#", 1)[0] if ":" in ln else ""
        row = {"key": key, "listed": listed,
               "exit_cc": exit_map.get(key), "entry_ip": None,
               "entry_geo": None, "verdict": None}
        if not is_literal_ip(host):
            row["verdict"] = "domain_entry"
        else:
            row["entry_ip"] = host
            pending_ips.add(host)
        rows.append(row)

    geo_map = lookup_geo(sorted(pending_ips), timeout=timeout, delay=delay) \
        if pending_ips else {}
    for row in rows:
        if row["verdict"] is None:
            g = geo_map.get(row["entry_ip"])
            row["entry_geo"] = (g or {}).get("cc")
            row["asn"] = (g or {}).get("asn")
            row["verdict"] = classify(row["listed"], g, row["exit_cc"])

    summary = Counter(r["verdict"] for r in rows)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(rows),
        "summary": dict(summary),
        "proxies": {r["key"]: {k: v for k, v in r.items() if k != "key"}
                    for r in rows},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--source", type=Path, default=None,
                        help="代理列表（默认 <data-dir>/valid/all.txt）")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=IPAPI_BATCH_DELAY)
    args = parser.parse_args(argv)
    source = args.source or (args.data_dir / "valid" / "all.txt")
    report = audit(source, args.data_dir / "quality", args.timeout, args.delay)

    out = args.data_dir / "quality" / "entry_audit.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1),
                   encoding="utf-8")

    total = report["total"] or 1
    print(f"Entry CC audit: {report['total']} lines -> {out}")
    for verdict, n in sorted(report["summary"].items(), key=lambda x: -x[1]):
        print(f"  {verdict:<14} {n:>6}  ({n / total * 100:.1f}%)")
    mism = report["summary"].get("tag_mismatch", 0)
    known = total - report["summary"].get("domain_entry", 0) \
        - report["summary"].get("cf_fronted", 0) \
        - report["summary"].get("entry_unknown", 0)
    if known:
        print(f"  标签可验证样本中错标率: {mism}/{known} = {mism / known * 100:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
