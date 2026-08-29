#!/usr/bin/env python3
"""Deep per-node speed probe: large sample × parallel streams × multi-CDN.

常规测速（validate_proxies）用 ≤1MB/5s 小窗口——足以分层但会把同国节点
压扁成相近数字（CDN 本地化 + TCP 窗口爬升不足）。本工具对**选定国家**
的候选节点做深测：

- 大样本（默认 20MB / 30s 上限），稳态窗口远大于 slow-start；
- 多并发流（默认 3）聚合吞吐——高 BDP 链路单流吃不满带宽；
- 多目标：``cf_speed``（speed.cloudflare.com 大文件，CF 边缘本地化，主目标）、
  ``cdnjs``（小型对照）与 ``ovh``（proof.ovh.net，非CF大文件，暴露真实国际
  transit 差距）。

结果写 ``data/quality/deep_speed.json``（keyed，含每流明细），不改动
清单行备注——深测结论供人工/下游参考，与全局档位语义解耦。

Usage::

    python scripts/deep_speed.py --cc US,CA --limit 30 \
        --bytes-mb 20 --streams 3 --targets cdnjs,ovh
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    DATA_DIR,
    QUALITY_DIR,
    parse_ltd_line,
    write_json,
)
from validate_proxies import (  # noqa: E402
    SPEED_WARMUP_BYTES,
    _TLS_CTX,
    open_conn,
    speed_download,
)

TARGETS = {
    # 大文件、CF 边缘本地化、多流聚合——深测的主目标。speed.cloudflare.com
    # 的 /__down?bytes= 按需生成长度，稳态样本远大于小文件，国别差异反映
    # 的是真实 transit 差距而非小样本抖动。
    "cf_speed": ("speed.cloudflare.com", "/__down?bytes=25000000"),
    "cdnjs": ("cdnjs.cloudflare.com", "/ajax/libs/three.js/r128/three.js"),
    "ovh": ("proof.ovh.net", "/files/10Mb.dat"),
    "cf_trace": ("cloudflare.com", "/cdn-cgi/trace"),
}


def aggregate(samples: list[float | None]) -> dict:
    """聚合多流结果：可用流求和 + 明细。"""
    ok = [s for s in samples if s is not None]
    return {
        "agg_mbps": round(sum(ok), 2),
        "streams_ok": len(ok),
        "streams_total": len(samples),
        "samples": [round(s, 2) if s is not None else None for s in samples],
    }


def summarize(results: dict[str, dict], target: str, top: int = 10) -> None:
    """stderr 输出指定目标的 Top-N 与组内离散度概览。"""
    rows = sorted(
        ((k, v[target]["agg_mbps"]) for k, v in results.items()
         if v.get(target, {}).get("streams_ok")),
        key=lambda kv: kv[1], reverse=True,
    )
    if not rows:
        print(f"[{target}] no successful probes", file=sys.stderr)
        return
    vals = [v for _, v in rows]
    print(f"\n[{target}] top-{min(top, len(rows))} "
          f"(n={len(rows)} max={max(vals)} min={min(vals)}):", file=sys.stderr)
    for k, v in rows[:top]:
        print(f"  {v:>8.2f} MB/s  {k}", file=sys.stderr)


async def probe_entry(
    ip: str,
    port: str,
    args: argparse.Namespace,
    sem: asyncio.Semaphore,
) -> dict | None:
    """单节点深测：TLS 延迟 + 每目标 ``--streams`` 路并发下载。

    ``gather(return_exceptions=True)``：任何单流测速失败都不再向上抛——
    此前异常会杀死整个并发任务组，进而中断整轮深测。
    """
    out: dict = {}
    async with sem:
        t0 = time.monotonic()
        try:
            reader, writer = await open_conn(
                ip, port, args.timeout, ctx=_TLS_CTX, sni=args.sni)
        except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
            return None
        out["tls_ms"] = round((time.monotonic() - t0) * 1000)
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass
        for name in args.targets.split(","):
            name = name.strip()
            host, path = TARGETS[name]
            cap_bytes = args.bytes_mb * 1024 * 1024
            samples = await asyncio.gather(*[
                _one_stream(ip, port, host, path, cap_bytes, args)
                for _ in range(args.streams)
            ], return_exceptions=True)
            samples = [s if isinstance(s, float) else None for s in samples]
            out[name] = aggregate(list(samples))
    return out


async def _one_stream(ip: str, port: str, host: str, path: str,
                      cap_bytes: int, args: argparse.Namespace) -> float | None:
    """单流下载测速。任何异常（含 ``asyncio.IncompleteReadError``、TLS、
    ``ValueError`` 等非 ConnectionError 的类型）都按失败处理——此前仅捕获
    ``ConnectionError/OSError`` 导致 gather 抛异常拖垮整个深测任务。
    """
    try:
        reader, writer = await open_conn(
            ip, port, args.timeout, ctx=_TLS_CTX, sni=host)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return None
    try:
        return await speed_download(
            reader, writer, host, path, cap_bytes, args.timeout,
            warmup_bytes=max(SPEED_WARMUP_BYTES, 1024 * 1024),
        )
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main_async(args: argparse.Namespace) -> int:
    if args.source:
        src = Path(args.source)
        if not src.exists():
            print(f"error: source {src} missing", file=sys.stderr)
            return 2
        text = src.read_text(encoding="utf-8")
    else:
        # 默认源：--cc 列出的国家 all.txt 合并
        chunks = []
        base = DATA_DIR / "valid" / "countries"
        for cc in [c.strip().upper() for c in args.cc.split(",") if c.strip()]:
            p = base / cc / "all.txt"
            if p.exists():
                chunks.append(p.read_text(encoding="utf-8"))
            else:
                print(f"warn: no pool for {cc}", file=sys.stderr)
        text = "\n".join(chunks)

    entries: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    keyed_lines: dict[str, str] = {}
    for ln in text.splitlines():
        parsed = parse_ltd_line(ln)
        if not parsed:
            continue
        key, ip, port, _cc = parsed
        if key in seen:
            continue
        seen.add(key)
        entries.append((key, ip, port))
        keyed_lines.setdefault(key, ln)
    # 候选排序：信誉分（行内尾 token）降序，取前 --limit

    def rep_of(ln_text: str) -> int:
        m = re.search(r"-(\d{1,3})$", ln_text.rstrip())
        return int(m.group(1)) if m else 0

    entries.sort(key=lambda e: -rep_of(keyed_lines.get(e[0], "")))
    entries = entries[: args.limit] if args.limit > 0 else entries
    print(f"deep-probe: {len(entries)} entries × targets={args.targets} "
          f"× streams={args.streams} × ≤{args.bytes_mb}MB", file=sys.stderr)

    sem = asyncio.Semaphore(args.workers)
    tasks = {
        asyncio.create_task(probe_entry(ip, port, args, sem)): key
        for key, ip, port in entries
    }
    results: dict[str, dict] = {}
    for task, (key, _ip, _port) in zip(tasks.keys(), entries):
        try:
            res = await task
        except Exception as exc:  # 单个节点异常不拖垮整轮
            print(f"probe error for {key}: {exc}", file=sys.stderr)
            res = None
        if res:
            results[key] = res

    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "params": {
            "cc": args.cc, "source": args.source, "limit": args.limit,
            "bytes_mb": args.bytes_mb, "streams": args.streams,
            "timeout": args.timeout, "targets": args.targets,
        },
        "results": results,
    }
    out = QUALITY_DIR / "deep_speed.json"
    write_json(out, {"proxies": results, "meta": payload["params"],
                     "generated": payload["generated"]})
    print(f"wrote {out} ({len(results)}/{len(entries)} probed)", file=sys.stderr)
    for name in args.targets.split(","):
        summarize(results, name.strip())
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="", help="逗号分隔国家码（默认源）")
    parser.add_argument("--source", type=Path, default=None,
                        help="显式池文件（优先于 --cc）")
    parser.add_argument("--limit", type=int, default=30,
                        help="每轮最多探测节点数（0=全部，默认 30）")
    parser.add_argument("--bytes-mb", type=int, default=20,
                        help="单流下载上限 MB（默认 20）")
    parser.add_argument("--streams", type=int, default=3,
                        help="每节点并发流数（默认 3）")
    parser.add_argument("--timeout", type=int, default=30,
                        help="连接/下载超时秒（默认 30）")
    parser.add_argument("--workers", type=int, default=6,
                        help="同时深测的节点数（默认 6）")
    parser.add_argument("--sni", default=None, help="覆盖入口 SNI")
    parser.add_argument("--targets", default="cdnjs",
                        help=f"逗号分隔目标：{','.join(TARGETS)}")
    args = parser.parse_args(argv)
    if not args.cc and not args.source:
        parser.error("需要 --cc 或 --source 之一")
    for name in args.targets.split(","):
        if name.strip() not in TARGETS:
            parser.error(f"未知目标 {name!r}；可选 {','.join(TARGETS)}")
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
