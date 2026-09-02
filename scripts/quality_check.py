#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Runs on the full alive pool (default ``data/valid/all.txt``) and writes
under ``data/quality/``:

- ``ipinfo.json``      exit IP / geo / IP type / reputation score + source
                      (per checked proxy)
- ``abuse.json``       optional abuse-score results (key-gated)
- ``reputation.json``  0-100 reputation scores (multi-source weighted merge:
                      netcoffee / ncgy / ip-api / ipquery / ffraud / blackbox
                      / otx / ipsum / ipapi_is / ipdata / whatismyip
                      / proxycheck / ip2location / dc_asn / abuse_list
                      / vpn_asn / resproxy_asn, plus opt-in getipintel),
                      keyed by ``ip:port#CC``
- ``all_rep.txt``      ``all.txt`` lines re-sorted by reputation desc
- ``countries/<cc>/rep.txt``, ``sets/<name>/rep.txt``
                      per-country / per-set ``all.txt`` re-sorted by reputation
- ``quality_meta.json`` aggregated summary for stats and charts
- annotated ``*.txt``  all/countries/ports/sets lines get ``#``-suffix segments
                      (``countries/*/all.txt`` and ``*/ltd.txt``; ``rep.txt`` is
                      written pre-annotated by ``write_reputation_files``)

All proxies use the TLS (Cloudflare edge) method: direct TLS connections with
SNI routing. Only Cloudflare-fronted hosts are reachable. The exit is the edge
itself.

Annotation format appends to the existing ``ip:port#<flag><cc>-<lat>-<speed>``
lines as ``-<type>-<rep>``, e.g. ``1.2.3.4:443#US-120ms-0.44MB/s-72``.
(流媒体解锁检查已移除——历史行上的 NF/D+/YT/MX/PV/GPT token 由
normalize_note 作为遗留段继续容忍解析，但不再产生新观测。) When the exit
region is known it is inserted right after the entry country code as
``<cc>→<exit>`` (CF edge ``loc`` airport code), e.g.
``1.2.3.4:443#US→LAX-120ms-...``.
Lines without results stay untouched.
"""

import argparse
import asyncio
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common import *  # noqa: F401,F403  (paths + shared helpers + regex + classify_ip)
from quality_reputation import *  # noqa: F401,F403
from quality_probe import *  # noqa: F401,F403  (TLS engine + exit geo + ipapi)


def build_ipinfo_map(
    results: dict,
    geo: dict,
    abuse_map: dict,
    risk_data: dict | None = None,
    weights: dict | None = None,
) -> dict[str, dict]:
    risk_data = risk_data or {}
    weights = weights or REPUTATION_WEIGHTS
    info_map: dict[str, dict] = {}
    for res in results.values():
        ip = res.get("exit_ip") or res.get("ip", "")
        geo_item = geo.get(ip) or {}
        cc = geo_item.get("countryCode")
        # Supplement with external API exit geo when ip-api is missing data
        ext_geo = (res.get("external_check") or {}).get("exit_geo") or {}
        info = {
            "exit_ip": ip,
            "country": geo_item.get("country") or ext_geo.get("country"),
            "country_code": cc or ext_geo.get("countryCode"),
            "region": geo_item.get("regionName"),
            "city": geo_item.get("city") or ext_geo.get("city"),
            "asn": geo_item.get("asn") or ext_geo.get("asn"),
            "org": geo_item.get("org") or ext_geo.get("asOrganization"),
            "isp": geo_item.get("isp"),
            "proxy": geo_item.get("proxy"),
            "hosting": geo_item.get("hosting"),
            "mobile": geo_item.get("mobile"),
            "listed_country": res["cc"],
            "country_match": (
                (cc or ext_geo.get("countryCode")) == res["cc"]
            ) if (cc or ext_geo.get("countryCode")) else None,
            "ip_type": classify_ip(geo_item),
            "geo_checked": bool(cc or ext_geo.get("countryCode")),
        }
        # Attach external check summary
        ext = res.get("external_check")
        if ext:
            info["ext_ok"] = ext.get("success", False)
            info["ext_colo"] = ext.get("colo")
            info["ext_response_ms"] = ext.get("response_ms")
        signals = collect_signals(ip, geo_item, risk_data, weights)
        abuse_item = abuse_map.get(res["key"])
        score = compute_reputation(signals, abuse_item, weights)
        if score is not None:
            info["reputation"] = score
            if abuse_item:
                info["reputation_source"] = abuse_item.get("service")
            else:
                _score, responding, flagged, numeric = vote_reputation(
                    signals, weights
                )
                info["reputation_source"] = (
                    responding[0] if len(responding) == 1 else "multi"
                )
                info["risk_sources"] = numeric
                info["rep_sources"] = responding
                info["rep_flags"] = flagged
        info["risk"] = derive_risk(signals, abuse_item, weights)
        info_map[res["key"]] = info
    return info_map


def type_tokens(ipinfo: dict) -> str:
    tokens = []
    ip_type = ipinfo.get("ip_type")
    if ip_type:
        tokens.append(ip_type)
    family = ipinfo.get("family")
    if family == "dual":
        tokens.append("DS")
    elif family == "ipv6":
        tokens.append("V6")
    return " ".join(tokens)


def build_annotation(stream_toks: str, type_toks: str) -> str:
    return "-".join(seg for seg in (stream_toks, type_toks) if seg)


# 旧 QC 后缀清理已由 common.normalize_note 统一接管（含流媒体并集、
# 类型/档位/家族/分数取最右），此处不再单独实现。


def resolve_exit_ips(results: dict, fam_map: dict) -> dict:
    """为每个检测结果解析真实出口 IP（原地写入 ``exit_ip`` 字段）。

    优先级：外部探测回显（``external_check.exit_geo.ip``）> exit_family
    实测（``exit_v4``/``exit_v6``）> 代理自身 IP。CF 中转代理的入口恒为
    CF 边缘 IP，信誉/地理必须查出口才有效。
    """
    n_src: Counter = Counter()
    for key, res in results.items():
        entry_ip = res["ip"]
        # ``exit_geo`` 键可能存在但值为 null（探测成功但响应无出口字段）
        ext_ip = ((res.get("external_check") or {}).get("exit_geo") or {}).get("ip")
        fam = fam_map.get(key) if isinstance(fam_map.get(key), dict) else {}
        ef_ip = fam.get("exit_v4") or fam.get("exit_v6")
        if ext_ip:
            res["exit_ip"], res["exit_ip_source"] = ext_ip, "trace"
        elif ef_ip:
            res["exit_ip"], res["exit_ip_source"] = ef_ip, "exit_family"
        else:
            res["exit_ip"], res["exit_ip_source"] = entry_ip, "proxy"
        n_src[res["exit_ip_source"]] += 1
    if n_src:
        print(
            "Exit IP source: "
            + ", ".join(f"{k}={n_src[k]}" for k in sorted(n_src))
        )
    return results


DEEP_SPEED_TTL_DAYS = 10


def read_fresh_deep_speed(max_age_days: float = DEEP_SPEED_TTL_DAYS) -> dict | None:
    """读 ``deep_speed.json``，超过 ``max_age_days`` 视为过期返回 ``None``。

    深测每周跑一次；若长时间停摆，陈旧带宽数据不应继续充当信誉加分来源。
    """
    deep = read_json(QUALITY_DIR / "deep_speed.json")
    if not deep:
        return None
    ts = deep.get("ts") or deep.get("generated_at") or deep.get("generated")
    if not ts:
        return None
    try:
        if isinstance(ts, (int, float)):  # epoch 秒
            stamp = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        else:  # ISO-8601
            stamp = datetime.fromisoformat(
                ts.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None
    age_days = (datetime.now(timezone.utc) - stamp).total_seconds() / 86400
    return deep if age_days <= max_age_days else None


def build_reputation_map(
    results: dict,
    risk_data: dict,
    weights: dict,
    deep_speed: dict | None = None,
) -> dict[str, dict]:
    rep_map: dict[str, dict] = {}
    deep = (deep_speed or {}).get("proxies") or {}
    for res in results.values():
        signals = collect_signals(
            res.get("exit_ip") or res["ip"], {}, risk_data, weights,
            include_ipapi=False,
        )
        score, responding, flagged, numeric = vote_reputation(signals, weights)
        if score is None:
            continue
        source = "multi" if len(responding) != 1 else (
            responding[0] if responding else None
        )
        # 深测带宽分量：最优目标 agg_mbps ≥50MB/s 记满分 +10，线性缩放，
        # 仅对已有信誉分的节点加成（深测是抽样，不产生幽灵分）
        bonus = 0
        ds = deep.get(res["key"])
        if isinstance(ds, dict):
            aggs = [
                v.get("agg_mbps")
                for v in ds.values()
                if isinstance(v, dict)
                and isinstance(v.get("agg_mbps"), (int, float))
            ]
            if aggs:
                bonus = round(min(max(aggs) / 50.0, 1.0) * 10)
                score = min(100, score + bonus)
        rep_map[res["key"]] = {
            "score": score,
            "risk": reputation_risk(score),
            "source": source,
            "sources": responding,
            "flags": flagged,
            "numeric": numeric,
            **({"deep_bonus": bonus} if bonus else {}),
        }
    return rep_map


def build_ranked(text: str, annotations: dict, rep_map: dict) -> list[str]:
    """Annotate ``text`` lines and re-order them by reputation desc.

    Lines with a reputation score are sorted by ``(score desc, latency asc,
    key)``; unscored lines keep their original relative order at the end.
    """
    scored: list[tuple[dict, str, str]] = []
    unscored: list[str] = []
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        ann = annotations.get(key) if key else None
        if ann:
            out = merge_note_tokens(line, *ann.split("-"))
        else:
            out = line
        rep = rep_map.get(key)
        if rep:
            scored.append((rep, key, out))
        else:
            unscored.append(out)

    def sort_key(item: tuple[dict, str, str]) -> tuple:
        rep, key, line = item
        lat_match = LATENCY_RE.search(line)
        lat = int(lat_match.group(1)) if lat_match else float("inf")
        return (-rep["score"], lat, key)

    scored.sort(key=sort_key)
    return [line for _rep, _key, line in scored] + unscored


REP_GROUP_NAMES = ("v4", "v6", "46", "cn", "cn4", "cn6", "cn46")


def write_reputation_files(source_text: str, annotations: dict, rep_map: dict) -> None:
    """写声誉排序清单及其 ``_verified`` / ``_stable`` 可靠性变体。

    变体过滤信号（与 validate/build_good 共用）：
    - ``_verified``: speed.json（本轮全链路验证通过）
    - ``_stable``:  china.json streak≥2（连续两轮大陆可达）
    根级 all_rep / all_{g}_rep / all_{g}_rep_ltd 全覆盖；子目录产出
    rep(+v/s)、rep_ltd(+v/s) 与 {g}_rep(_ltd) 单维度文件。
    """
    speed_keys = load_speed_keys()
    stable_keys = load_china_stable_keys()

    def emit(base: Path, lines: list[str]) -> None:
        """写清单本体 + verified/stable 变体（空变体清理旧文件）。"""
        write_text_if_changed(base, "\n".join(lines) + "\n")
        for suffix, keys in (("_verified", speed_keys), ("_stable", stable_keys)):
            vpath = base.with_name(f"{base.stem}{suffix}.txt")
            vlines = [ln for ln in lines if (k := line_to_key(ln)) and k in keys]
            if vlines:
                write_text_if_changed(vpath, "\n".join(vlines) + "\n")
            elif vpath.exists():
                vpath.unlink()

    ranked = build_ranked(source_text, annotations, rep_map)
    emit(REP_RANK_FILE, ranked)
    valid_root = REP_RANK_FILE.parent

    # --- 顶层 cross-product rep 文件 (all_cn_rep.txt, all_cn4_rep_ltd.txt 等) ---
    for g in REP_GROUP_NAMES:
        src = valid_root / f"all_{g}.txt"
        if src.exists():
            r = build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map)
            emit(valid_root / f"all_{g}_rep.txt", r)
        ltd_src = valid_root / f"all_{g}_ltd.txt"
        if ltd_src.exists():
            r = build_ranked(ltd_src.read_text(encoding="utf-8"), annotations, rep_map)
            emit(valid_root / f"all_{g}_rep_ltd.txt", r)

    # --- 每个 set/country 子目录: rep(+v/s) + rep_ltd(+v/s) + 分组 rep ---
    for sub in ("countries", "sets"):
        for src in sorted((valid_root / sub).glob("*/all.txt")):
            emit(
                src.with_name("rep.txt"),
                build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map),
            )
        for ltd_src in sorted((valid_root / sub).glob("*/ltd.txt")):
            emit(
                ltd_src.with_name("rep_ltd.txt"),
                build_ranked(
                    ltd_src.read_text(encoding="utf-8"), annotations, rep_map
                ),
            )
        for g in REP_GROUP_NAMES:
            for src in sorted((valid_root / sub).glob(f"*/{g}.txt")):
                r = build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map)
                write_text_if_changed(
                    src.with_name(f"{g}_rep.txt"), "\n".join(r) + "\n"
                )
            for src in sorted((valid_root / sub).glob(f"*/{g}_ltd.txt")):
                r = build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map)
                write_text_if_changed(
                    src.with_name(f"{g}_rep_ltd.txt"), "\n".join(r) + "\n"
                )

    entries = {
        key: {
            "score": rep["score"],
            "risk": rep["risk"],
            "source": rep["source"],
            "sources": rep.get("sources") or [],
        }
        for key, rep in rep_map.items()
    }
    entries = dict(
        sorted(entries.items(), key=lambda kv: (-kv[1]["score"], kv[0]))
    )
    write_json(REPUTATION_FILE, keyed_json(entries))


def build_annotations(results: dict, rep_map: dict) -> dict[str, str]:
    annotations: dict[str, str] = {}
    for res in results.values():
        ann = ""
        rep = rep_map.get(res["key"])
        if rep:
            ann = build_annotation(ann, str(rep["score"]))
        annotations[res["key"]] = ann
    return annotations


def annotate_text(
    text: str, annotations: dict,
) -> tuple[str, bool]:
    """Append ``-annotation`` tokens to proxy lines (streaming + reputation).

    Exit-country markers (→CC) are filled by ``annotate_classify.py``
    from ``ipinfo.json`` and are **not** handled here.
    """
    out = []
    changed = False
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        ann = annotations.get(key) if key else None
        out_line = line
        if ann:
            out_line = merge_note_tokens(out_line, *ann.split("-"))
        if out_line != line:
            changed = True
        out.append(out_line)
    return "\n".join(out) + "\n", changed


def annotate_valid_files(annotations: dict) -> int:
    """Annotate ``all.txt``/``all_ltd.txt`` and sub-file trees with tokens.

    Returns number of view rows pruned by the trailing reconcile (0 if none).
    """
    files: list[Path] = [VALID_DIR / "all.txt", VALID_DIR / "all_ltd.txt"]
    for sub in ("countries", "sets"):
        files.extend(sorted((VALID_DIR / sub).glob("*/all.txt")))
        files.extend(sorted((VALID_DIR / sub).glob("*/ltd.txt")))
    files.extend(sorted((VALID_DIR / "ports").glob("*.txt")))
    for path in files:
        if not path.exists():
            continue
        text, changed = annotate_text(
            path.read_text(encoding="utf-8"), annotations,
        )
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(path)
    from annotate_classify import reconcile_views

    return reconcile_views(VALID_DIR)


def build_meta(
    results: dict, ipinfo: dict, abuse_map: dict,
    rep_map: dict | None = None,
) -> dict:
    rep_map = rep_map or {}
    by_type = Counter(info["ip_type"] for info in ipinfo.values())
    risk = Counter(
        info["risk"] for info in ipinfo.values() if info.get("risk")
    )
    reps = [
        rep["score"] for rep in rep_map.values()
        if rep.get("score") is not None
    ]
    rep_dist = {
        "0-25": sum(1 for r in reps if r < 25),
        "25-50": sum(1 for r in reps if 25 <= r < 50),
        "50-75": sum(1 for r in reps if 50 <= r < 75),
        "75-100": sum(1 for r in reps if r >= 75),
    }
    country_mismatch = sum(
        1 for info in ipinfo.values()
        if isinstance(info, dict) and info.get("country_match") is False
    )
    ext_ok = sum(
        1 for res in results.values()
        if (res.get("external_check") or {}).get("success")
    )
    ext_total = sum(
        1 for res in results.values() if "external_check" in res
    )
    return {
        "ts": now_ts(),
        "total": len(results),
        "tls": len(results),
        "by_type": dict(sorted(by_type.items())),
        "risk": dict(sorted(risk.items())),
        "abuse_checked": len(abuse_map),
        "reputation_checked": len(reps),
        "rep_dist": rep_dist,
        "rep_avg": (round(sum(reps) / len(reps), 1) if reps else None),
        "rep_median": (
            round(
                (sorted(reps)[n // 2 - 1] + sorted(reps)[n // 2]) / 2, 1
            ) if (n := len(reps)) else None
        ),
        "country_mismatch": country_mismatch,
        "ext_check_total": ext_total,
        "ext_check_ok": ext_ok,
    }


async def run(args: argparse.Namespace) -> int:
    if not args.source.exists():
        print(f"Error: {args.source} not found", file=sys.stderr)
        return 1
    entries = [
        p for p in (parse_ltd_line(line) for line in args.source.read_text(
            encoding="utf-8"
        ).splitlines()) if p
    ]
    if args.limit > 0:
        entries = entries[: args.limit]
    if not entries:
        print(f"No entries in {args.source}")
        return 0
    methods = load_methods()
    print(
        f"Checking {len(entries)} proxies "
        f"(timeout={args.timeout}s, workers={args.workers}) ..."
    )

    results = await run_checks(entries, methods, args)
    print(f"Completed {len(results)} checks")

    # 出口 IP 解析后，信誉/地理/滥用全部查真实出口——CF 中转代理的
    # 入口恒为 CF 边缘 IP，查入口会得到千篇一律的"干净"结果。
    fam_map = read_json(EXIT_FAMILY_FILE).get("proxies", {})
    results = resolve_exit_ips(results, fam_map)

    geo = await batch_ipapi([res["exit_ip"] for res in results.values()])

    rep_ips = [res["exit_ip"] for res in results.values()]
    asn_map = {ip: norm_asn(geo[ip].get("asn")) for ip in rep_ips
               if ip in geo and norm_asn(geo[ip].get("asn"))}
    risk_data = await lookup_all_risk(rep_ips, args, asn_map)
    if risk_data:
        print(
            f"Reputation: {len(risk_data)}/{len(set(rep_ips))} IPs from "
            f"{', '.join(args.reputation_sources)}"
        )
    abuse_map = await run_abuse(results, {
        k: {"exit_ip": res["exit_ip"]} for k, res in results.items()
    }, args)
    ipinfo = build_ipinfo_map(
        results, geo, abuse_map, risk_data, args.reputation_weights
    )
    rep_map = build_reputation_map(
        results, risk_data, args.reputation_weights,
        deep_speed=read_fresh_deep_speed(),
    )

    annotations = build_annotations(results, rep_map)
    source_text = args.source.read_text(encoding="utf-8")
    if rep_map:
        write_reputation_files(source_text, annotations, rep_map)

    # Extract and persist external check results
    ext_checks = {}
    for key, res in results.items():
        ext = res.get("external_check")
        if ext:
            ext_checks[key] = ext
    if ext_checks:
        write_json(EXTERNAL_CHECK_FILE, keyed_json(ext_checks))

    if ipinfo:
        write_json(IPINFO_FILE, keyed_json(ipinfo))
    else:
        IPINFO_FILE.unlink(missing_ok=True)
    STREAMING_FILE.unlink(missing_ok=True)  # 流媒体检查已移除，清理遗留产物
    if abuse_map:
        write_json(ABUSE_FILE, keyed_json(abuse_map))
    meta = build_meta(results, ipinfo, abuse_map, rep_map)
    write_json(QUALITY_META_FILE, meta)
    annotate_valid_files(annotations)

    print(
        f"by_type={meta['by_type']} "
        f"rep_avg={meta['rep_avg']} rep_dist={meta['rep_dist']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=DEFAULT_SOURCE,
        help="Input proxy list (default: data/valid/all.txt)",
    )
    parser.add_argument(
        "--abuse-service", choices=("none", "abuseipdb", "ipqs"), default="none",
        help="Abuse-score provider (key from ABUSEIPDB_KEY / IPQS_KEY env)",
    )
    parser.add_argument(
        "--reputation-provider",
        choices=("multi", "netcoffee", "ip-api", "none"),
        default="multi",
        help="Reputation strategy: multi (weighted merge of --reputation-sources), "
        "netcoffee (legacy net.coffee + ip-api), ip-api (flags only), or none",
    )
    parser.add_argument(
        "--reputation-sources",
        default=None,
        help="Comma list of sources for --reputation-provider multi "
        "(default: all DEFAULT_REP_SOURCES in quality_reputation.py: "
        "netcoffee,ncgy,ip-api,ipquery,ffraud,blackbox,otx,ipsum,"
        "ipapi_is,ipdata,whatismyip,dc_asn,abuse_list,vpn_asn,resproxy_asn,"
        "proxycheck,ip2location,ipwhois,tor_exit,spamhaus,freeipapi,"
        "hackmyip,scamalytics,iplocation,cins,et_compromised,feodo)",
    )
    parser.add_argument(
        "--reputation-weights",
        dest="reputation_weights_override",
        default=None,
        help="Comma list of name:weight overrides, e.g. netcoffee:40,ncgy:20",
    )
    parser.add_argument(
        "--rep-cache-ttl",
        type=int,
        default=REP_CACHE_TTL,
        help="Reputation signal cache TTL in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--no-rep-cache",
        action="store_true",
        help="Disable the reputation signal cache",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=TIMEOUT,
        help="Per-proxy timeout (seconds)",
    )
    parser.add_argument("--read-cap", type=int, default=READ_CAP,
                        help="Max body bytes read per HTTP response")
    parser.add_argument(
        "-w", "--workers", type=int, default=WORKERS,
        help="Max concurrent checks",
    )
    parser.add_argument("--limit", type=int, default=0,
                        help="Max proxies to check (0 = all)")
    parser.add_argument(
        "--time-budget", type=int, default=0,
        help="Stop after this many seconds (0 = unlimited)",
    )
    args = parser.parse_args(argv)
    import os

    args.abuse_key = ""
    if args.abuse_service != "none":
        env_name = {
            "abuseipdb": "ABUSEIPDB_KEY",
            "ipqs": "IPQS_KEY",
        }[args.abuse_service]
        args.abuse_key = os.environ.get(env_name, "")
        if not args.abuse_key:
            print(
                f"Warning: {env_name} not set; skipping abuse scores",
                file=sys.stderr,
            )
            args.abuse_service = "none"
    args.getipintel_email = os.environ.get("GETIPINTEL_EMAIL", "")
    args.reputation_weights = dict(REPUTATION_WEIGHTS)
    override = args.reputation_weights_override or ""
    for tok in override.split(","):
        if ":" in tok:
            name, weight = tok.split(":", 1)
            try:
                args.reputation_weights[name.strip()] = int(weight)
            except ValueError:
                logging.warning("Invalid weight value for %s: %s", name, weight)
    args.reputation_sources = args.reputation_sources or ""
    if args.reputation_provider == "none":
        args.reputation_sources = []
    elif args.reputation_provider == "netcoffee":
        args.reputation_sources = ["netcoffee", "ip-api"]
    elif args.reputation_provider == "ip-api":
        args.reputation_sources = ["ip-api"]
    else:
        args.reputation_sources = [
            s.strip() for s in args.reputation_sources.split(",") if s.strip()
        ]
        args.reputation_sources = [
            s for s in args.reputation_sources if s in REPUTATION_WEIGHTS
        ]
        if not args.reputation_sources:
            args.reputation_sources = list(DEFAULT_REP_SOURCES)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

