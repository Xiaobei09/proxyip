#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Runs on the full alive pool (default ``data/valid/all.txt``) and writes
under ``data/quality/``:

- ``ipinfo.json``      exit IP / geo / IP type / reputation score + source
                      (per checked proxy)
- ``streaming.json``   per-service unlock results (incl. native Netflix)
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
itself and is tagged ``CF``.

Annotation format appends to the existing ``ip:port#<flag><cc>-<lat>-<speed>``
lines as ``-<streaming>-<type>-<rep>``, e.g.
``1.2.3.4:443#US-120ms-0.44MB/s-NF(US) D+ YT GPT-CF-72``. When the exit
region is known it is inserted right after the entry country code as
``<cc>→<exit>`` (CF edge ``loc`` airport code), e.g.
``1.2.3.4:443#US→LAX-120ms-...``.
Lines without results stay untouched.
"""

import argparse
import asyncio
import logging
import re
import sys
from collections import Counter
from pathlib import Path

from common import *  # noqa: F401,F403  (paths + shared helpers + regex + classify_ip)
from quality_reputation import *  # noqa: F401,F403
from quality_streaming import *  # noqa: F401,F403


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
        ip = res.get("ip", "")
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
        risk_flags = {
            source: signal
            for source, signal in risk_data.get(ip, {}).items()
        }
        if risk_flags:
            info["risk_flags"] = risk_flags
        signals = collect_signals(ip, geo_item, risk_data, weights)
        abuse_item = abuse_map.get(res["key"])
        score = compute_reputation(signals, abuse_item, weights)
        if score is not None:
            info["reputation"] = score
            if abuse_item:
                info["reputation_source"] = abuse_item.get("service")
            else:
                _score, sources = weighted_reputation(signals, weights)
                info["reputation_source"] = (
                    sources[0] if len(sources) == 1 else "multi"
                )
                info["risk_sources"] = sources
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


_QC_STREAMING_BASE = {"D+", "YT", "MX", "PV", "GPT"}
_QC_TYPE = {"CF"}
_QC_KNOWN = _QC_STREAMING_BASE | _QC_TYPE


def _is_rep_score(tok: str) -> bool:
    """Check if *tok* is a reputation score (1-3 digit integer)."""
    return tok.isdigit() and 1 <= len(tok) <= 3


def _is_qc_token(tok: str) -> bool:
    """Check if *tok* is a QC-produced token (streaming / CF / score)."""
    if tok in _QC_KNOWN:
        return True
    if tok.startswith("NF(") and tok.endswith(")"):
        return True
    return _is_rep_score(tok)


_QC_TOKEN_RE = re.compile(
    r"(?:^|(?<=-))(?:NF\([^)]*\)|D\+|YT|MX|PV|GPT|CF|\d{1,3})(?=$|-)"
)


def _strip_qc_match(m: re.Match) -> str:
    """Collapse matched QC token into a single ``-`` delimiter (or ``""`` at
    string boundaries) so adjacent delimiters merge cleanly."""
    s = m.group(0)
    if s.startswith("-") and s.endswith("-"):
        return "-"
    return ""


def strip_qc_annotations(line: str) -> str:
    """Remove ALL QC-produced tokens from *line* to prevent suffix duplication.

    Strips streaming tokens (NF(..), D+, YT, MX, PV, GPT), CF, and reputation
    scores — but preserves other workflow tokens (CN, V4, V6, DS, DC, speed
    tier, exit region →CC). This lets ``annotate_text`` re-append a clean
    annotation without accumulating stale duplicates across CI runs.
    """
    idx = line.find("#")
    if idx < 0:
        return line
    base = line[:idx]
    rest = line[idx + 1:]
    i = 0
    while i < len(rest) and not ("A" <= rest[i] <= "Z"):
        i += 1
    if rest[i:].startswith("ALL") and rest[i + 3:i + 4] in ("", "-"):
        cc_end = i + 3
    else:
        cc_end = i + 2
    note = rest[cc_end:]
    if not note:
        return line
    # Split off leading → exit-region so it is never consumed by the regex
    prefix = ""
    if note.startswith("→"):
        dash_pos = note.find("-", 1)
        if dash_pos > 0:
            prefix = note[:dash_pos]
            note = note[dash_pos:]
        else:
            return line  # note is just "→XX", nothing to strip
    cleaned = _QC_TOKEN_RE.sub(_strip_qc_match, note)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = cleaned.strip("-")
    return base + "#" + rest[:cc_end] + prefix + ("-" + cleaned if cleaned else "")


def build_reputation_map(
    results: dict,
    risk_data: dict,
    weights: dict,
) -> dict[str, dict]:
    rep_map: dict[str, dict] = {}
    for res in results.values():
        signals = collect_signals(
            res["ip"], {}, risk_data, weights, include_ipapi=False
        )
        score, sources = weighted_reputation(signals, weights)
        source = "multi" if len(sources) != 1 else (sources[0] if sources else None)
        if score is None:
            continue
        rep_map[res["key"]] = {
            "score": score,
            "risk": reputation_risk(score),
            "source": source,
            "sources": sources,
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
        if ann and not line.rstrip().endswith("-" + ann):
            out = strip_qc_annotations(line) + "-" + ann
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


def _build_ranked_map(source_text: str, annotations: dict, rep_map: dict) -> list[str]:
    """从文本构建声誉排序列表。"""
    return build_ranked(source_text, annotations, rep_map)


def write_reputation_files(source_text: str, annotations: dict, rep_map: dict) -> None:
    """写声誉排序清单及其 ``_verified`` / ``_stable`` 可靠性变体。

    变体过滤信号（与 validate/build_good 共用）：
    - ``_verified``: speed.json（本轮全链路验证通过）
    - ``_stable``:  china.json streak≥2（连续两轮大陆可达）
    根级 all_rep / all_{g}_rep / all_{g}_rep_ltd 与子目录 rep.txt 全覆盖；
    子目录分组 rep 保持单维度以控制文件数量。
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

    # --- 每个 set/country 子目录: rep.txt + cross-product rep 文件 ---
    for sub in ("countries", "sets"):
        for src in sorted((valid_root / sub).glob("*/all.txt")):
            emit(
                src.with_name("rep.txt"),
                build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map),
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
        stream_toks = streaming_tokens(res["streaming"])
        ann = build_annotation(stream_toks, "CF")
        rep = rep_map.get(res["key"])
        if rep:
            ann = build_annotation(ann, str(rep["score"]))
        annotations[res["key"]] = ann
    return annotations


def build_exits(results: dict, ipinfo: dict) -> dict[str, str]:
    """Exit region per key: CF edge ``loc`` from the OpenAI trace response."""
    exits: dict[str, str] = {}
    for res in results.values():
        region = (res.get("streaming") or {}).get("openai", {}).get("region")
        if region:
            exits[res["key"]] = region
    return exits


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
        if ann and not out_line.rstrip().endswith("-" + ann):
            out_line = strip_qc_annotations(out_line) + "-" + ann
        if out_line != line:
            changed = True
        out.append(out_line)
    return "\n".join(out) + "\n", changed


def annotate_valid_files(annotations: dict) -> None:
    """Annotate ``all.txt``/``all_ltd.txt`` and sub-file trees with tokens."""
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


def build_meta(
    results: dict, ipinfo: dict, streaming: dict, abuse_map: dict,
    rep_map: dict | None = None,
) -> dict:
    rep_map = rep_map or {}
    per_service = {name: {"ok": 0, "blocked": 0, "error": 0} for name in SERVICES}
    streaming_ok = 0
    for st in streaming.values():
        if any(res.get("status") == "ok" for res in st.values()):
            streaming_ok += 1
        for name, res in st.items():
            status = res.get("status", "error")
            if status not in per_service[name]:
                status = "error"
            per_service[name][status] += 1
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
        "services": list(SERVICES),
        "streaming": per_service,
        "streaming_ok": streaming_ok,
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

    geo = await batch_ipapi([res["ip"] for res in results.values()])

    rep_ips = [res["ip"] for res in results.values()]
    asn_map = {ip: norm_asn(geo[ip].get("asn")) for ip in rep_ips
               if ip in geo and norm_asn(geo[ip].get("asn"))}
    risk_data = await lookup_all_risk(rep_ips, args, asn_map)
    if risk_data:
        print(
            f"Reputation: {len(risk_data)}/{len(set(rep_ips))} IPs from "
            f"{', '.join(args.reputation_sources)}"
        )
    abuse_map = await run_abuse(results, {
        k: {"exit_ip": res["ip"]} for k, res in results.items()
    }, args)
    ipinfo = build_ipinfo_map(
        results, geo, abuse_map, risk_data, args.reputation_weights
    )
    rep_map = build_reputation_map(
        results, risk_data, args.reputation_weights
    )

    streaming = finalize_streaming(results, ipinfo)
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
    write_json(STREAMING_FILE, keyed_json(streaming))
    if abuse_map:
        write_json(ABUSE_FILE, keyed_json(abuse_map))
    meta = build_meta(results, ipinfo, streaming, abuse_map, rep_map)
    write_json(QUALITY_META_FILE, meta)
    annotate_valid_files(annotations)

    print(
        f"streaming_ok={meta['streaming_ok']} "
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
        "--services", nargs="*", default=None,
        help="Services to check (default: all of netflix disney youtube max prime openai)",
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
        "(default: netcoffee,ncgy,ip-api,ipquery,ffraud,blackbox,otx,ipsum,"
        "ipapi_is,ipdata,whatismyip,dc_asn,abuse_list,vpn_asn,resproxy_asn,"
        "proxycheck,ip2location)",
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
    if not args.services:
        args.services = list(SERVICES)
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

