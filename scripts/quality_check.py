#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Runs on a bounded population (default ``data/valid/all_ltd.txt``, the
per-country fastest survivors) and writes under ``data/valid/``:

- ``ipinfo.json``      exit IP / address family / dual-stack / geo / IP type /
                      reputation score + source (per checked proxy)
- ``streaming.json``   per-service unlock results (incl. native Netflix)
- ``abuse.json``       optional abuse-score results (key-gated)
- ``reputation.json``  0-100 reputation scores (multi-source weighted merge:
                      net.coffee / ip.nc.gy / ip-api / ipdata / Tor exit lists,
                      optionally GetIPIntel + ipapi.is), keyed by ``ip:port#CC``
- ``all_rep.txt``      ``all_ltd.txt`` lines re-sorted by reputation desc
- ``countries/<cc>/rep.txt``, ``sets/<name>/rep.txt``
                      per-country / per-set ``all.txt`` re-sorted by reputation
- ``quality_meta.json`` aggregated summary for stats and charts
- annotated ``*.txt``  all/countries/ports/sets lines get ``#``-suffix segments
                      (``countries/*/all.txt`` and ``*/ltd.txt``; ``rep.txt`` is
                      written pre-annotated by ``write_reputation_files``)

Two proxy flavors are handled, selected by the method recorded in
``data/valid/index.json``:

1. ``connect`` (standard HTTP CONNECT proxies): full suite - plain-HTTP exit
   IP echo (IPv4 + IPv6 for dual-stack), geo/IP type via ip-api batch, and
   per-service streaming unlocks over a CONNECT + TLS tunnel.
2. ``tls`` (Cloudflare edge proxies): only Cloudflare-fronted hosts are
   reachable via SNI routing, so only ChatGPT/OpenAI
   (``chat.openai.com/cdn-cgi/trace``) is probed; the exit is the edge itself
   and is tagged ``CF``.

Annotation format appends to the existing ``ip:port#<flag><cc>-<lat>-<speed>``
lines as ``-<streaming>-<type>-<rep>``, e.g.
``1.2.3.4:443#US-120ms-0.44MB/s-NF(US) D+ YT GPT-DC-72`` (streaming tokens
space-separated, IP-type tokens after a second dash, then the 0-100 reputation
score). When the exit region is known it is inserted right after the entry
country code as ``<cc>→<exit>`` (CF edge ``loc`` airport code for ``tls``
proxies, exit-IP country otherwise), e.g. ``1.2.3.4:443#US→LAX-120ms-...``.
Lines without results stay untouched.
"""
#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Facade module: the reputation/IP-risk domain lives in ``quality_reputation``
and the streaming/geo/network domain in ``quality_streaming``; both are
re-exported here so ``import quality_check as qc; qc.*`` keeps working.
File-writing, annotation and CLI orchestration stay in this module.
"""

import argparse
import asyncio
import re
import sys
from collections import Counter
from pathlib import Path

from common import *  # noqa: F401,F403  (paths + shared helpers)
from quality_reputation import *  # noqa: F401,F403
from quality_streaming import *  # noqa: F401,F403

def classify_ip(geo: dict) -> str:
    if geo.get("hosting"):
        return "DC"
    if geo.get("mobile"):
        return "MOB"
    if geo.get("proxy"):
        return "PROXY"
    return "RES"


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
        if res.get("tls"):
            continue
        ip4, ip6 = res.get("v4"), res.get("v6")
        geo_item = geo.get(ip4) or {}
        family, dual = "ipv4", False
        if ip4 and ip6:
            family, dual = "dual", True
        elif not ip4 and ip6:
            family = "ipv6"
        cc = geo_item.get("countryCode")
        exit_ip = ip4 or ip6
        abuse_item = abuse_map.get(res["key"])
        info = {
            "exit_ip": exit_ip,
            "family": family,
            "dual_stack": dual,
            "country": geo_item.get("country"),
            "country_code": cc,
            "region": geo_item.get("regionName"),
            "city": geo_item.get("city"),
            "asn": geo_item.get("asn"),
            "org": geo_item.get("org"),
            "isp": geo_item.get("isp"),
            "proxy": geo_item.get("proxy"),
            "hosting": geo_item.get("hosting"),
            "mobile": geo_item.get("mobile"),
            "listed_country": res["cc"],
            "country_match": (cc == res["cc"]) if cc else None,
            "ip_type": classify_ip(geo_item),
            "geo_checked": bool(cc),
        }
        risk_flags = {
            source: signal
            for source, signal in risk_data.get(exit_ip, {}).items()
        }
        if risk_flags:
            info["risk_flags"] = risk_flags
        signals = collect_signals(exit_ip, geo_item, risk_data, weights)
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


def build_reputation_map(
    results: dict,
    ipinfo: dict,
    risk_data: dict,
    weights: dict,
) -> dict[str, dict]:
    rep_map: dict[str, dict] = {}
    for res in results.values():
        if res.get("tls"):
            signals = collect_signals(
                res["ip"], {}, risk_data, weights, include_ipapi=False
            )
            score = compute_reputation(signals, None, weights)
            _score, sources = weighted_reputation(signals, weights)
            source = "multi" if len(sources) != 1 else (sources[0] if sources else None)
        else:
            info = ipinfo.get(res["key"]) or {}
            score = info.get("reputation")
            sources = info.get("risk_sources") or []
            source = info.get("reputation_source")
        if score is None:
            continue
        rep_map[res["key"]] = {
            "score": score,
            "risk": reputation_risk(score),
            "source": source,
            "sources": sources,
        }
    return rep_map


LATENCY_RE = re.compile(r"-(\d+)ms")


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
        out = line + ("-" + ann if ann else "")
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


def _write_atomic(path: Path, text: str) -> None:
    write_text_if_changed(path, text)


def write_reputation_files(source_text: str, annotations: dict, rep_map: dict) -> None:
    ranked = build_ranked(source_text, annotations, rep_map)
    _write_atomic(REP_RANK_FILE, "\n".join(ranked) + "\n")
    valid_root = REP_RANK_FILE.parent
    for sub in ("countries", "sets"):
        for src in sorted((valid_root / sub).glob("*/all.txt")):
            ranked = build_ranked(
                src.read_text(encoding="utf-8"), annotations, rep_map
            )
            _write_atomic(src.with_name("rep.txt"), "\n".join(ranked) + "\n")
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


def build_annotations(results: dict, ipinfo: dict, rep_map: dict) -> dict[str, str]:
    annotations: dict[str, str] = {}
    for res in results.values():
        stream_toks = streaming_tokens(res["streaming"])
        if res.get("tls"):
            type_toks = "CF"
        else:
            type_toks = type_tokens(ipinfo.get(res["key"]) or {})
        ann = build_annotation(stream_toks, type_toks)
        rep = rep_map.get(res["key"])
        if rep:
            ann = build_annotation(ann, str(rep["score"]))
        annotations[res["key"]] = ann
    return annotations


def build_exits(results: dict, ipinfo: dict) -> dict[str, str]:
    """Exit region per key: CF edge ``loc`` for ``tls`` proxies, else the exit-IP
    country. Used to annotate ``ip:port#<entry>→<exit>`` on valid lines."""
    exits: dict[str, str] = {}
    for res in results.values():
        if res.get("tls"):
            region = (res.get("streaming") or {}).get("openai", {}).get("region")
        else:
            region = (ipinfo.get(res["key"]) or {}).get("country_code")
        if region:
            exits[res["key"]] = region
    return exits


EXIT_REGION_RE = re.compile(r"^(.*#[^A-Z]*[A-Z]+)")


def insert_exit_region(line: str, exit_region: str) -> str:
    """Insert ``→<exit>`` right after the entry country code (idempotent)."""
    if not exit_region or "→" in line:
        return line
    m = EXIT_REGION_RE.match(line)
    if not m:
        return line
    return line[: m.end(1)] + "→" + exit_region + line[m.end(1):]


def annotate_text(
    text: str, annotations: dict, exits: dict | None = None
) -> tuple[str, bool]:
    out = []
    changed = False
    exits = exits or {}
    for line in text.splitlines():
        if not line:
            continue
        key = line_to_key(line)
        ann = annotations.get(key) if key else None
        exit_region = exits.get(key) if key else None
        out_line = insert_exit_region(line, exit_region) if exit_region else line
        if ann and not out_line.rstrip().endswith("-" + ann):
            out_line = out_line + "-" + ann
        if out_line != line:
            changed = True
        out.append(out_line)
    return "\n".join(out) + "\n", changed


def annotate_valid_files(annotations: dict, exits: dict | None = None) -> None:
    files: list[Path] = [VALID_DIR / "all.txt", VALID_DIR / "all_ltd.txt"]
    for sub in ("countries", "sets"):
        files.extend(sorted((VALID_DIR / sub).glob("*/all.txt")))
        files.extend(sorted((VALID_DIR / sub).glob("*/ltd.txt")))
    files.extend(sorted((VALID_DIR / "ports").glob("*.txt")))
    for path in files:
        if not path.exists():
            continue
        text, changed = annotate_text(
            path.read_text(encoding="utf-8"), annotations, exits
        )
        if changed:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(path)


def build_meta(
    results: dict, ipinfo: dict, streaming: dict, abuse_map: dict
) -> dict:
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
    family = Counter(info["family"] for info in ipinfo.values())
    mismatch = sum(
        1 for info in ipinfo.values() if info.get("country_match") is False
    )
    dual = sum(1 for info in ipinfo.values() if info.get("dual_stack"))
    risk = Counter(
        info["risk"] for info in ipinfo.values() if info.get("risk")
    )
    reps = [
        info["reputation"] for info in ipinfo.values()
        if info.get("reputation") is not None
    ]
    rep_dist = {
        "0-25": sum(1 for r in reps if r < 25),
        "25-50": sum(1 for r in reps if 25 <= r < 50),
        "50-75": sum(1 for r in reps if 50 <= r < 75),
        "75-100": sum(1 for r in reps if r >= 75),
    }
    return {
        "ts": now_ts(),
        "total": len(results),
        "connect": sum(1 for r in results.values() if not r.get("tls")),
        "tls": sum(1 for r in results.values() if r.get("tls")),
        "services": list(SERVICES),
        "streaming": per_service,
        "streaming_ok": streaming_ok,
        "by_type": dict(sorted(by_type.items())),
        "family": dict(sorted(family.items())),
        "dual_stack": dual,
        "country_mismatch": mismatch,
        "risk": dict(sorted(risk.items())),
        "abuse_checked": len(abuse_map),
        "reputation_checked": len(reps),
        "rep_dist": rep_dist,
        "rep_avg": (round(sum(reps) / len(reps), 1) if reps else None),
        "rep_median": (
            round(sorted(reps)[len(reps) // 2], 1) if reps else None
        ),
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

    geo = await batch_ipapi(
        [res["v4"] for res in results.values() if res.get("v4")]
    )
    ipinfo = build_ipinfo_map(results, geo, {})
    abuse_map = await run_abuse(results, ipinfo, args)

    rep_ips = []
    asn_map: dict[str, str] = {}
    for res in results.values():
        if res.get("tls"):
            rep_ips.append(res["ip"])
        else:
            info = ipinfo.get(res["key"]) or {}
            if info.get("exit_ip"):
                rep_ips.append(info["exit_ip"])
                if info.get("asn"):
                    asn_map[info["exit_ip"]] = info["asn"]
    risk_data = await lookup_all_risk(rep_ips, args, asn_map)
    if risk_data:
        print(
            f"Reputation: {len(risk_data)}/{len(set(rep_ips))} IPs from "
            f"{', '.join(args.reputation_sources)}"
        )
    ipinfo = build_ipinfo_map(
        results, geo, abuse_map, risk_data, args.reputation_weights
    )
    rep_map = build_reputation_map(
        results, ipinfo, risk_data, args.reputation_weights
    )

    streaming = finalize_streaming(results, ipinfo)
    annotations = build_annotations(results, ipinfo, rep_map)
    source_text = args.source.read_text(encoding="utf-8")
    if rep_map:
        write_reputation_files(source_text, annotations, rep_map)

    write_json(IPINFO_FILE, keyed_json(ipinfo))
    write_json(STREAMING_FILE, keyed_json(streaming))
    if abuse_map:
        write_json(ABUSE_FILE, keyed_json(abuse_map))
    meta = build_meta(results, ipinfo, streaming, abuse_map)
    write_json(QUALITY_META_FILE, meta)
    annotate_valid_files(annotations, build_exits(results, ipinfo))

    print(
        f"streaming_ok={meta['streaming_ok']} "
        f"by_type={meta['by_type']} family={meta['family']} "
        f"mismatch={meta['country_mismatch']} "
        f"rep_avg={meta['rep_avg']} rep_dist={meta['rep_dist']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=DEFAULT_SOURCE,
        help="Input proxy list (default: data/valid/all_ltd.txt)",
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
        "(default: netcoffee,ncgy,ip-api,ipquery,ffraud,ipapi_is,ipdata,"
        "whatismyip,dc_asn,abuse_list,torlist,vpn_asn,resproxy_asn)",
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
                pass
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

