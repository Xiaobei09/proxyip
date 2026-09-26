#!/usr/bin/env python3
"""Streaming unlock and exit-IP quality checks for alive proxies.

Runs on the full alive pool (default ``data/valid/all.txt``) and writes
under ``data/quality/``:

- ``ipinfo.json``      exit IP / geo / IP type / reputation score + source
                      (per checked proxy)
- ``abuse.json``       optional abuse-score results (key-gated)
- ``reputation.json``  0-100 reputation scores (multi-source weighted merge
                      over ``DEFAULT_REP_SOURCES``, plus opt-in sources via
                      ``--reputation-sources``; see ``quality_reputation.py``
                      ``REPUTATION_WEIGHTS`` and docs/scripts.md『默认源与权重』表),
                      keyed by ``ip:port#CC``
- ``all_rep.txt``      ``all.txt`` lines re-sorted by reputation desc
- ``countries/<cc>/rep.txt``, ``sets/<name>/rep.txt``
                      per-country / per-set ``all.txt`` re-sorted by reputation
- ``quality_meta.json`` aggregated summary for stats and charts
- annotated ``*.txt``  all/countries/ports/sets lines get ``#``-suffix segments
                      (``countries/*/all.txt`` and ``*/ltd.txt``; ``rep.txt`` is
                      written pre-annotated by ``write_reputation_files``)

All proxies use the TLS (Cloudflare edge) method: direct TLS connections with
SNI routing. Only Cloudflare-fronted hosts are reachable. The exit is the
probe-observed egress IP (``resolve_exit_ips``: trace > exit_family > proxy
itself).

Annotation format appends to the existing ``ip:port#<flag><cc>-<lat>-<speed>``
lines as ``-<rep>`` (type tokens ``DC/RES/MOB/PROXY`` 由 annotate_classify
追加), e.g. ``1.2.3.4:443#US-120ms-0.44MB/s-72``.
(流媒体解锁检查已移除——历史行上的 NF/D+/YT/MX/PV/GPT token 由
normalize_note 作为遗留段继续容忍解析，但不再产生新观测。) When the exit
region is known it is inserted right after the entry country code as
``<cc>→<exit>`` (CF edge ``loc`` airport code), e.g.
``1.2.3.4:443#US→LAX-120ms-...``.
Lines without results stay untouched.

``--time-budget`` 墙钟感知止损：探测相位让出 ``POST_RESERVE_S`` 给后处理，
四个网络相位（probe / ip-api geo / reputation / abuse）均受绝对 deadline
硬门控——超龄不再新开任务、已提交结果照常落盘（partial commit），避免缓存
大面积失效时某相位把 job 拖过 CI 的 ``timeout-minutes`` 硬杀。
"""

import argparse
import asyncio
import logging
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
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
            # R233：来源身份一律经 rep_public_id 去身份后才进已发布产物。
            # ``multi`` 是语义哨兵（多源交叉），rep_public_id 原样透传。
            #
            # ``rep_flags`` **刻意不去身份**：它是**语义标志**而非来源身份
            # （hosting/anonymous/listed/proxy/vpn/crawler/mobile…），
            # 下游 build_good 等按字面语义读取。实测其中 ``abuse``（2545 处）
            # 与词表撞名——那只是因为私有包有 rep_abuse.py，**属词表假阳性**，
            # 把它哈希掉会摧毁 flags 的可判读性。故 flags 保持原样。
            if abuse_item:
                info["reputation_source"] = rep_public_id(
                    abuse_item.get("service"))
            else:
                _score, responding, flagged, numeric = vote_reputation(
                    signals, weights
                )
                info["reputation_source"] = rep_public_id(
                    responding[0] if len(responding) == 1 else "multi"
                )
                info["risk_sources"] = [rep_public_id(s) for s in numeric]
                info["rep_sources"] = [rep_public_id(s) for s in responding]
                info["rep_flags"] = flagged
        info["risk"] = derive_risk(signals, abuse_item, weights)
        info_map[res["key"]] = info
    return info_map


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
        # R233：来源名一律经 rep_public_id 去身份后才进已发布产物
        # （data/quality/reputation.json 与 ipinfo.json 的每条记录都带这三个
        # 字段）。``multi`` 是语义哨兵，rep_public_id 原样透传。
        rep_map[res["key"]] = {
            "score": score,
            "risk": reputation_risk(score),
            "source": rep_public_id(source),
            "sources": [rep_public_id(s) for s in responding],
            "flags": flagged,
            "numeric": [rep_public_id(s) for s in numeric],
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
    - ``_stable``:  china.json streak≥2（连续两轮大陆可达）且 flip≤1
      （排除"可达↔不可达"慢性振荡源，见 common.load_china_stable_keys）
    根级 all_rep / all_rep_ltd / all_{g}_rep / all_{g}_rep_ltd 全覆盖；子目录
    产出 rep(+v/s)、rep_ltd(+v/s) 与 {g}_rep(_ltd) 单维度文件。源文件缺失
    时清理对应产物（空清单不落盘并清理上轮残留）。
    """
    speed_keys = load_speed_keys()
    stable_keys = load_china_stable_keys()

    def emit(base: Path, lines: list[str]) -> None:
        """写清单本体 + verified/stable 变体（空清单/空变体清理旧文件）。"""
        if lines:
            write_text_if_changed(base, "\n".join(lines) + "\n")
        elif base.exists():
            base.unlink()
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

    # --- 根级 all_rep_ltd(+v/s)：all_ltd.txt 的同规则信誉排行 ---
    all_ltd = valid_root / "all_ltd.txt"
    if all_ltd.exists():
        emit(
            valid_root / "all_rep_ltd.txt",
            build_ranked(all_ltd.read_text(encoding="utf-8"), annotations, rep_map),
        )
    else:
        for suffix in ("", "_verified", "_stable"):
            stale = valid_root / f"all_rep_ltd{suffix}.txt"
            if stale.exists():
                stale.unlink()

    # --- 顶层 cross-product rep 文件 (all_cn_rep.txt, all_cn4_rep_ltd.txt 等) ---
    for g in REP_GROUP_NAMES:
        src = valid_root / f"all_{g}.txt"
        if src.exists():
            r = build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map)
            emit(valid_root / f"all_{g}_rep.txt", r)
        else:
            for suffix in ("", "_verified", "_stable"):
                stale = valid_root / f"all_{g}_rep{suffix}.txt"
                if stale.exists():
                    stale.unlink()
        ltd_src = valid_root / f"all_{g}_ltd.txt"
        if ltd_src.exists():
            r = build_ranked(ltd_src.read_text(encoding="utf-8"), annotations, rep_map)
            emit(valid_root / f"all_{g}_rep_ltd.txt", r)
        else:
            for suffix in ("", "_verified", "_stable"):
                stale = valid_root / f"all_{g}_rep_ltd{suffix}.txt"
                if stale.exists():
                    stale.unlink()

    # --- 每个 set/country 子目录: rep(+v/s) + rep_ltd(+v/s) + 分组 rep ---
    for sub in ("countries", "sets"):
        for src in sorted((valid_root / sub).glob("*/all.txt")):
            emit(
                src.with_name("rep.txt"),
                build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map),
            )
        for stale in sorted((valid_root / sub).glob("*/rep.txt")):
            if not stale.with_name("all.txt").exists():
                stale.unlink()
        for ltd_src in sorted((valid_root / sub).glob("*/ltd.txt")):
            emit(
                ltd_src.with_name("rep_ltd.txt"),
                build_ranked(
                    ltd_src.read_text(encoding="utf-8"), annotations, rep_map
                ),
            )
        for stale in sorted((valid_root / sub).glob("*/rep_ltd.txt")):
            if not stale.with_name("ltd.txt").exists():
                stale.unlink()
        for g in REP_GROUP_NAMES:
            for src in sorted((valid_root / sub).glob(f"*/{g}.txt")):
                r = build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map)
                rep_path = src.with_name(f"{g}_rep.txt")
                if r:
                    write_text_if_changed(rep_path, "\n".join(r) + "\n")
                elif rep_path.exists():
                    rep_path.unlink()
            for src in sorted((valid_root / sub).glob(f"*/{g}_ltd.txt")):
                r = build_ranked(src.read_text(encoding="utf-8"), annotations, rep_map)
                rep_path = src.with_name(f"{g}_rep_ltd.txt")
                if r:
                    write_text_if_changed(rep_path, "\n".join(r) + "\n")
                elif rep_path.exists():
                    rep_path.unlink()
            for stale in sorted((valid_root / sub).glob(f"*/{g}_rep.txt")):
                if not stale.with_name(f"{g}.txt").exists():
                    stale.unlink()
            for stale in sorted((valid_root / sub).glob(f"*/{g}_rep_ltd.txt")):
                if not stale.with_name(f"{g}_ltd.txt").exists():
                    stale.unlink()

    entries: dict[str, dict] = {}
    for key, rep in rep_map.items():
        ent = {
            "score": rep["score"],
            "risk": rep["risk"],
            "source": rep["source"],
            "sources": rep.get("sources") or [],
            "flags": rep.get("flags") or [],
            "numeric": rep.get("numeric") or [],
        }
        if rep.get("deep_bonus") is not None:
            ent["deep_bonus"] = rep["deep_bonus"]
        entries[key] = ent
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
    skipped: list | None = None,
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
    _s_reps = sorted(reps)
    _n_reps = len(_s_reps)
    rep_median = (
        round(_s_reps[_n_reps // 2] if _n_reps % 2
              else (_s_reps[_n_reps // 2 - 1] + _s_reps[_n_reps // 2]) / 2, 1)
        if _n_reps else None
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
        "rep_median": rep_median,
        "country_mismatch": country_mismatch,
        "ext_check_total": ext_total,
        "ext_check_ok": ext_ok,
        "skipped": list(skipped or []),
    }


POST_RESERVE_S = 600


def _within_budget(start: float, budget: int) -> bool:
    """``True`` 只要墙钟预算仍有余量；``budget <= 0``（不限）恒为 ``True``。

    供 run() 相位感知止损：超过预算后不再开启新的网络密集相位，已得的
    探测/解析结果仍照常落盘（提交部分结果，而不撞 120min 硬杀整链）。
    """
    return budget <= 0 or time.monotonic() - start < budget


def ensure_worker_executor(workers: int) -> int:
    """放大事件循环默认 executor，使配置的并发真正生效。

    ``asyncio.to_thread`` 默认走 loop 的 default executor，其线程数为
    ``min(32, cpu+4)``——GitHub runner（2-4 核）上仅 ~8 线程，远低于探针
    ``--workers``（60）与信誉各源 semaphore 之和。于是所有阻塞型 HTTP
    查询被这个小池串行化：占绝大多数的快速请求还好，但少量失效代理要等
    满 ``check_external_api`` 的 30s 超时，串行尾巴会把相位拖到预算上限
    （实证：18243 探针中最后 ~600 个吃掉 62min）。这里按 I/O 密集场景放大
    默认池（线程多 > 核数无妨），让 semaphore 成为真实并发上限。

    返回最终线程数。
    """
    want = max(64, workers * 2)
    loop = asyncio.get_running_loop()
    current = getattr(loop, "_default_executor", None)
    if current is not None and getattr(current, "_max_workers", 0) >= want:
        return current._max_workers
    loop.set_default_executor(
        ThreadPoolExecutor(max_workers=want, thread_name_prefix="qworker")
    )
    return want


async def run(args: argparse.Namespace) -> int:
    print(f"Worker executor: {ensure_worker_executor(args.workers)} threads")
    if not args.source.exists():
        print(f"Error: {args.source} not found", file=sys.stderr)
        return 1
    start = time.monotonic()
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
    budget = args.time_budget if args.time_budget and args.time_budget > 0 else 0
    skipped: list[str] = []
    if budget:
        print(
            f"Time budget {budget}s; will stop opening new phases at "
            f"deadline and commit partial results"
        )
    print(
        f"Checking {len(entries)} proxies "
        f"(timeout={args.timeout}s, workers={args.workers}) ..."
    )

    # 探测相位让出 POST_RESERVE_S 给后处理（geo/信誉/滥用），使预算内
    # 优先保住探针全检；后处理相位受全局 deadline _within_budget 门控
    # （超时则跳过 geo/reputation/abuse 相位并计入 skipped 告警），本地
    # 写盘照常短时完成，不会撞 CI 超时。
    # 降级语义：budget 耗尽导致 reputation 相位被 skip 时，risk_data={}
    # → rep_map 为空 → reputation.json 本轮不写（旧文件滞留不清理），
    # quality_meta/ipinfo/abuse 仍照常产出。R18 后 probe 止损先行为主，
    # 该降级仅在超载时触发。
    probe_args = argparse.Namespace(**vars(args))
    if budget:
        probe_args.time_budget = max(1, budget - POST_RESERVE_S)
    results = await run_checks(entries, methods, probe_args)
    print(f"Completed {len(results)} checks")

    # 出口 IP 解析后，信誉/地理/滥用全部查真实出口——CF 中转代理的
    # 入口恒为 CF 边缘 IP，查入口会得到千篇一律的"干净"结果。
    fam_map = read_json(EXIT_FAMILY_FILE).get("proxies", {})
    results = resolve_exit_ips(results, fam_map)

    # 相位外部受 _within_budget 门控；相位内部（batch_ipapi 分块/per-IP
    # 兜底）也接收绝对 deadline 止损，防止上游全挂时长时间空转突破预算。
    phase_deadline = (start + budget) if budget else None
    geo: dict = {}
    if _within_budget(start, budget):
        geo = await batch_ipapi(
            [res["exit_ip"] for res in results.values()],
            deadline=phase_deadline,
        )
    else:
        skipped.append("ip-api geo")
        print("Warning: time budget exhausted; skipping ip-api geo",
              file=sys.stderr)

    rep_ips = [res["exit_ip"] for res in results.values()]
    asn_map = {ip: norm_asn(geo[ip].get("asn")) for ip in rep_ips
               if ip in geo and norm_asn(geo[ip].get("asn"))}
    risk_data: dict = {}
    if _within_budget(start, budget):
        risk_data = await lookup_all_risk(
            rep_ips, args, asn_map, deadline=phase_deadline
        )
    else:
        skipped.append("reputation lookup")
        print("Warning: time budget exhausted; skipping reputation lookup",
              file=sys.stderr)
    if risk_data:
        print(
            f"Reputation: {len(risk_data)}/{len(set(rep_ips))} IPs from "
            f"{', '.join(args.reputation_sources)}"
        )
    abuse_map: dict = {}
    abuse_enabled = args.abuse_service != "none" and bool(args.abuse_key)
    if abuse_enabled and _within_budget(start, budget):
        abuse_map = await run_abuse(results, {
            k: {"exit_ip": res["exit_ip"]} for k, res in results.items()
        }, args, deadline=phase_deadline)
        cached_abuse = load_abuse_file()
        if cached_abuse:
            before = len(abuse_map)
            abuse_map = merge_abuse_fallback(abuse_map, cached_abuse, set(results))
            used = len(abuse_map) - before
            if used:
                print(
                    f"Abuse: filled {used} proxy(es) from cached abuse.json "
                    "(phase partial/unavailable)"
                )
    elif abuse_enabled:
        # 仅当滥用相位确实启用时才记为跳过，避免 abuse_service=none 时
        # 产生假「降级」告警污染 quality_meta.skipped。
        skipped.append("abuse scores")
        print("Warning: time budget exhausted; skipping abuse scores",
              file=sys.stderr)
        abuse_map = merge_abuse_fallback({}, load_abuse_file(), set(results))
        if abuse_map:
            print(
                f"Warning: using {len(abuse_map)} cached abuse score(s) "
                "as fallback", file=sys.stderr)
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
    meta = build_meta(results, ipinfo, abuse_map, rep_map, skipped)
    write_json(QUALITY_META_FILE, meta)
    annotate_valid_files(annotations)

    print(
        f"by_type={meta['by_type']} "
        f"rep_avg={meta['rep_avg']} rep_dist={meta['rep_dist']}"
    )
    if budget and skipped:
        print(
            f"Warning: {len(skipped)} phase(s) skipped under time budget "
            f"{budget}s (skipped: {', '.join(skipped)}); committed "
            f"{len(results)} proxies, rep_avg={meta['rep_avg']}",
            file=sys.stderr,
        )
    return 0


def parse_reputation_sources(
    value: str,
    provider: str = "default",
    allowed: dict | None = None,
    default: list | None = None,
) -> tuple[list[str], list[str]]:
    """Resolve ``--reputation-sources``/``--reputation-provider``.

    Returns ``(sources, unknown)``。``provider`` 为 ``none``/``netcoffee``/
    ``ip-api`` 时直接给出对应源（``unknown`` 恒空）；否则把 ``value`` 按
    逗号拆分，仅保留 ``allowed``（默认 ``REPUTATION_WEIGHTS``）内的知名，
    未知/无效项放入 ``unknown`` 由调用方告警——避免 typo 被静默丢弃后
    整组回退成全量默认源的误配置。合法源为空时回退 ``default``。
    """
    allowed = allowed if allowed is not None else REPUTATION_WEIGHTS
    default = default if default is not None else list(DEFAULT_REP_SOURCES)
    if provider == "none":
        return [], []
    if provider == "netcoffee":
        return ["netcoffee", "ip-api"], []
    if provider == "ip-api":
        return ["ip-api"], []
    raw = [s.strip() for s in (value or "").split(",") if s.strip()]
    unknown = [s for s in raw if s not in allowed]
    valid = [s for s in raw if s in allowed]
    if not valid:
        return list(default), unknown
    return valid, unknown


def parse_reputation_weights(
    override: str,
    base: dict | None = None,
) -> tuple[dict, list[str]]:
    """Apply ``--reputation-weights-override`` on a copy of the base weights.

    Returns ``(weights, unknown)``。只认 ``base``（默认 ``REPUTATION_WEIGHTS``）
    内已知名；未知/无 ``:`` 分隔的片段放入 ``unknown`` 供告警，杜绝
    typo 静默「新增 dict 键」却让目标源权重不生效（同 R260 的 source 语义）。
    数值非法（非 int）时保留原权重并告警。
    """
    base = dict(base) if base is not None else dict(REPUTATION_WEIGHTS)
    unknown: list[str] = []
    for tok in (override or "").split(","):
        if not tok.strip():
            continue
        name, sep, weight = tok.partition(":")
        if not sep:
            unknown.append(tok.strip())
            continue
        name = name.strip()
        if name not in base:
            unknown.append(tok.strip())
            continue
        try:
            base[name] = int(weight)
        except ValueError:
            logging.warning("Invalid weight value for %s: %s", name, weight)
    return base, unknown


def list_rep_sources() -> int:
    """`--list-rep-sources`：打印全部信誉源与权重/默认成员（R142 可发现性）。

    动态读权重表（经 PCB 回绑，无包回退内置静态值）；无网络无写盘。
    """
    defaults = set(DEFAULT_REP_SOURCES)
    print("name weight default")
    for name, weight in REPUTATION_WEIGHTS.items():
        print(f"{name} {weight} {'yes' if name in defaults else 'no'}")
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
        "(default: all DEFAULT_REP_SOURCES，见 docs/scripts.md『默认源与权重』表；"
        "有效源名见 --list-rep-sources)",
    )
    parser.add_argument(
        "--reputation-weights",
        dest="reputation_weights_override",
        default=None,
        help="Comma list of name:weight overrides, e.g. netcoffee:40,ncgy:20 "
        "(有效源名见 --list-rep-sources)",
    )
    parser.add_argument(
        "--list-rep-sources", action="store_true",
        help="列出全部信誉源与权重/默认成员（动态读权重表，无网络无写盘）",
    )
    parser.add_argument(
        "--rep-cache-ttl",
        type=int,
        default=REP_CACHE_TTL,
        help="Reputation signal cache TTL in seconds; expired entries are "
             "re-queried and kept as fallback on refresh failure "
             "(default: %(default)s)",
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
        help="Stop after this many seconds (0 = unlimited); at deadline new "
             "phases are skipped (600s reserved for geo/reputation/abuse) "
             "and partial results are still committed",
    )
    args = parser.parse_args(argv)
    if args.list_rep_sources:
        return list_rep_sources()
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
    args.reputation_weights, weight_unknown = parse_reputation_weights(
        args.reputation_weights_override,
    )
    for name in weight_unknown:
        logging.warning(
            "Unknown reputation weight target %r dropped; "
            "check --reputation-weights (expect <source>:<int>)",
            name,
        )
    args.reputation_sources = args.reputation_sources or ""
    parsed, unknown = parse_reputation_sources(
        args.reputation_sources, args.reputation_provider,
    )
    args.reputation_sources = parsed
    for name in unknown:
        logging.warning(
            "Unknown reputation source %r dropped; check --reputation-sources",
            name,
        )
    if args.reputation_provider not in ("none", "netcoffee", "ip-api") and \
       unknown and args.reputation_sources == list(DEFAULT_REP_SOURCES):
        logging.warning(
            "No valid reputation source survived; fell back to all defaults "
            "(%d sources) instead of only %d requested",
            len(list(DEFAULT_REP_SOURCES)), len(unknown),
        )
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

