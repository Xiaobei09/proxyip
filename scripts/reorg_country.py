#!/usr/bin/env python3
"""Reorganize country/set/port files by exit IP country.

出口国观测经四源汇聚（``common.build_exit_cc_map``：external_check >
upstream_meta > streaming > ipinfo），将代理行标注/迁移为 ``#<IC>→<OC>``
格式。已有 ``→CC`` 但与新观测不同视为陈旧，直接替换；同国行也补齐标记。

Idempotent: running twice with the same quality JSONs produces no changes.

Affected directories:

- ``data/valid/countries/*/all.txt``
- ``data/valid/sets/*/all.txt``
- ``data/valid/ports/*.txt``

Sub-group files (``cn.txt``, ``v4.txt``, …) are **not** reorganised; they will
be refreshed on the next ``annotate_classify.py`` run.

Usage::

    python scripts/reorg_country.py [--data-dir data]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import (
    DATA_DIR,
    build_exit_cc_map,
    line_to_key,
    parse_ltd_line,
    upsert_exit_region,
    write_text_if_changed,
)


def ensure_exit_marker(line: str, exit_cc: str) -> str:
    """Insert or **replace** ``→<exit_cc>`` after ``#<emoji><CC>``.

    The listed ``#CC`` is preserved; only the exit-country marker changes.
    已有 ``→`` 但国家不同视为陈旧观测，直接替换（出口会漂移）。
    """
    parsed = parse_ltd_line(line)
    if not parsed:
        return line
    return upsert_exit_region(line, exit_cc)


def load_quality_json(path: Path) -> dict:
    """Load a quality JSON → ``{key: info}``；缺失/损坏 → ``{}``。"""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data.get("proxies", data) if isinstance(data, dict) else {}


def reorganize_file(
    path: Path, exit_map: dict[str, str], stats: dict[str, int]
) -> None:
    """Reorganize a single txt file in-place based on ``exit_map``.

    命中出口观测的行一律 upsert ``→OC`` 标记（同国也标注，保证覆盖面）；
    仅当位于 ``countries/<CC>/`` 且与出口国不同时才迁移目录。sets/ports
    混国文件只标注不移动。
    """
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    keep: list[str] = []
    # {exit_cc: [line, …]}
    moves: dict[str, list[str]] = {}
    changed = False
    # Determine this file's country code from path (countries/<CC>/all.txt)
    src_cc = _path_country(path)
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        key = line_to_key(line)
        if key and key in exit_map:
            exit_cc = exit_map[key]
            marked = ensure_exit_marker(line, exit_cc)
            if src_cc is None or src_cc == exit_cc:
                # sets/ports 混国文件或已在出口国目录：只更新标记
                if marked != raw:
                    changed = True
                keep.append(marked)
                continue
            moves.setdefault(exit_cc, []).append(marked)
            stats["moved"] += 1
        else:
            keep.append(raw)
    if not moves and not changed:
        return
    write_text_if_changed(path, "\n".join(keep) + "\n" if keep else "")
    stats["files_written"] += 1
    # Append moved lines to exit-country counterpart
    for new_cc, new_lines in moves.items():
        # Determine target path: mirror the same sub-path under the new CC dir
        target = _target_path(path, new_cc)
        existing = target.read_text(encoding="utf-8") if target.exists() else ""
        merged = (existing.rstrip("\n") + "\n" if existing else "") + "\n".join(new_lines) + "\n"
        write_text_if_changed(target, merged)
        stats["files_written"] += 1


def _target_path(src: Path, new_cc: str) -> Path:
    """Map ``src`` to its counterpart under the exit country directory."""
    parts = src.parts
    # countries/<CC>/all.txt → countries/<new_cc>/all.txt
    # sets/<name>/all.txt    → sets/<name>/all.txt   (no change)
    # ports/<port>.txt       → ports/<port>.txt       (no change)
    if "countries" in parts:
        idx = parts.index("countries")
        new_parts = list(parts)
        new_parts[idx + 1] = new_cc
        return Path(*new_parts)
    return src


def _path_country(path: Path) -> str | None:
    """Extract country code from ``countries/<CC>/…`` path, or ``None``."""
    parts = path.parts
    if "countries" in parts:
        idx = parts.index("countries")
        if idx + 1 < len(parts):
            cc = parts[idx + 1]
            if len(cc) == 2 and cc.isalpha():
                return cc.upper()
    return None


def reorganize(ipinfo_path: Path, data_dir: Path) -> int:
    """Main entry: reorganize all country/set/port files.  Returns moved count.

    出口国观测四源汇聚（external_check > upstream_meta > streaming >
    ipinfo，见 common.build_exit_cc_map），不再仅依赖 ipinfo 的
    country_match（历史覆盖不足 1%）。
    """
    quality_dir = data_dir / "quality"
    ipinfo = {"proxies": load_quality_json(ipinfo_path)}
    external = {"proxies": load_quality_json(quality_dir / "external_check.json")}
    upstream = {"proxies": load_quality_json(quality_dir / "upstream_meta.json")}
    streaming = {"proxies": load_quality_json(quality_dir / "streaming.json")}
    family = {"proxies": load_quality_json(quality_dir / "exit_family.json")}
    exit_map = build_exit_cc_map(ipinfo, external, upstream, streaming, family)
    if not exit_map:
        print("No exit-country observations to reorganize.")
        return 0
    print(f"Reorganizing with {len(exit_map)} exit observations ...")
    stats = {"moved": 0, "files_written": 0}
    valid_root = data_dir / "valid"
    # countries/
    for all_txt in sorted((valid_root / "countries").glob("*/all.txt")):
        reorganize_file(all_txt, exit_map, stats)
    # sets/
    for all_txt in sorted((valid_root / "sets").glob("*/all.txt")):
        reorganize_file(all_txt, exit_map, stats)
    # ports/
    for port_txt in sorted((valid_root / "ports").glob("*.txt")):
        reorganize_file(port_txt, exit_map, stats)
    print(f"Moved {stats['moved']} lines, wrote {stats['files_written']} files.")
    return stats["moved"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DATA_DIR,
        help="Data root (default: data/)",
    )
    parser.add_argument(
        "--ipinfo",
        type=Path,
        default=None,
        help="Path to ipinfo.json (default: <data-dir>/quality/ipinfo.json)",
    )
    args = parser.parse_args(argv)
    ipinfo_path = args.ipinfo or (args.data_dir / "quality" / "ipinfo.json")
    moved = reorganize(ipinfo_path, args.data_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
