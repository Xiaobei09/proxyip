#!/usr/bin/env python3
"""Reorganize country/set/port files by exit IP country.

Reads ``data/valid/ipinfo.json`` (written by ``quality_check.py``) and moves
proxy lines whose exit-IP country differs from the listed country (``#CC``)
to the exit country directory.  The ``#CC`` + flag-emoji in each moved line is
rewritten to reflect the exit country so that directory and line content stay
consistent.

Idempotent: running twice with the same ``ipinfo.json`` produces no changes.

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
import sys
from pathlib import Path

from common import (
    COUNTRIES_DIR,
    IPINFO_FILE,
    VALID_DIR,
    line_to_key,
    parse_ltd_line,
    write_text_if_changed,
)


def flag_of(cc: str) -> str:
    """Regional-indicator emoji flag for an ISO 3166-1 alpha-2 code."""
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in cc)


def rewrite_cc(line: str, new_cc: str) -> str:
    """Replace the ``#<emoji><CC>`` segment with ``#<new_emoji><new_cc>``.

    Everything after the first ``-`` following the CC (annotations, exit
    region marker, …) is preserved unchanged.
    """
    parsed = parse_ltd_line(line)
    if not parsed:
        return line
    _old_key, _ip, _port, old_cc = parsed
    if old_cc == new_cc:
        return line
    addr, rest = line.rsplit("#", 1)
    # Skip emoji (non-ASCII) to reach the 2-letter CC
    i = 0
    while i < len(rest) and ord(rest[i]) > 127:
        i += 1
    after_cc = rest[i + 2:]  # keep everything after old CC (starting with '-')
    new_emoji = flag_of(new_cc)
    return f"{addr}#{new_emoji}{new_cc}{after_cc}"


def load_ipinfo(ipinfo_path: Path) -> dict:
    """Load ipinfo.json → ``{key: {country_code, country_match, …}}``."""
    if not ipinfo_path.exists():
        return {}
    data = json.loads(ipinfo_path.read_text(encoding="utf-8"))
    return data.get("proxies", data)


def _build_exit_map(ipinfo: dict) -> dict[str, str]:
    """``{key: exit_cc}`` for proxies where ``country_match=False``."""
    result: dict[str, str] = {}
    for key, info in ipinfo.items():
        if not isinstance(info, dict):
            continue
        if info.get("country_match") is not False:
            continue
        exit_cc = info.get("country_code")
        if exit_cc and len(exit_cc) == 2 and exit_cc.isalpha():
            result[key] = exit_cc.upper()
    return result


def reorganize_file(
    path: Path, exit_map: dict[str, str], stats: dict[str, int]
) -> None:
    """Reorganize a single txt file in-place based on ``exit_map``.

    Lines whose key is in ``exit_map`` are rewritten (CC + emoji) and moved
    to the exit country's counterpart path.  ``stats`` accumulates counts.
    """
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    keep: list[str] = []
    # {exit_cc: [line, …]}
    moves: dict[str, list[str]] = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        key = line_to_key(line)
        if key and key in exit_map:
            new_cc = exit_map[key]
            moved_line = rewrite_cc(line, new_cc)
            moves.setdefault(new_cc, []).append(moved_line)
            stats["moved"] += 1
        else:
            keep.append(raw)
    if not moves:
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
    # sets/<name>/all.txt    → sets/<name>/all.txt   (no change, just rewrite CC)
    # ports/<port>.txt       → ports/<port>.txt       (no change, just rewrite CC)
    if "countries" in parts:
        idx = parts.index("countries")
        new_parts = list(parts)
        new_parts[idx + 1] = new_cc
        return Path(*new_parts)
    # sets/ and ports/ stay in the same directory (only line content changes)
    return src


def reorganize(ipinfo_path: Path, data_dir: Path) -> int:
    """Main entry: reorganize all country/set/port files.  Returns moved count."""
    ipinfo = load_ipinfo(ipinfo_path)
    exit_map = _build_exit_map(ipinfo)
    if not exit_map:
        print("No country mismatches to reorganize.")
        return 0
    print(f"Reorganizing {len(exit_map)} mismatched proxies ...")
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
        default=VALID_DIR.parent,
        help="Data root (default: data/)",
    )
    parser.add_argument(
        "--ipinfo",
        type=Path,
        default=None,
        help="Path to ipinfo.json (default: <data-dir>/valid/ipinfo.json)",
    )
    args = parser.parse_args(argv)
    ipinfo_path = args.ipinfo or (args.data_dir / "valid" / "ipinfo.json")
    moved = reorganize(ipinfo_path, args.data_dir)
    return 0 if moved >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
