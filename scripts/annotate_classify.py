#!/usr/bin/env python3
"""Fill missing suffixes and add node classification tokens to proxy lines.

Reads JSON data files (ipinfo.json, reputation.json, china.json,
exit_family.json, streaming.json) and annotates all ``data/valid/*.txt``
files with missing suffixes (CN, V4/V6, streaming, reputation) and
classification tokens (IP type, speed tier).

Output line format:
  ip:port#<flag><CC>[→<exit>]-<latency>ms[-<speed>MB/s][-<note>]-<type>-<tier>

where ``<type>`` is ``DC``/``RES``/``MOB``/``PROXY`` and ``<tier>`` is
``fast``/``mid``/``slow``.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    VALID_DIR,
    has_token,
    line_to_key,
    parse_line,
    write_text_if_changed,
)
from quality_streaming import streaming_tokens

SPEED_RE = re.compile(r"(\d+(?:\.\d+)?)MB/s")
LATENCY_RE = re.compile(r"-(\d+)ms")
EXIT_REGION_RE = re.compile(r"^(.*#[^A-Z]*[A-Z]+)")

IP_TYPES = frozenset({"DC", "RES", "MOB", "PROXY"})
FAMILY_TOKENS = frozenset({"V4", "V6", "DS"})


def speed_tier(note: str) -> str:
    """Parse speed from note, return ``fast``/``mid``/``slow``/``unknown``."""
    m = SPEED_RE.search(note)
    if not m:
        return "unknown"
    mbps = float(m.group(1))
    if mbps >= 5:
        return "fast"
    if mbps >= 1:
        return "mid"
    return "slow"


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _build_china_set(data: dict) -> set[str]:
    """``china.json`` → set of keys with ``verdict == "reachable"``."""
    result = set()
    for key, entry in data.get("proxies", {}).items():
        if entry.get("verdict") == "reachable":
            result.add(key)
    return result


def _build_family_map(data: dict) -> dict[str, str]:
    """``exit_family.json`` → ``{key: family}``."""
    return {
        k: v.get("family", "")
        for k, v in data.get("proxies", {}).items()
        if v.get("family")
    }


def _build_streaming_map(data: dict) -> dict[str, dict]:
    """``streaming.json`` → ``{key: streaming_dict}``."""
    return {
        k: v
        for k, v in data.get("proxies", {}).items()
        if v
    }


def _build_ip_type_map(data: dict) -> dict[str, str]:
    """``ipinfo.json`` → ``{key: ip_type}``."""
    return {
        k: v.get("ip_type", "")
        for k, v in data.get("proxies", {}).items()
        if v.get("ip_type")
    }


def _build_rep_map(data: dict) -> dict[str, int]:
    """``reputation.json`` → ``{key: score}``."""
    return {
        k: v.get("score", 0)
        for k, v in data.get("proxies", {}).items()
        if v.get("score")
    }


def _insert_exit_region(line: str, exit_region: str) -> str:
    """Insert ``→<exit>`` right after the entry country code (idempotent)."""
    if not exit_region or "→" in line:
        return line
    m = EXIT_REGION_RE.match(line)
    if not m:
        return line
    return line[: m.end(1)] + "→" + exit_region + line[m.end(1) :]


def fill_and_classify(
    line: str,
    china_set: set[str],
    family_map: dict[str, str],
    streaming_map: dict[str, dict],
    rep_map: dict[str, int],
    ip_type_map: dict[str, str],
) -> str:
    """Fill missing suffixes and append classification tokens."""
    parsed = parse_line(line)
    if not parsed:
        return line

    key, _ip, _port, _cc, note = parsed
    out = line

    # --- suffix filling ---

    # CN token
    if key in china_set and not has_token(note, "CN"):
        out += "-CN"

    # V4 / V6 / DS
    family = family_map.get(key, "")
    if family:
        fam_token = {"ipv4": "V4", "ipv6": "V6", "dual": "DS"}.get(family, "")
        if fam_token and not has_token(note, fam_token) and not any(
            has_token(note, t) for t in FAMILY_TOKENS
        ):
            out += "-" + fam_token

    # streaming tokens
    st = streaming_map.get(key)
    if st:
        stoks = streaming_tokens(st)
        if stoks:
            for tok in stoks.split():
                if not has_token(note, tok):
                    out += "-" + tok

    # reputation score (only if not already present)
    rep_score = rep_map.get(key)
    if rep_score:
        score_str = str(rep_score)
        if not has_token(note, score_str) and score_str not in note:
            out += "-" + score_str

    # --- classification tokens ---

    # IP type
    ip_type = ip_type_map.get(key, "")
    if ip_type and ip_type in IP_TYPES and not has_token(note, ip_type):
        out += "-" + ip_type

    # speed tier
    tier = speed_tier(note)
    if tier != "unknown" and not has_token(note, tier):
        out += "-" + tier

    return out


def collect_txt_files(valid_dir: Path) -> list[Path]:
    """Collect all proxy txt files to annotate."""
    files: list[Path] = []
    for name in ("all.txt", "all_ltd.txt"):
        p = valid_dir / name
        if p.exists():
            files.append(p)
    for sub in ("countries", "sets"):
        d = valid_dir / sub
        if d.is_dir():
            files.extend(sorted(d.glob("*/all.txt")))
            files.extend(sorted(d.glob("*/ltd.txt")))
    ports_dir = valid_dir / "ports"
    if ports_dir.is_dir():
        files.extend(sorted(ports_dir.glob("*.txt")))
    return files


def annotate_files(
    files: list[Path],
    china_set: set[str],
    family_map: dict[str, str],
    streaming_map: dict[str, dict],
    rep_map: dict[str, int],
    ip_type_map: dict[str, str],
) -> int:
    """Annotate all files, return total lines changed."""
    total_changed = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        out_lines = []
        changed = 0
        for line in text.splitlines():
            if not line:
                continue
            new_line = fill_and_classify(
                line, china_set, family_map, streaming_map, rep_map, ip_type_map
            )
            if new_line != line:
                changed += 1
            out_lines.append(new_line)
        if changed:
            write_text_if_changed(path, "\n".join(out_lines) + "\n")
            total_changed += changed
            print(f"  {path.name}: {changed} lines updated")
    return total_changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--data-dir",
        type=Path,
        default=VALID_DIR.parent,
        help="data/ root (default: repo-root/data)",
    )
    args = ap.parse_args(argv)
    valid_dir = args.data_dir / "valid"

    # load data
    ipinfo = _load_json(valid_dir / "ipinfo.json")
    rep_data = _load_json(valid_dir / "reputation.json")
    china_data = _load_json(valid_dir / "china.json")
    family_data = _load_json(valid_dir / "exit_family.json")
    streaming_data = _load_json(valid_dir / "streaming.json")

    # build maps
    china_set = _build_china_set(china_data)
    family_map = _build_family_map(family_data)
    streaming_map = _build_streaming_map(streaming_data)
    rep_map = _build_rep_map(rep_data)
    ip_type_map = _build_ip_type_map(ipinfo)

    print(
        f"Maps: cn={len(china_set)} family={len(family_map)} "
        f"streaming={len(streaming_map)} rep={len(rep_map)} "
        f"ip_type={len(ip_type_map)}"
    )

    # collect and annotate
    files = collect_txt_files(valid_dir)
    if not files:
        print("No txt files found")
        return 0

    total = annotate_files(
        files, china_set, family_map, streaming_map, rep_map, ip_type_map
    )
    print(f"Done: {len(files)} files, {total} lines updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
