#!/usr/bin/env python3
"""Export ``data/valid/all.json`` — structured machine-readable pool.

One JSON object per annotated proxy line:

    {"line":  "<original line>",
     "ip": ..., "port": ..., "flag": "🇺🇸", "cc": "US", "exit": "LAX",
     "latency_ms": 120, "speed_mbps": 0.44,
     "family": "V4|V6|DS|null", "cn": bool, "type": "DC|null",
     "tier": "fast|null", "rep": 72|null, "uptime7": 92|null}

Run in the stats workflow (single writer) before commit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import DATA_DIR, VALID_DIR, parse_line, read_json  # noqa: E402
from common import write_text_if_changed  # noqa: E402


def _note_tokens(note: str) -> list[str]:
    return [t for t in note.split("-") if t]


def line_to_obj(line: str) -> dict | None:
    parsed = parse_line(line)
    if not parsed:
        return None
    key, ip, port, cc, note = parsed
    toks = _note_tokens(note)

    def _int(tok: str) -> int | None:
        try:
            return int(tok.rstrip("ms"))
        except ValueError:
            return None

    latency = next((_int(t) for t in toks if t.endswith("ms")), None)
    speed = None
    for t in toks:
        if t.endswith("MB/s"):
            try:
                speed = float(t[:-4])
            except ValueError:
                pass
    family = next((t for t in toks if t in ("V4", "V6", "DS")), None)
    cn = any(t in ("CN", "CN4", "CN6", "CN46", "CNH") for t in toks)
    ip_type = next((t for t in toks if t in ("DC", "RES", "MOB", "PROXY")), None)
    tier = next((t for t in toks if t in ("fast", "mid", "slow")), None)
    rep = next((int(t) for t in toks if t.isdigit() and len(t) <= 3), None)
    uptime = next(
        (
            int(t[1:])
            for t in toks
            if len(t) > 1 and t[0] == "U" and t[1:].isdigit()
        ),
        None,
    )
    flag = ""
    m = note.split("→")
    head = line.split("#", 1)[1] if "#" in line else ""
    for ch in head:
        if ord(ch) > 0x1F000:
            flag += ch
        elif flag:
            break
    exit_cc = m[1].split("-")[0] if len(m) > 1 else None
    return {
        "key": key,
        "ip": ip,
        "port": int(port),
        "flag": flag,
        "cc": cc,
        "exit": exit_cc,
        "latency_ms": latency,
        "speed_mbps": speed,
        "family": family,
        "cn": cn,
        "type": ip_type,
        "tier": tier,
        "rep": rep,
        "uptime7": uptime,
        "line": line,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=DATA_DIR)
    args = ap.parse_args(argv)
    src = args.data_dir / "valid" / "all.txt"
    out = args.data_dir / "valid" / "all.json"
    if not src.exists():
        print(f"No {src}; skip")
        return 0
    objs = []
    for ln in src.read_text(encoding="utf-8").splitlines():
        o = line_to_obj(ln)
        if o:
            objs.append(o)
    write_text_if_changed(
        out, json.dumps(objs, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    print(f"Wrote {out} ({len(objs)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
