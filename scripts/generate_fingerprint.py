#!/usr/bin/env python3
"""Generate coherent browser fingerprints.

Each generated fingerprint is internally consistent: the user agent, platform,
screen resolution, timezone and language all belong to the same operating
system and locale, mimicking a real device profile.
"""

import argparse
import hashlib
import json
import random
import sys

UAS = {
    "windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    ],
    "macos": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ],
    "linux": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    ],
    "android": [
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    ],
    "ios": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.0.0 Mobile/15E148 Safari/604.1",
    ],
}

PLATFORM = {
    "windows": "Win32",
    "macos": "MacIntel",
    "linux": "Linux x86_64",
    "android": "Linux armv8l",
    "ios": "iPhone",
}

SCREENS = {
    "windows": [(1920, 1080), (2560, 1440), (1366, 768), (1536, 864), (3840, 2160)],
    "macos": [(1440, 900), (2560, 1440), (3024, 1964), (1728, 1117)],
    "linux": [(1920, 1080), (1366, 768), (2560, 1440)],
    "android": [(1080, 2400), (1440, 3120), (1080, 2340), (1170, 2532)],
    "ios": [(1170, 2532), (1290, 2796), (1080, 1920)],
}

TIMEZONES = {
    "windows": [
        "America/New_York", "America/Chicago", "America/Los_Angeles",
        "Europe/London", "Europe/Berlin", "Asia/Singapore",
        "Asia/Shanghai", "Australia/Sydney", "America/Sao_Paulo",
    ],
    "macos": [
        "America/New_York", "America/Los_Angeles", "Europe/London",
        "Europe/Paris", "Asia/Tokyo", "Asia/Shanghai",
    ],
    "linux": [
        "Europe/Berlin", "Europe/Moscow", "Asia/Shanghai",
        "America/New_York", "Asia/Singapore", "Europe/Amsterdam",
    ],
    "android": [
        "Asia/Singapore", "Asia/Kolkata", "Asia/Seoul",
        "Europe/London", "America/New_York", "Europe/Berlin",
    ],
    "ios": [
        "Asia/Tokyo", "America/Los_Angeles", "Europe/London",
        "Asia/Singapore", "Australia/Melbourne",
    ],
}

LANGS = {
    "windows": [["en-US", "en"], ["zh-CN", "zh"], ["de-DE", "de"], ["en-GB", "en"]],
    "macos": [["en-US", "en"], ["fr-FR", "fr"], ["ja-JP", "ja"], ["en-GB", "en"]],
    "linux": [["en-US", "en"], ["ru-RU", "ru"], ["de-DE", "de"], ["en-GB", "en"]],
    "android": [["en-US", "en"], ["hi-IN", "hi"], ["zh-CN", "zh"], ["ko-KR", "ko"]],
    "ios": [["en-US", "en"], ["ja-JP", "ja"], ["en-GB", "en"], ["zh-CN", "zh"]],
}

WEBGL = {
    "windows": [("ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002487) Direct3D11 vs_5_0 ps_5_0, D3D11)", "NVIDIA Corporation"),
                ("ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)", "Intel Inc.")],
    "macos": [("ANGLE (Apple, Apple M1, OpenGL 4.1)", "Apple"),
              ("ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics 645, OpenGL 4.1)", "Intel Inc.")],
    "linux": [("ANGLE (AMD, AMD Radeon(TM) Graphics (0x00001638) Direct3D11 vs_5_0 ps_5_0, D3D11)", "AMD"),
              ("WebKit WebGL", "Mesa/X.org")],
    "android": [("ANGLE (Qualcomm, Adreno (TM) 740 Direct3D11 vs_5_0 ps_5_0, D3D11)", "Qualcomm"),
                ("ANGLE (ARM, Mali-G78, OpenGL ES 3.2)", "ARM")],
    "ios": [("Apple GPU", "Apple"), ("Apple A16 GPU", "Apple")],
}

CONCURRENCY = {"windows": [4, 8, 12, 16], "macos": [4, 8, 10], "linux": [4, 8, 16], "android": [4, 8], "ios": [4, 6]}
MEMORY = {"windows": [4, 8, 8, 16], "macos": [8, 8, 16], "linux": [2, 4, 8, 16], "android": [4, 4, 8], "ios": [4, 4, 8]}
DPR = {"windows": [1.0, 1.25, 1.5], "macos": [1.0, 2.0], "linux": [1.0, 1.25], "android": [2.625, 2.75, 3.0], "ios": [3.0, 3.0, 2.0]}


def fingerprint(rng: random.Random) -> dict:
    os_ = rng.choice(list(UAS))
    ua = rng.choice(UAS[os_])
    w, h = rng.choice(SCREENS[os_])
    locale = rng.choice(LANGS[os_])
    gl_renderer, gl_vendor = rng.choice(WEBGL[os_])
    canvas_seed = f"{os_}:{w}x{h}:{ua}".encode()
    canvas_hash = hashlib.sha256(canvas_seed).hexdigest()[:16]

    fp = {
        "os": os_,
        "userAgent": ua,
        "platform": PLATFORM[os_],
        "language": locale[0],
        "languages": locale,
        "timezone": rng.choice(TIMEZONES[os_]),
        "screen": {"width": w, "height": h, "colorDepth": 24, "devicePixelRatio": rng.choice(DPR[os_])},
        "hardwareConcurrency": rng.choice(CONCURRENCY[os_]),
        "deviceMemory": rng.choice(MEMORY[os_]),
        "webgl": {"renderer": gl_renderer, "vendor": gl_vendor},
        "canvasHash": canvas_hash,
    }
    return fp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of fingerprints to generate")
    parser.add_argument("-s", "--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)
    fps = [fingerprint(rng) for _ in range(args.count)]
    for fp in fps:
        if args.pretty:
            print(json.dumps(fp, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(fp, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
