#!/usr/bin/env python3
"""私有检查包（PCB）加载器。

逆向/反爬细节已迁入私有仓库（本地 staging：仓库根 ``pcb/``，独立版本库，
不进公开 git）。本加载器：

- ``pcb/`` 存在 → 把 ``pcb/plugins`` 入 path，按名导入插件并校验
  ``INTERFACE_VERSION``，mismatch 即 fail-fast（防接口漂移）；manifest
  可单独校验，CI 可用 ``require_bundle`` 禁止静默降级。
- ``pcb/`` 缺失（fork/PR/公开 CI）→ ``bundle_available()`` 为 False，
  普通调用方走既有 fail-open；显式 ``require_bundle`` 则立即失败。
- ``PROXYIP_PCB_ROOT`` 可覆盖只读检出位置，默认仍是仓库根 ``pcb/``。

PCB 单向依赖公开基座（``common``、``ws_transport``）；公开代码除本加载器
外不得反向依赖 PCB 插件（防泄漏锁测试钉住此契约）。
"""

import json
import os
import sys
from pathlib import Path

INTERFACE_VERSION = 1

_BUNDLE_DIR: Path | None = None
_MANIFEST: dict | None = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def bundle_root() -> Path:
    """返回 PCB 根目录。

    默认取仓库根 ``pcb/``；``PROXYIP_PCB_ROOT`` 可指向任意只读检出，
    供单测、本地隔离副本与 CI 显式 pin 使用。测试可重置内部缓存。
    """
    global _BUNDLE_DIR
    if _BUNDLE_DIR is not None:
        return _BUNDLE_DIR
    override = os.environ.get("PROXYIP_PCB_ROOT", "").strip()
    _BUNDLE_DIR = (Path(override).expanduser() if override
                   else _repo_root() / "pcb")
    return _BUNDLE_DIR


def bundle_available() -> bool:
    """本地是否有可用的 PCB staging（``pcb/plugins`` 目录存在）。"""
    return (bundle_root() / "plugins").is_dir()


def bundle_dir() -> Path | None:
    """返回 PCB 根目录（不存在则 ``None``；兼容旧调用方）。"""
    root = bundle_root()
    return root if root.is_dir() else None


def require_bundle() -> Path:
    """要求 PCB 可用；缺失即 fail-fast（CI 专用，防静默降级）。"""
    root = bundle_root()
    if not (root / "plugins").is_dir():
        raise RuntimeError(f"PCB bundle required but missing (no {root / 'plugins'})")
    return root


def load_manifest() -> dict:
    """读取并校验 ``pcb/manifest.json``（进程内缓存）。"""
    global _MANIFEST
    if _MANIFEST is not None:
        return _MANIFEST
    root = require_bundle()
    path = root / "manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"PCB manifest unreadable: {path}") from exc
    version = data.get("interface_version")
    if version != INTERFACE_VERSION:
        raise RuntimeError(
            f"PCB manifest interface v{version} != loader v{INTERFACE_VERSION}"
        )
    _MANIFEST = data
    return data


def load_plugins(*names: str) -> dict:
    """批量载入插件；任一缺失/版本不符即 raise，不作部分降级。"""
    return {name: load_plugin(name) for name in names}


def load_plugin(name: str):
    """导入 ``pcb/plugins/<name>.py`` 并校验接口版本。

    缺 bundle 或版本不符时 raise（``ModuleNotFoundError`` /
    ``RuntimeError``），调用方自行 fail-open。模块名限单个 Python 标识符，
    杜绝点号属性访问或路径式注入。
    """
    if not isinstance(name, str) or not name.isidentifier():
        raise ValueError(f"invalid PCB plugin name: {name!r}")
    plugins = require_bundle() / "plugins"
    sp = str(plugins)
    if sp not in sys.path:
        sys.path.insert(0, sp)
    mod = __import__(name)
    ver = getattr(mod, "PCB_INTERFACE_VERSION", None)
    if ver != INTERFACE_VERSION:
        raise RuntimeError(
            f"PCB plugin {name} interface v{ver} != loader v{INTERFACE_VERSION}"
        )
    return mod
