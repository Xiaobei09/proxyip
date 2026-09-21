#!/usr/bin/env python3
"""私有检查包（PCB）加载器。

逆向/反爬细节已迁入私有仓库（本地 staging：仓库根 ``pcb/``，独立版本库，
不进公开 git）。本加载器：

- ``pcb/`` 存在 → 把 ``pcb/plugins`` 入 path，按名导入插件并校验
  ``INTERFACE_VERSION``， mismatch 即 fail-fast（防接口漂移）。
- ``pcb/`` 缺失（fork/PR/公开 CI）→ ``bundle_available()`` 为 False，
  调用方必须走 opt-in 跳过（已有 fail-open 语义），不得崩溃。

PCB 单向依赖公开基座（``common``、``ws_transport``）；公开代码除本加载器
外不得反向依赖 PCB 插件（防泄漏锁测试钉住此契约）。
"""

import sys
from pathlib import Path

INTERFACE_VERSION = 1

_BUNDLE_DIR: Path | None = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def bundle_available() -> bool:
    """本地是否有可用的 PCB staging（``pcb/plugins`` 目录存在）。"""
    return (_repo_root() / "pcb" / "plugins").is_dir()


def bundle_dir() -> Path | None:
    """返回 PCB 根目录（不存在则 ``None``）。"""
    if _BUNDLE_DIR is not None:
        return _BUNDLE_DIR
    return None


def load_plugin(name: str):
    """导入 ``pcb/plugins/<name>.py`` 并校验接口版本。

    缺 bundle 或版本不符时 raise（``ModuleNotFoundError`` /
    ``RuntimeError``），调用方自行 fail-open。
    """
    root = _repo_root()
    plugins = root / "pcb" / "plugins"
    if not plugins.is_dir():
        raise ModuleNotFoundError(f"PCB bundle missing (no {plugins})")
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
