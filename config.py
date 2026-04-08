"""配置加载模块（V2）。"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    import winreg

from rich.console import Console

console = Console()

DEFAULT_CONFIG: dict[str, Any] = {
    "scan_targets": [
        "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Desktop",
    ],
    "quarantine_dir": "%USERPROFILE%\\SpaceCleaner_Quarantine",
    "exclude_dirs": [
        "%USERPROFILE%\\Documents",
        "%USERPROFILE%\\Pictures",
        "%USERPROFILE%\\Videos",
    ],
    "exclude_extensions": [
        ".py",
        ".docx",
        ".xlsx",
        ".pdf",
        ".txt",
    ],
    "min_file_size_kb": 500,
    "quarantine_cleanup_after_days": 3,
    "report_dir": "",
    "rule_source": "builtin",
    "cleanup_mode": "conservative",
    "log_retention_days": 3,
    "state_dir": "",
    "quarantine_cleanup_after_zip_days": 3,
}


def get_wechat_path() -> str | None:
    """自动嗅探微信文件保存路径（Windows 注册表）。"""
    if sys.platform != "win32":
        return None

    candidates: list[Path] = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\WeChat", 0, winreg.KEY_READ)
        raw_path, _ = winreg.QueryValueEx(key, "FileSavePath")
        winreg.CloseKey(key)

        if str(raw_path).strip() == "MyDocuments":
            candidates.append(Path.home() / "Documents" / "WeChat Files")
        else:
            base = Path(str(raw_path))
            candidates.append(base / "WeChat Files")
            candidates.append(base)
    except OSError:
        pass

    candidates.append(Path.home() / "Documents" / "WeChat Files")

    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[0]) if candidates else None


def get_qq_path() -> str | None:
    """自动嗅探 QQ 文件保存路径。"""
    if sys.platform != "win32":
        return None

    candidates: list[Path] = []
    for sub_key in [r"Software\Tencent\QQ", r"Software\Tencent\TIM"]:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key, 0, winreg.KEY_READ)
            for value_name in ["FileSavePath", "PersonalPath"]:
                try:
                    raw_path, _ = winreg.QueryValueEx(key, value_name)
                    if str(raw_path).strip():
                        candidates.append(Path(str(raw_path)))
                except OSError:
                    continue
            winreg.CloseKey(key)
        except OSError:
            continue

    candidates.append(Path.home() / "Documents" / "Tencent Files")

    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[0]) if candidates else None


def _inject_auto_targets(cfg: dict[str, Any]) -> dict[str, Any]:
    """自动补充推荐扫描目录，避免新手手工输入路径。"""
    merged = dict(cfg)
    existing = [str(p) for p in merged.get("scan_targets", []) if str(p).strip()]

    auto_targets: list[str] = []
    wechat_path = get_wechat_path()
    if wechat_path:
        auto_targets.append(wechat_path)
        auto_targets.append(str(Path(wechat_path) / "FileStorage"))

    qq_path = get_qq_path()
    if qq_path:
        auto_targets.append(qq_path)

    # 去重并保持顺序。
    seen: set[str] = set()
    final_targets: list[str] = []
    for p in existing + auto_targets:
        expanded = os.path.expandvars(str(p)).strip()
        if not expanded:
            continue
        key = expanded.lower()
        if key in seen:
            continue
        seen.add(key)
        final_targets.append(expanded)

    merged["scan_targets"] = final_targets
    merged["auto_scan_targets"] = [os.path.expandvars(str(p)) for p in auto_targets]
    return merged


def _expand_paths(cfg: dict[str, Any]) -> dict[str, Any]:
    expanded = dict(cfg)
    expanded["scan_targets"] = [os.path.expandvars(str(p)) for p in cfg.get("scan_targets", [])]
    expanded["auto_scan_targets"] = [os.path.expandvars(str(p)) for p in cfg.get("auto_scan_targets", [])]
    expanded["exclude_dirs"] = [os.path.expandvars(str(p)) for p in cfg.get("exclude_dirs", [])]
    expanded["quarantine_dir"] = os.path.expandvars(str(cfg.get("quarantine_dir", "")))
    report_dir = str(cfg.get("report_dir", "")).strip()
    expanded["report_dir"] = os.path.expandvars(report_dir) if report_dir else ""
    state_dir = str(cfg.get("state_dir", "")).strip()
    expanded["state_dir"] = os.path.expandvars(state_dir) if state_dir else ""
    return expanded


def get_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """加载配置；若配置缺失或损坏则自动回退默认值。"""
    base_dir = Path(__file__).resolve().parent
    cfg_path = Path(config_path) if config_path else base_dir / "config.json"

    try:
        with cfg_path.open("r", encoding="utf-8-sig") as f:
            loaded = json.load(f)
        merged = {**DEFAULT_CONFIG, **loaded}
        merged = _inject_auto_targets(merged)
        return _expand_paths(merged)
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        console.print(f"[bold red]配置文件加载失败，已使用内置默认配置：{exc}[/bold red]")
        merged = _inject_auto_targets(DEFAULT_CONFIG)
        return _expand_paths(merged)


def save_config(config: dict[str, Any], config_path: str | Path | None = None) -> Path:
    """保存配置到磁盘（UTF-8-SIG，兼容记事本）。"""
    base_dir = Path(__file__).resolve().parent
    cfg_path = Path(config_path) if config_path else base_dir / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with cfg_path.open("w", encoding="utf-8-sig") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    return cfg_path
