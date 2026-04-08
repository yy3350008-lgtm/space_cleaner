"""交互界面模块（V2，面向小白）。"""

from __future__ import annotations

import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
from typing import Callable
import string
import winreg

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn
from rich.progress import Progress
from rich.progress import SpinnerColumn
from rich.progress import TextColumn
from rich.table import Table

console = Console()

SAFETY_BOUNDARY_NOTICE = (
    "【安全边界声明】\n"
    "本工具默认不主动删除任何文件。\n"
    "所有操作只做压缩与隔离，原文件保留副本。\n"
    "删除动作必须由你手动确认，不会自动执行。"
)

MAIN_MENU_OPTIONS = [
    "👉 一键安全清理（保守模式，扫描下载与桌面）",
    "👉 自定义兼推荐清理（标准模式，所有磁盘可选）",
    "👉 自主加入隔离箱（手动选文件）",
    "👉 极限释放（压缩后清理隔离副本，需三重确认）",
    "👉 查看物理隔离箱（系统文件夹）",
    "👉 查看『隔离箱』与历史恢复",
    "👉 手动清理到期隔离副本",
    "👉 手动清空隔离箱（立即执行）",
    "👉 退出",
]

SMART_SCAN_HINT = (
    "[说明] 请选择一个文件夹，助手将自动分析该目录及其子目录下所有的安装包与临时文件。"
)

def show_welcome_panel() -> None:
    msg = (
        "👋 欢迎使用释放空间助手！我们不是暴力的『文件粉碎机』，\n"
        "而是你的『文件周转站』。\n"
        "我们会先把疑似垃圾的安装包打包搬到隔离区，\n"
        "等您确认它们确实没用后，再彻底丢掉。\n"
        "安全第一，随时可还原！"
    )
    console.print(Panel.fit(msg, title="释放空间助手 V2", border_style="cyan"))
    console.print(Panel.fit(SAFETY_BOUNDARY_NOTICE, title="运行逻辑", border_style="green"))


def show_before_action_notice(file_count: int) -> None:
    console.print(
        f"[cyan]即将对 {file_count} 个文件执行压缩/隔离，原文件不会被自动删除。[/cyan]"
    )


def show_after_action_notice() -> None:
    console.print("[cyan]操作完成。如需删除，请进入『手动清理』菜单单独确认。[/cyan]")


def show_ctrl_c_hint(step_name: str = "当前步骤") -> None:
    """统一提示：Ctrl+C 可中止并返回上一步。"""
    console.print(f"[blue]提示：在{step_name}按 Ctrl+C 可中止并返回上一步。[/blue]")


def ask_delete_expired(expired_count: int, days: int) -> bool:
    """提示是否清理到期隔离副本。"""
    if expired_count <= 0:
        return False
    show_ctrl_c_hint("清理确认")
    return bool(
        questionary.confirm(
            f"⏰ 提醒：您的『隔离箱』里有 {expired_count} 个文件已经存放超过 {days} 天了，"
            "目前电脑运行一切正常。是否现在把它们彻底扔进回收站？",
            default=False,
        ).ask()
    )


def render_scan_summary(scan_result: dict) -> None:
    candidates = scan_result.get("candidates", [])
    panel = scan_result.get("space_panel", {})

    table = Table(title="扫描结果")
    table.add_column("序号", justify="right")
    table.add_column("文件名")
    table.add_column("物理位置")
    table.add_column("大小", justify="right")
    table.add_column("命中规则")

    for idx, e in enumerate(candidates[:20], start=1):
        p = Path(getattr(e, "path", ""))
        drive = p.drive.upper() if p.drive else "未知盘"
        location = f"{drive}盘" if drive else "未知盘"
        size_mb = getattr(e, "size_bytes", 0) / 1024 / 1024
        table.add_row(str(idx), p.name, location, f"{size_mb:.2f} MB", str(getattr(e, "rule_matched", "")))

    console.print(table)
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"立刻腾出空间: {panel.get('immediate_free_bytes', 0) / 1024 / 1024:.2f} MB",
                    f"预计压缩节省: {panel.get('after_delete_quarantine_bytes', 0) / 1024 / 1024:.2f} MB",
                    f"隔离箱历史占用: {panel.get('current_quarantine_bytes', 0) / 1024 / 1024:.2f} MB",
                ]
            ),
            title="空间收益",
            border_style="green",
        )
    )


def run_scanner_with_progress(scan_func: Callable, *args, **kwargs):
    """在线程中执行扫描，主线程刷新进度，避免界面假死。"""
    result_box = {"result": None, "done": False, "error": None}
    scanned_count = {"value": 0}

    def _cb(count: int) -> None:
        scanned_count["value"] = count

    kwargs["progress_callback"] = _cb

    def _worker() -> None:
        try:
            result_box["result"] = scan_func(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - 线程内异常转发
            result_box["error"] = exc
        finally:
            result_box["done"] = True

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    with Progress(
        SpinnerColumn(),
        TextColumn("🔍 正在翻箱倒柜寻找陈年安装包..."),
        BarColumn(),
        TextColumn("已扫描 {task.completed} 文件"),
        console=console,
    ) as progress:
        task_id = progress.add_task("scan", total=None)
        last = 0
        while not result_box["done"]:
            current = scanned_count["value"]
            delta = max(current - last, 0)
            if delta:
                progress.update(task_id, advance=delta)
                last = current
            t.join(timeout=0.05)

        current = scanned_count["value"]
        delta = max(current - last, 0)
        if delta:
            progress.update(task_id, advance=delta)

    if result_box["error"] is not None:
        raise result_box["error"]
    return result_box["result"]


def ask_main_menu() -> str:
    """展示主菜单并返回选择项。"""
    show_ctrl_c_hint("主菜单")
    return questionary.select("请选择操作：", choices=MAIN_MENU_OPTIONS).ask() or MAIN_MENU_OPTIONS[-1]


def _pick_files_and_infer_directories(initial_dir: str | None = None) -> list[str]:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    selected = filedialog.askopenfilenames(
        title="请选择目录内任意文件（可多选，窗口会显示所有文件）",
        initialdir=initial_dir or str(Path.home()),
    )
    root.destroy()
    dirs: list[str] = []
    seen: set[str] = set()
    for file_path in selected:
        parent = str(Path(file_path).parent)
        key = parent.lower()
        if key in seen:
            continue
        seen.add(key)
        dirs.append(parent)
    return dirs


def ask_custom_targets(default_targets: list[str], auto_targets: list[str] | None = None) -> list[str]:
    """仅选择一个目录并立即处理，避免“先添加再批量执行”的冗余操作。"""
    auto_targets = auto_targets or []
    recommended: list[str] = []
    seen: set[str] = set()
    for p in list(default_targets) + list(auto_targets):
        norm = os.path.expandvars(str(p)).strip()
        if not norm:
            continue
        key = norm.lower()
        if key in seen:
            continue
        seen.add(key)
        recommended.append(norm)

    console.print("[cyan][助手说明] 正在深度分析该目录。由于包含子目录，这可能需要一点时间，请稍候。[/cyan]")
    initial_dir = recommended[0] if recommended else str(Path.home())
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    selected_dir = filedialog.askdirectory(
        title="请选择一个文件夹，助手会自动分析子目录",
        initialdir=initial_dir,
    )
    root.destroy()
    if selected_dir:
        return [str(selected_dir)]
    if recommended:
        console.print("[yellow]未选择目录，已自动使用推荐目录。[/yellow]")
        return [recommended[0]]
    return []


def _get_available_drives() -> list[str]:
    """获取所有可用磁盘（仅 Windows）。"""
    if os.name != 'nt':
        return [str(Path.home())]
    
    drives = []
    try:
        # 首先尝试通过逻辑驱动器检测
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        if drives:
            return drives
    except Exception:
        pass
    
    # 如果失败，返回默认的 C 盘
    return ["C:\\"]


def ask_select_drive() -> str:
    """让用户选择要浏览的磁盘。"""
    show_ctrl_c_hint("磁盘选择")
    drives = _get_available_drives()
    if len(drives) == 1:
        return drives[0]
    
    choices = [questionary.Choice(title=f"💾 {drive}", value=drive) for drive in sorted(drives)]
    selected = questionary.select("请选择要浏览的磁盘：", choices=choices).ask()
    return selected or drives[0]


def _fmt_bytes(num_bytes: int) -> str:
    size = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.2f} {units[idx]}"


def browse_directory_action(start_dir: str | None = None) -> dict:
    """目录浏览器：目录仅导航，文件才允许加入隔离候选。"""
    current = Path(start_dir or Path.home()).expanduser()
    
    selected_files: list[str] = []

    while True:
        if not current.exists() or not current.is_dir():
            current = Path.home()

        dirs: list[Path] = []
        files: list[Path] = []
        try:
            with os.scandir(str(current)) as it:
                for de in it:
                    p = Path(current, de.name)
                    try:
                        if de.is_dir(follow_symlinks=False):
                            dirs.append(p)
                        elif de.is_file(follow_symlinks=False):
                            files.append(p)
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            console.print("[yellow]当前目录无访问权限，已返回上一级。[/yellow]")
            current = current.parent if current.parent != current else Path.home()
            continue

        dirs.sort(key=lambda p: p.name.lower())
        files.sort(key=lambda p: p.name.lower())

        options: list[questionary.Choice] = []
        options.append(questionary.Choice(title=f"📂 当前目录：{current}", value={"kind": "noop"}, disabled="浏览模式"))
        options.append(questionary.Choice(title="💽 切换磁盘", value={"kind": "switch_drive"}))
        options.append(questionary.Choice(title="📁 进入上级目录 ..", value={"kind": "up"}))

        for d in dirs[:120]:
            options.append(questionary.Choice(title=f"📁 [目录] {d.name}", value={"kind": "enter_dir", "path": str(d)}))

        for f in files[:240]:
            marker = "✅" if str(f) in selected_files else "⬜"
            title = f"{marker} 📄 [文件] {f.name} ({_fmt_bytes(f.stat().st_size)})"
            options.append(questionary.Choice(title=title, value={"kind": "toggle_file", "path": str(f)}))

        options.append(questionary.Separator("--- 操作 ---"))
        options.append(questionary.Choice(title=f"✅ 处理已选文件（{len(selected_files)}）", value={"kind": "process_selected"}))
        options.append(
            questionary.Choice(
                title="🚀 智能扫描并建议压缩",
                value={"kind": "smart_scan_recommend", "path": str(current)},
            )
        )
        options.append(questionary.Choice(title="↩ 返回主菜单", value={"kind": "cancel"}))

        show_ctrl_c_hint("目录浏览")
        try:
            picked = questionary.select("请选择操作（目录只导航，文件才加入隔离候选）：", choices=options).ask()
        except KeyboardInterrupt:
            console.print("[yellow]已中止当前目录操作，返回上一步。[/yellow]")
            return {"action": "cancel", "current_dir": str(current), "selected_files": selected_files}
        if not picked:
            return {"action": "cancel", "current_dir": str(current), "selected_files": selected_files}

        kind = picked.get("kind")
        if kind == "noop":
            continue
        if kind == "switch_drive":
            current = Path(ask_select_drive())
            continue
        if kind == "up":
            current = current.parent if current.parent != current else current
            continue
        if kind == "enter_dir":
            current = Path(str(picked.get("path", current)))
            continue
        if kind == "toggle_file":
            file_path = str(picked.get("path", ""))
            if file_path:
                if file_path in selected_files:
                    selected_files.remove(file_path)
                else:
                    selected_files.append(file_path)
            continue
        if kind == "process_selected":
            if not selected_files:
                console.print("[yellow]请先选择至少一个文件。[/yellow]")
                continue
            return {"action": "manual_files", "current_dir": str(current), "selected_files": list(selected_files)}
        if kind == "smart_scan_recommend":
            return {"action": "smart_scan_recommend", "current_dir": str(current), "selected_files": list(selected_files)}
        if kind == "cancel":
            return {"action": "cancel", "current_dir": str(current), "selected_files": list(selected_files)}


def show_extreme_release_intro() -> None:
    """进入极限释放前，先给出大白话风险说明。"""
    console.print(
        Panel.fit(
            "🚨 什么是极限释放？这是最后一步。当您的文件已安全移入隔离箱并完成 ZIP 备份后，"
            "此操作将彻底清理隔离箱副本以释放物理空间。",
            title="极限释放说明",
            border_style="red",
        )
    )


def ask_continue_next_directory() -> bool:
    """完成一个目录后，是否继续选择下一个目录。"""
    show_ctrl_c_hint("继续选择确认")
    return bool(questionary.confirm("要继续选择下一个目录吗？", default=False).ask())


def ask_pick_files_for_quarantine(initial_dir: str | None = None) -> list[str]:
    """手动选择要加入隔离箱的文件（多选）。"""
    show_ctrl_c_hint("文件选择")
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    selected = filedialog.askopenfilenames(
        title="请选择要加入隔离箱的文件（可多选）",
        initialdir=initial_dir or str(Path.home()),
    )
    root.destroy()
    return [str(p) for p in selected]


def ask_confirm_manual_purge(file_count: int, total_size_bytes: int) -> bool:
    """手动清空隔离箱前确认。"""
    show_ctrl_c_hint("清空隔离箱确认")
    size_mb = total_size_bytes / 1024 / 1024
    return bool(
        questionary.confirm(
            f"将删除隔离箱内 {file_count} 个文件（约 {size_mb:.2f} MB），是否继续？",
            default=False,
        ).ask()
    )


def open_quarantine_folder(q_dir: str) -> bool:
    """物理开箱：直接在系统资源管理器打开隔离目录。"""
    path = os.path.expandvars(str(q_dir))
    try:
        os.makedirs(path, exist_ok=True)
        if hasattr(os, "startfile"):
            os.startfile(path)  # type: ignore[attr-defined]
            return True

        # 非 Windows 兜底。
        subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


def ask_move_confirm(file_count: int) -> bool:
    """搬运确认。"""
    show_ctrl_c_hint("压缩/隔离确认")
    return bool(
        questionary.confirm(
            f"📦 找到了 {file_count} 个文件。我们要把它们装进『隔离箱』并打个压缩包吗？"
            "（文件还在您的电脑里，随时可以反悔）",
            default=True,
        ).ask()
    )


def show_extreme_release_checks(plan: dict) -> None:
    """展示极限释放前的十项检查结果。"""
    checks = plan.get("checks", [])
    table = Table(title="极限释放 - 十项安全检查")
    table.add_column("序号", justify="right")
    table.add_column("检查项")
    table.add_column("结果", justify="center")
    table.add_column("说明")

    for idx, item in enumerate(checks, start=1):
        ok = bool(item.get("ok", False))
        result = "通过" if ok else "未通过"
        style = "green" if ok else "red"
        table.add_row(str(idx), str(item.get("name", "")), f"[{style}]{result}[/{style}]", str(item.get("detail", "")))

    console.print(table)
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"可清理隔离副本: {int(plan.get('candidate_count', 0))} 个",
                    f"预计释放隔离空间: {int(plan.get('candidate_bytes', 0)) / 1024 / 1024:.2f} MB",
                    f"阻断项: {len(plan.get('blockers', []))} 个",
                    f"警告项: {len(plan.get('warnings', []))} 个",
                ]
            ),
            title="极限释放评估",
            border_style="magenta",
        )
    )


def ask_extreme_release_confirm(plan: dict) -> bool:
    """三重人工确认：阅读风险、输入口令、最终确认。"""
    if plan.get("blockers"):
        return False

    show_ctrl_c_hint("极限释放确认")

    step1 = questionary.confirm(
        "⚠️ 这会在压缩校验通过后清理隔离副本。您已阅读十项检查并理解风险吗？",
        default=False,
    ).ask()
    if not step1:
        return False

    phrase = questionary.text("请输入确认口令【极限释放】以继续：").ask() or ""
    if phrase.strip() != "极限释放":
        console.print("[yellow]口令不匹配，已取消本次极限释放。[/yellow]")
        return False

    count = int(plan.get("candidate_count", 0))
    size_mb = int(plan.get("candidate_bytes", 0)) / 1024 / 1024
    step3 = questionary.confirm(
        f"最后确认：将清理 {count} 个隔离副本（约 {size_mb:.2f} MB），并写入清理报告，是否执行？",
        default=False,
    ).ask()
    return bool(step3)


def show_history_panel(total_files: int, total_size_bytes: int) -> None:
    console.print(
        Panel.fit(
            f"隔离箱当前共有 {total_files} 个文件\n占用 {total_size_bytes / 1024 / 1024:.2f} MB",
            title="隔离箱概览",
            border_style="yellow",
        )
    )
