"""释放空间助手 V2 入口。"""

from __future__ import annotations

import ctypes
import io
import json
import logging
import sys
import uuid
from datetime import datetime
from pathlib import Path

import questionary
from rich.console import Console

from config import get_config
from config import save_config
from recovery import load_manifest_entries
from recovery import list_sessions
from recovery import restore_file
from reporter import write_manifest
from reporter import write_preview_report
from safety import check_expired_quarantine
from safety import check_resume
from safety import create_zip_archive
from safety import build_extreme_release_plan
from safety import assert_no_deleted_entries
from safety import delete_quarantine_files
from safety import mark_in_progress_as_failed
from safety import move_to_quarantine
from safety import purge_quarantine_now
from safety import pre_flight_check
from scanner import compute_fingerprint
from scanner import make_long_path
from scanner import scan_directory
from scanner import scan_recommended_directory
from ui import ask_main_menu
from ui import ask_confirm_manual_purge
from ui import ask_select_drive
from ui import ask_custom_targets
from ui import browse_directory_action
from ui import ask_continue_next_directory
from ui import ask_delete_expired
from ui import ask_extreme_release_confirm
from ui import ask_move_confirm
from ui import ask_pick_files_for_quarantine
from ui import open_quarantine_folder
from ui import run_scanner_with_progress
from ui import render_scan_summary
from ui import show_ctrl_c_hint
from ui import show_after_action_notice
from ui import show_before_action_notice
from ui import show_extreme_release_checks
from ui import show_extreme_release_intro
from ui import show_history_panel
from ui import show_welcome_panel

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console()
_SINGLE_INSTANCE_MUTEX = None


def _ensure_single_instance() -> bool:
    """Windows 单实例保护，防止并发破坏状态机。"""
    global _SINGLE_INSTANCE_MUTEX
    if sys.platform != "win32":
        return True
    try:
        _SINGLE_INSTANCE_MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\SpaceCleaner_SingleInstance")
        already_exists = ctypes.windll.kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS
        return not already_exists
    except Exception:
        # 无法创建互斥量时不阻断主流程，但继续记录到日志。
        return True


def _setup_logger(base_dir: Path) -> logging.Logger:
    logger = logging.getLogger("space_cleaner")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger

    fh = logging.FileHandler(base_dir / "space_cleaner.log", encoding="utf-8-sig")
    sh = logging.StreamHandler()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh.setFormatter(formatter)
    sh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def _load_rules(base_dir: Path) -> dict:
    rules_file = base_dir / "rules" / "builtin_rules.json"
    with rules_file.open("r", encoding="utf-8") as f:
        return json.load(f)


def _merge_scan_results(results: list[dict]) -> dict:
    merged = {
        "candidates": [],
        "skipped_permission": [],
        "skipped_locked": [],
        "skipped_hardlink": [],
        "skipped_exclude": [],
        "total_scanned": 0,
        "estimated_free_bytes": 0,
    }
    for r in results:
        merged["candidates"].extend(r.get("candidates", []))
        merged["skipped_permission"].extend(r.get("skipped_permission", []))
        merged["skipped_locked"].extend(r.get("skipped_locked", []))
        merged["skipped_hardlink"].extend(r.get("skipped_hardlink", []))
        merged["skipped_exclude"].extend(r.get("skipped_exclude", []))
        merged["total_scanned"] += int(r.get("total_scanned", 0))
        merged["estimated_free_bytes"] += int(r.get("estimated_free_bytes", 0))

    merged["skipped_permission"] = sorted(set(merged["skipped_permission"]))
    merged["skipped_locked"] = sorted(set(merged["skipped_locked"]))
    merged["skipped_hardlink"] = sorted(set(merged["skipped_hardlink"]))
    merged["skipped_exclude"] = sorted(set(merged["skipped_exclude"]))
    panel = {
        "immediate_free_bytes": sum(int(r.get("space_panel", {}).get("immediate_free_bytes", 0)) for r in results),
        "after_delete_quarantine_bytes": sum(
            int(r.get("space_panel", {}).get("after_delete_quarantine_bytes", 0)) for r in results
        ),
        "current_quarantine_bytes": max(
            [int(r.get("space_panel", {}).get("current_quarantine_bytes", 0)) for r in results] or [0]
        ),
    }
    merged["space_panel"] = panel
    return merged


def _run_scan_flow(
    config: dict,
    rules: dict,
    scan_targets: list[str],
    report_dir: Path,
    state_file: Path,
    cleanup_mode: str,
    extreme_release: bool = False,
    scan_func=scan_directory,
) -> None:
    local_config = dict(config)
    local_config["cleanup_mode"] = cleanup_mode

    results = []
    for t in scan_targets:
        try:
            results.append(run_scanner_with_progress(scan_func, t, rules, local_config))
        except Exception as exc:
            console.print(f"[yellow]部分路径跳过：{t}（{exc}）[/yellow]")

    if not results:
        console.print("[yellow]部分路径跳过：本次没有可用扫描结果。[/yellow]")
        return

    merged = _merge_scan_results(results)
    render_scan_summary(merged)

    preview_path = report_dir / f"preview_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_file = write_preview_report(merged, str(preview_path))
    console.print(f"[green]预览报告已生成：{report_file}[/green]")

    candidates = merged.get("candidates", [])
    if not candidates:
        console.print("[yellow]这次没有找到可疑文件，您的电脑很干净。[/yellow]")
        return

    show_before_action_notice(len(candidates))

    if not ask_move_confirm(len(candidates)):
        console.print("[yellow]已取消，本次不会改动任何文件。[/yellow]")
        return

    check_result = pre_flight_check(candidates, local_config["quarantine_dir"])
    if not check_result.get("ok"):
        if check_result.get("reason") == "insufficient_space":
            console.print("[red]空间不够：隔离区分区剩余空间不足，已自动中止。[/red]")
        else:
            console.print("[red]安全预检未通过，已自动中止。[/red]")
        return

    if check_result.get("locked_skipped"):
        locked_paths = [str(p).lower() for p in check_result["locked_skipped"]]
        has_im_lock = any(("wechat" in p) or ("qq" in p) or ("filestorage" in p) for p in locked_paths)
        if has_im_lock:
            console.print("[yellow]该文件正在被微信使用，已为您自动跳过，无需担心。[/yellow]")
        console.print(f"[yellow]有 {len(check_result['locked_skipped'])} 个文件正在被占用，已自动跳过。[/yellow]")

    strategy = check_result.get("move_strategy", "rename")
    selected = check_result.get("entries", candidates)

    success_entries = []
    for e in selected:
        ok = move_to_quarantine(e, local_config["quarantine_dir"], strategy, str(state_file))
        if ok:
            success_entries.append(e)

    if not success_entries:
        console.print("[red]没有文件成功进入隔离区。[/red]")
        return

    zip_result = create_zip_archive(
        session_id=state_file.stem,
        state_file_path=str(state_file),
        output_dir=str(report_dir),
        cleanup_after_days=int(local_config.get("quarantine_cleanup_after_zip_days", 3)),
    )
    if zip_result.get("ok"):
        console.print(f"[green]归档完成：{zip_result.get('archive_path','')}[/green]")
        if zip_result.get("skipped_large"):
            console.print(
                f"[yellow]{len(zip_result['skipped_large'])} 个超大文件仅隔离未压缩（>3.9GB）。[/yellow]"
            )
    else:
        console.print(f"[red]归档失败：{zip_result.get('reason','unknown')}[/red]")

    with state_file.open("r", encoding="utf-8-sig") as f:
        state = json.load(f)

    manifest_path = write_manifest(state, str(report_dir))
    console.print(f"[green]操作清单已生成：{manifest_path}[/green]")
    show_after_action_notice()

    if not extreme_release:
        return

    if not zip_result.get("ok"):
        console.print("[yellow]极限释放已跳过：归档未成功，保护策略阻止执行。[/yellow]")
        return

    archived_count = sum(1 for item in state.get("entries", []) if item.get("status") == "archived")
    if archived_count <= 0:
        console.print("[yellow]极限释放已跳过：还没有完成归档的文件。[/yellow]")
        return

    plan = build_extreme_release_plan(str(state_file), max_state_age_seconds=1800)
    show_extreme_release_checks(plan)

    if plan.get("blockers"):
        console.print("[red]极限释放已阻断：存在未通过的关键检查项。[/red]")
        return

    if not ask_extreme_release_confirm(plan):
        console.print("[yellow]已取消极限释放，隔离副本将继续保留用于恢复。[/yellow]")
        return

    extreme_result = delete_quarantine_files(
        session_id=state_file.stem,
        state_file_path=str(state_file),
        entry_ids=list(plan.get("candidate_entry_ids", [])),
    )
    console.print(
        f"[green]极限释放完成：成功 {len(extreme_result.get('deleted', []))}，"
        f"失败 {len(extreme_result.get('failed', []))}。[/green]"
    )
    report_path = str(extreme_result.get("report_path", "")).strip()
    if report_path:
        console.print(f"[green]清理报告：{report_path}[/green]")


def _run_manual_quarantine_flow(config: dict, report_dir: Path, state_file: Path) -> None:
    _run_manual_quarantine_flow_with_files(config, report_dir, state_file, ask_pick_files_for_quarantine())


def _run_manual_quarantine_flow_with_files(
    config: dict,
    report_dir: Path,
    state_file: Path,
    picked: list[str],
) -> None:
    if not picked:
        console.print("[yellow]未选择文件，已返回。[/yellow]")
        return

    entries: list[dict] = []
    for p in picked:
        src = Path(p)
        if not src.exists() or not src.is_file():
            continue
        try:
            entries.append(
                {
                    "path": str(src),
                    "long_path": make_long_path(str(src)),
                    "size_bytes": src.stat().st_size,
                    "fingerprint": compute_fingerprint(str(src)),
                    "rule_matched": "manual_selected",
                    "is_duplicate": False,
                    "companion_files": [],
                    "skip_zip": src.stat().st_size > int(3.9 * 1024 * 1024 * 1024),
                }
            )
        except (PermissionError, OSError):
            continue

    if not entries:
        console.print("[yellow]没有可处理文件（可能无权限或文件不存在）。[/yellow]")
        return

    show_before_action_notice(len(entries))

    check_result = pre_flight_check(entries, config["quarantine_dir"])
    if not check_result.get("ok"):
        console.print("[red]安全预检未通过，已中止。[/red]")
        return

    strategy = check_result.get("move_strategy", "rename")
    selected = check_result.get("entries", entries)

    success_entries = []
    for e in selected:
        ok = move_to_quarantine(e, config["quarantine_dir"], strategy, str(state_file))
        if ok:
            success_entries.append(e)

    if not success_entries:
        console.print("[red]未成功加入隔离箱。[/red]")
        return

    zip_result = create_zip_archive(
        session_id=state_file.stem,
        state_file_path=str(state_file),
        output_dir=str(report_dir),
        cleanup_after_days=int(config.get("quarantine_cleanup_after_zip_days", 3)),
    )
    if zip_result.get("ok"):
        console.print(f"[green]已加入隔离箱并归档：{zip_result.get('archive_path','')}[/green]")
    else:
        console.print(f"[red]归档失败：{zip_result.get('reason','unknown')}[/red]")

    with state_file.open("r", encoding="utf-8-sig") as f:
        state = json.load(f)
    manifest_path = write_manifest(state, str(report_dir))
    console.print(f"[green]操作清单已生成：{manifest_path}[/green]")
    show_after_action_notice()


def _run_smart_scan_recommend_flow(config: dict, rules: dict, target_dir: str, report_dir: Path, state_file: Path) -> None:
    """智能扫描并建议压缩：扫描目录和子目录，命中后直接进入安全隔离+归档流程。"""
    console.print(f"[cyan]智能扫描并建议压缩：正在分析目录 {target_dir}[/cyan]")
    _run_scan_flow(
        config,
        rules,
        [target_dir],
        report_dir,
        state_file,
        cleanup_mode="standard",
        scan_func=scan_recommended_directory,
    )
    assert_no_deleted_entries(str(state_file))


def _history_restore_flow(report_dir: Path) -> None:
    sessions = list_sessions(str(report_dir))
    if not sessions:
        console.print("[yellow]暂无历史恢复记录。[/yellow]")
        return

    choices = [f"{idx + 1}. {Path(s).name}" for idx, s in enumerate(sessions)]
    choice = questionary.select("请选择一个历史清单：", choices=choices).ask()
    if not choice:
        return

    selected_index = int(choice.split(".", 1)[0]) - 1
    manifest_csv = sessions[selected_index]
    entries = load_manifest_entries(manifest_csv)
    if not entries:
        console.print("[yellow]所选清单没有可恢复记录。[/yellow]")
        return

    restorable = [e for e in entries if e.get("status") in {"quarantined", "archived", "deleted"}]
    if not restorable:
        console.print("[yellow]这个清单中没有可恢复项目。[/yellow]")
        return

    e_choices = []
    for idx, e in enumerate(restorable, start=1):
        name = Path(e.get("original_path", "")).name or "unknown"
        status = e.get("status", "unknown")
        e_choices.append(questionary.Choice(title=f"{idx}. {name} [{status}]", value=idx - 1))

    selected_indexes = questionary.checkbox(
        "请选择要恢复的文件（空格多选）：",
        choices=e_choices,
    ).ask()
    if not selected_indexes:
        return

    restore_all = bool(
        questionary.confirm(
            "是否要把这个清单里所有可恢复文件一次性全部恢复？如果选否，将只恢复你刚才选中的文件。",
            default=False,
        ).ask()
    )

    targets = restorable if restore_all else [restorable[idx] for idx in selected_indexes]
    confirm_label = "完全恢复" if restore_all else "确认恢复"
    if not questionary.confirm(f"请再次确认：是否执行{confirm_label}？", default=False).ask():
        console.print("[yellow]已取消恢复。[/yellow]")
        return

    restored = 0
    failed = 0
    for item in targets:
        target = dict(item)
        target["manifest_csv"] = manifest_csv
        if restore_file(target):
            restored += 1
        else:
            failed += 1

    if failed == 0:
        console.print(f"[green]恢复完成：成功恢复 {restored} 个文件。[/green]")
    else:
        console.print(f"[yellow]恢复完成：成功 {restored} 个，失败 {failed} 个。[/yellow]")


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    logger = _setup_logger(base_dir)

    if not _ensure_single_instance():
        console.print("[yellow]程序已在运行，请勿重复打开。[/yellow]")
        logger.warning("检测到重复启动，已拒绝本次实例")
        return 0

    config = get_config(base_dir / "config.json")
    rules = _load_rules(base_dir)

    report_dir = Path(config["report_dir"]) if config.get("report_dir") else base_dir
    report_dir.mkdir(parents=True, exist_ok=True)

    quarantine_dir = Path(config["quarantine_dir"])
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    state_dir = Path(config.get("state_dir") or (quarantine_dir / "states"))
    state_dir.mkdir(parents=True, exist_ok=True)

    show_welcome_panel()

    in_progress = check_resume(str(state_dir))
    if in_progress:
        console.print(f"[yellow]检测到 {len(in_progress)} 条上次未完成的操作。[/yellow]")
        if questionary.confirm("是否把这些未完成记录标记为失败并继续？", default=True).ask():
            grouped: dict[str, int] = {}
            for item in in_progress:
                sf = item.get("_state_file", "")
                grouped[sf] = grouped.get(sf, 0) + 1
            for sf in grouped:
                mark_in_progress_as_failed(sf)

    while True:
        try:
            choice = ask_main_menu()
            if "一键安全清理" in choice:
                show_ctrl_c_hint("一键安全清理")
                state_file = state_dir / f"state_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.json"
                _run_scan_flow(
                    config,
                    rules,
                    config.get("scan_targets", []),
                    report_dir,
                    state_file,
                    cleanup_mode="conservative",
                )

            elif "自定义兼推荐清理" in choice:
                show_ctrl_c_hint("自定义兼推荐清理")
                current_dir = ask_select_drive()
                console.print("[cyan]提示：不想手动挑文件时，直接选『智能扫描并建议压缩』即可。[/cyan]")
                while True:
                    browse_result = browse_directory_action(current_dir)
                    action = browse_result.get("action")
                    current_dir = str(browse_result.get("current_dir", current_dir))

                    if action == "cancel":
                        console.print("[yellow]未选择目录，已返回主菜单。[/yellow]")
                        break

                    state_file = state_dir / f"state_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.json"

                    if action == "manual_files":
                        selected_files = list(browse_result.get("selected_files", []))
                        _run_manual_quarantine_flow_with_files(config, report_dir, state_file, selected_files)
                    elif action == "smart_scan_recommend":
                        _run_smart_scan_recommend_flow(config, rules, current_dir, report_dir, state_file)
                    else:
                        console.print("[yellow]未知动作，已返回主菜单。[/yellow]")
                        break

                    if not ask_continue_next_directory():
                        break

            elif "极限释放" in choice:
                show_ctrl_c_hint("极限释放")
                show_extreme_release_intro()
                while True:
                    targets = ask_custom_targets(config.get("scan_targets", []), config.get("auto_scan_targets", []))
                    if not targets:
                        console.print("[yellow]未选择目录，已返回主菜单。[/yellow]")
                        break

                    state_file = state_dir / f"state_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.json"
                    _run_scan_flow(
                        config,
                        rules,
                        targets,
                        report_dir,
                        state_file,
                        cleanup_mode="standard",
                        extreme_release=True,
                    )

                    if not ask_continue_next_directory():
                        break

            elif "自主加入隔离箱" in choice:
                show_ctrl_c_hint("自主加入隔离箱")
                while True:
                    state_file = state_dir / f"state_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.json"
                    _run_manual_quarantine_flow(config, report_dir, state_file)
                    if not ask_continue_next_directory():
                        break

            elif "查看物理隔离箱" in choice:
                if open_quarantine_folder(str(quarantine_dir)):
                    console.print("[green]已打开隔离箱目录。[/green]")
                else:
                    console.print("[red]打开隔离箱失败，请检查目录权限。[/red]")

            elif "查看『隔离箱』与历史恢复" in choice:
                show_ctrl_c_hint("历史恢复")
                files = [p for p in quarantine_dir.glob("*") if p.is_file()]
                total = sum(p.stat().st_size for p in files)
                show_history_panel(len(files), total)
                _history_restore_flow(report_dir)

            elif "手动清理到期隔离副本" in choice:
                show_ctrl_c_hint("手动清理到期隔离副本")
                cleanup_days = int(config.get("quarantine_cleanup_after_days", 3))
                expired = check_expired_quarantine(str(state_dir), cleanup_after_days=cleanup_days)
                if not ask_delete_expired(len(expired), cleanup_days):
                    console.print("[yellow]已取消本次到期清理。[/yellow]")
                    continue

                grouped_entries: dict[str, list[str]] = {}
                for item in expired:
                    sf = item.get("_state_file", "")
                    grouped_entries.setdefault(sf, []).append(item.get("fingerprint", ""))

                for sf, ids in grouped_entries.items():
                    result = delete_quarantine_files(session_id=Path(sf).stem, state_file_path=sf, entry_ids=ids)
                    console.print(
                        f"[green]清理完成：成功 {len(result.get('deleted', []))}，"
                        f"失败 {len(result.get('failed', []))}。[/green]"
                    )

            elif "手动清空隔离箱" in choice:
                show_ctrl_c_hint("手动清空隔离箱")
                q_files = [p for p in quarantine_dir.glob("*") if p.is_file()]
                q_total = sum(p.stat().st_size for p in q_files)
                if not ask_confirm_manual_purge(len(q_files), q_total):
                    console.print("[yellow]已取消清空隔离箱。[/yellow]")
                    continue

                purge_result = purge_quarantine_now(str(quarantine_dir), str(state_dir))
                console.print(
                    f"[green]隔离箱清空完成：成功 {len(purge_result.get('deleted', []))}，"
                    f"失败 {len(purge_result.get('failed', []))}。[/green]"
                )

            else:
                save_config(config, base_dir / "config.json")
                console.print("[cyan]感谢使用，祝你电脑清爽不卡顿。[/cyan]")
                logger.info("用户退出程序")
                return 0
        except KeyboardInterrupt:
            logger.warning("用户触发 Ctrl+C，中止当前步骤并返回上一步")
            console.print("[yellow]已中止当前操作，已返回上一步。[/yellow]")
            continue
        except Exception as exc:
            logger.exception("主流程异常")
            console.print(f"[red]本次操作出现异常：{exc}。程序已保护现场，您可以继续使用。[/red]")


if __name__ == "__main__":
    raise SystemExit(main())
