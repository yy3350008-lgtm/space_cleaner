"""报告生成模块（V2）。"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any


def _fmt_size(num_bytes: int) -> str:
    size = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.2f} {units[idx]}"


def _entry_get(entry: Any, key: str, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def write_preview_report(scan_result: dict, output_path: str) -> str:
    """输出 Dry-run 预览清单（UTF-8-BOM TXT）。"""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    candidates = scan_result.get("candidates", [])
    skipped_permission = scan_result.get("skipped_permission", [])
    skipped_locked = scan_result.get("skipped_locked", [])
    skipped_hardlink = scan_result.get("skipped_hardlink", [])
    space_panel = scan_result.get("space_panel", {})

    total_candidates = len(candidates)
    estimated = int(scan_result.get("estimated_free_bytes", 0))
    total_skipped = len(skipped_permission) + len(skipped_locked) + len(skipped_hardlink)

    lines: list[str] = []
    lines.append("═" * 40)
    lines.append("释放空间助手 —— 扫描预览报告")
    lines.append(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("扫描模式：预览（Dry-run，未动任何文件）")
    lines.append("═" * 40)
    lines.append("")
    lines.append("【空间收益预估】")
    lines.append(f"立刻腾出空间：{_fmt_size(int(space_panel.get('immediate_free_bytes', estimated)))}")
    lines.append(f"预计压缩节省：{_fmt_size(int(space_panel.get('after_delete_quarantine_bytes', estimated)))}")
    lines.append(f"隔离箱历史占用：{_fmt_size(int(space_panel.get('current_quarantine_bytes', 0)))}")
    lines.append("")

    lines.append("【待处理文件清单】")
    lines.append("序号 | 大小 | 文件名 | 命中规则 | 关联文件")
    lines.append("---- | ---- | ------ | -------- | --------")

    for idx, item in enumerate(candidates, start=1):
        path = str(_entry_get(item, "path", ""))
        size = _fmt_size(int(_entry_get(item, "size_bytes", 0)))
        rule = str(_entry_get(item, "rule_matched", ""))
        companions = _entry_get(item, "companion_files", []) or []
        companion_display = "无" if not companions else "; ".join(companions)
        file_name = Path(path).name
        lines.append(f"{idx:03d}  | {size} | {file_name} | {rule} | {companion_display}")

        permission_warning = _entry_get(item, "permission_warning", "")
        if permission_warning:
            lines.append(f"      [权限警告] {permission_warning}")

    lines.append("")
    lines.append("【跳过文件（权限不足）】")
    for p in skipped_permission:
        lines.append(f"- {p}（无读取权限）")

    lines.append("")
    lines.append("【跳过文件（文件被锁定）】")
    for p in skipped_locked:
        lines.append(f"- {p}（文件被其他程序占用）")

    lines.append("")
    lines.append("【跳过文件（硬链接）】")
    for p in skipped_hardlink:
        lines.append(f"- {p}（nlink>1，跳过以防止破坏引用）")

    lines.append("")
    lines.append("【统计摘要】")
    lines.append(f"待处理文件数：{total_candidates}")
    lines.append(f"估计可释放空间：{_fmt_size(estimated)}")
    lines.append(f"跳过文件数：{total_skipped}")
    lines.append("═" * 40)
    lines.append("提示：以上仅为预览，未对任何文件执行操作。")
    lines.append("═" * 40)

    with out.open("w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines) + "\n")

    return str(out)


def write_manifest(state: dict, output_path: str) -> str:
    """生成 manifest TXT + CSV。"""
    out_dir = Path(output_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = out_dir / f"manifest_{stamp}.txt"
    csv_path = out_dir / f"manifest_{stamp}.csv"

    session_id = state.get("session_id", "")
    created_at = state.get("created_at", "")
    entries = state.get("entries", [])

    txt_lines = [
        "释放空间助手 —— 操作清单",
        f"session_id: {session_id}",
        f"created_at: {created_at}",
        "",
        "序号 | 状态 | 大小 | 原路径 | 隔离路径 | 归档",
        "---- | ---- | ---- | ------ | -------- | ----",
    ]

    for idx, item in enumerate(entries, start=1):
        size = _fmt_size(int(item.get("size_bytes", 0)))
        txt_lines.append(
            f"{idx:03d} | {item.get('status', '')} | {size} | {item.get('original_path', '')} | "
            f"{item.get('quarantine_path', '')} | {item.get('archive_path', '')}"
        )

    with txt_path.open("w", encoding="utf-8-sig") as f:
        f.write("\n".join(txt_lines) + "\n")

    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "session_id",
                "original_path",
                "quarantine_path",
                "companion_files",
                "size_bytes",
                "status",
                "quarantined_at",
                "archived_at",
                "delete_after",
                "archive_path",
                "fingerprint",
                "skip_zip",
            ],
        )
        writer.writeheader()
        for item in entries:
            writer.writerow(
                {
                    "session_id": session_id,
                    "original_path": item.get("original_path", ""),
                    "quarantine_path": item.get("quarantine_path", ""),
                    "companion_files": "|".join(item.get("companion_files", []) or []),
                    "size_bytes": item.get("size_bytes", 0),
                    "status": item.get("status", ""),
                    "quarantined_at": item.get("quarantined_at", ""),
                    "archived_at": item.get("archived_at", ""),
                    "delete_after": item.get("delete_after", ""),
                    "archive_path": item.get("archive_path", ""),
                    "fingerprint": item.get("fingerprint", ""),
                    "skip_zip": item.get("skip_zip", False),
                }
            )

    return str(txt_path)
