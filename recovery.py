"""恢复模块（V2）。"""

from __future__ import annotations

import csv
import os
import shutil
import zipfile
from pathlib import Path


def _same_drive(path_a: str, path_b: str) -> bool:
    return Path(path_a).drive.lower() == Path(path_b).drive.lower()


def _move_with_verify(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if _same_drive(str(src), str(dest)):
        os.rename(str(src), str(dest))
    else:
        shutil.copy2(str(src), str(dest))
        if src.stat().st_size != dest.stat().st_size:
            raise OSError("copy verify failed")
        src.unlink()


def _update_manifest_status(manifest_csv: Path, original_path: str, status: str) -> None:
    rows: list[dict] = []
    with manifest_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        for row in reader:
            if row.get("original_path") == original_path:
                row["status"] = status
            rows.append(row)

    with manifest_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def list_sessions(manifest_dir: str) -> list[str]:
    """列出所有历史 manifest CSV，按时间倒序。"""
    d = Path(manifest_dir)
    if not d.exists():
        return []
    csv_files = sorted(d.glob("manifest_*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [str(p) for p in csv_files]


def load_manifest_entries(manifest_csv: str) -> list[dict]:
    p = Path(manifest_csv)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def restore_file(entry: dict) -> bool:
    """从 quarantine_path 恢复到 original_path，并同步恢复 companion_files。"""
    try:
        quarantine_path = Path(entry["quarantine_path"])
        original_path = Path(entry["original_path"])
        archive_path = str(entry.get("archive_path", "")).strip()
        raw_companions = entry.get("companion_files", []) or []
        if isinstance(raw_companions, str):
            companions = [c for c in raw_companions.split("|") if c]
        else:
            companions = list(raw_companions)

        if not quarantine_path.exists():
            # 隔离副本缺失时，尝试从归档包按原文件名恢复。
            if not archive_path:
                return False
            if not Path(archive_path).exists():
                return False
            if not restore_from_zip(archive_path, original_path.name, str(original_path)):
                return False

            manifest_csv = entry.get("manifest_csv")
            if manifest_csv:
                _update_manifest_status(Path(manifest_csv), str(original_path), "restored")
            return True

        original_path.parent.mkdir(parents=True, exist_ok=True)

        if original_path.exists():
            answer = input(f"目标文件已存在，是否覆盖？{original_path} [y/N]: ").strip().lower()
            if answer != "y":
                return False
            if original_path.is_file():
                original_path.unlink()

        _move_with_verify(quarantine_path, original_path)

        for c in companions:
            c_src = Path(c)
            if not c_src.exists():
                continue
            c_dest = original_path.parent / c_src.name
            if c_dest.exists() and c_dest.is_file():
                c_dest.unlink()
            _move_with_verify(c_src, c_dest)

        manifest_csv = entry.get("manifest_csv")
        if manifest_csv:
            _update_manifest_status(Path(manifest_csv), str(original_path), "restored")

        return True
    except (KeyError, PermissionError, OSError, shutil.Error):
        return False


def restore_from_zip(zip_path: str, file_in_zip: str, restore_to: str) -> bool:
    """从 ZIP 中提取单个文件并还原到目标路径。"""
    z_path = Path(zip_path)
    target = Path(restore_to)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(str(z_path), "r", allowZip64=True) as zf:
            with zf.open(file_in_zip, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        return True
    except (PermissionError, OSError, KeyError, zipfile.BadZipFile):
        return False
