"""安全操作层（V2）。"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
import zipfile
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Any

from rich.console import Console
from send2trash import send2trash

from scanner import is_file_locked

console = Console()


def _entry_get(entry: Any, key: str, default: Any = None) -> Any:
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _same_drive(path_a: str, path_b: str) -> bool:
    drive_a = Path(path_a).drive.lower()
    drive_b = Path(path_b).drive.lower()
    return bool(drive_a and drive_b and drive_a == drive_b)


def _utcnow_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _parse_iso(iso_text: str | None) -> datetime | None:
    if not iso_text:
        return None
    try:
        return datetime.fromisoformat(iso_text)
    except ValueError:
        return None


def _load_state(state_file: str) -> dict:
    p = Path(state_file)
    if not p.exists():
        return {
            "session_id": str(uuid.uuid4()),
            "created_at": _utcnow_iso(),
            "entries": [],
        }

    with p.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def _save_state(state_file: str, state: dict) -> None:
    atomic_save_json(state, state_file)


def atomic_save_json(data: dict, file_path: str) -> None:
    """临时文件 + fsync + replace，确保状态写入原子可靠。"""
    p = Path(file_path)
    _ensure_parent(p)
    fd, tmp_name = tempfile.mkstemp(prefix=p.stem + "_", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, str(p))
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass


def reconcile_missing_quarantine_entries(state_file_path: str) -> dict:
    """自愈状态：若隔离副本被手动删除，自动将状态标记为 missing。"""
    state = _load_state(state_file_path)
    changed = 0
    for item in state.get("entries", []):
        status = str(item.get("status", ""))
        if status in {"deleted", "restored", "failed", "missing"}:
            continue

        qp = Path(str(item.get("quarantine_path", "")))
        if not qp.exists():
            item["status"] = "missing"
            item["missing_at"] = _utcnow_iso()
            changed += 1

    if changed:
        _save_state(state_file_path, state)
    return {"changed": changed, "state": state}


def _upsert_state_entry(state: dict, item: dict) -> None:
    for idx, e in enumerate(state.get("entries", [])):
        if e.get("original_path") == item.get("original_path"):
            state["entries"][idx] = item
            return
    state.setdefault("entries", []).append(item)


def pre_flight_check(entries: list, quarantine_dir: str) -> dict:
    """执行操作前强制安全预检。"""
    warnings: list[str] = []
    if not entries:
        return {"ok": False, "reason": "empty_entries", "detail": "没有可处理文件"}

    # 先剔除被占用文件，再计算空间，避免误判空间不足。
    locked_skipped: list[str] = []
    filtered_entries: list[Any] = []
    for entry in entries:
        src = str(_entry_get(entry, "path", ""))
        if src and is_file_locked(src):
            locked_skipped.append(src)
            continue
        filtered_entries.append(entry)

    if not filtered_entries:
        return {
            "ok": False,
            "reason": "all_locked_or_empty",
            "locked_skipped": locked_skipped,
            "warnings": warnings,
            "entries": [],
            "detail": "候选文件都被占用或为空",
        }

    total_size = sum(int(_entry_get(e, "size_bytes", 0)) for e in filtered_entries)

    q_dir = Path(quarantine_dir)
    q_dir.mkdir(parents=True, exist_ok=True)

    usage = shutil.disk_usage(q_dir)
    required = int(total_size * 1.2)
    if usage.free < required:
        detail = (
            f"隔离分区剩余空间不足：free={usage.free} bytes, "
            f"required={required} bytes (含20%余量)"
        )
        console.print(f"[bold red]{detail}[/bold red]")
        return {"ok": False, "reason": "insufficient_space", "detail": detail}

    strategy = "rename"

    for entry in filtered_entries:
        src = str(_entry_get(entry, "path", ""))
        if src and not _same_drive(src, str(q_dir)):
            strategy = "copy_then_delete"

        if int(_entry_get(entry, "size_bytes", 0)) > int(3.9 * 1024 * 1024 * 1024):
            try:
                setattr(entry, "skip_zip", True)
            except Exception:
                if isinstance(entry, dict):
                    entry["skip_zip"] = True
            warnings.append(f"文件超过3.9GB，将跳过ZIP：{src}")

    return {
        "ok": True,
        "move_strategy": strategy,
        "locked_skipped": locked_skipped,
        "warnings": warnings,
        "entries": filtered_entries,
    }


def _build_quarantine_path(entry: Any, quarantine_dir: str) -> Path:
    source_name = Path(str(_entry_get(entry, "path"))).name
    unique_name = f"{uuid.uuid4().hex[:8]}_{source_name}"
    return Path(quarantine_dir) / unique_name


def move_to_quarantine(entry: Any, quarantine_dir: str, move_strategy: str, state_file: str) -> bool:
    """移动单个文件到隔离区，并维护状态机。"""
    src = Path(str(_entry_get(entry, "path", "")))
    if not src.exists():
        return False

    dest = _build_quarantine_path(entry, quarantine_dir)
    state = _load_state(state_file)

    state_item = {
        "original_path": str(src),
        "quarantine_path": str(dest),
        "companion_files": list(_entry_get(entry, "companion_files", []) or []),
        "size_bytes": int(_entry_get(entry, "size_bytes", 0)),
        "fingerprint": str(_entry_get(entry, "fingerprint", "")),
        "status": "in_progress",
        "quarantined_at": _utcnow_iso(),
        "archived_at": None,
        "archive_path": None,
        "skip_zip": bool(_entry_get(entry, "skip_zip", False)),
        "delete_after": None,
    }
    _upsert_state_entry(state, state_item)
    _save_state(state_file, state)

    copied = False
    try:
        _ensure_parent(dest)
        if move_strategy == "rename":
            try:
                os.rename(str(src), str(dest))
            except OSError:
                shutil.copy2(str(src), str(dest))
                copied = True
                if dest.stat().st_size != src.stat().st_size:
                    raise OSError("copy verification failed: size mismatch")
                os.remove(str(src))
        else:
            shutil.copy2(str(src), str(dest))
            copied = True
            if dest.stat().st_size != src.stat().st_size:
                raise OSError("copy verification failed: size mismatch")
            os.remove(str(src))

        state = _load_state(state_file)
        state_item["status"] = "quarantined"
        state_item["quarantined_at"] = _utcnow_iso()
        _upsert_state_entry(state, state_item)
        _save_state(state_file, state)

        try:
            setattr(entry, "quarantine_path", str(dest))
        except Exception:
            if isinstance(entry, dict):
                entry["quarantine_path"] = str(dest)

        return True
    except (PermissionError, OSError, shutil.Error) as exc:
        if copied and dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass

        state = _load_state(state_file)
        state_item["status"] = "failed"
        state_item["error"] = str(exc)
        _upsert_state_entry(state, state_item)
        _save_state(state_file, state)
        console.print(f"[red]隔离失败：{src} -> {exc}[/red]")
        return False


def create_zip_archive(session_id: str, state_file_path: str, output_dir: str, cleanup_after_days: int = 3) -> dict:
    """仅压缩 quarantined 且非 skip_zip 文件，成功后更新 archived 状态。"""
    reconcile_missing_quarantine_entries(state_file_path)
    state = _load_state(state_file_path)
    arc = Path(output_dir) / f"SpaceCleaner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    _ensure_parent(arc)

    to_archive: list[dict] = []
    skipped_large: list[str] = []
    for item in state.get("entries", []):
        if item.get("status") != "quarantined":
            continue
        if bool(item.get("skip_zip", False)):
            skipped_large.append(item.get("original_path", ""))
            continue
        qp = Path(item.get("quarantine_path", ""))
        if qp.exists() and qp.is_file():
            to_archive.append(item)

    if not to_archive:
        return {
            "ok": True,
            "archive_path": str(arc),
            "file_count": 0,
            "zip_size_bytes": 0,
            "skipped_large": skipped_large,
        }

    try:
        used_names: set[str] = set()

        def build_arcname(original_path: str) -> str:
            base = Path(original_path).name
            stem = Path(base).stem
            suffix = Path(base).suffix
            candidate = base
            n = 1
            while candidate.lower() in used_names:
                candidate = f"{stem}_{n}{suffix}"
                n += 1
            used_names.add(candidate.lower())
            return candidate

        with zipfile.ZipFile(str(arc), "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for item in to_archive:
                file_path = Path(item["quarantine_path"])
                arcname = build_arcname(item["original_path"])
                zf.write(str(file_path), arcname=arcname)

        with zipfile.ZipFile(str(arc), "r", allowZip64=True) as zf:
            bad_file = zf.testzip()

        if bad_file is not None:
            try:
                arc.unlink()
            except OSError:
                pass
            raise RuntimeError(f"zip_corrupted:{bad_file}")

        for item in state.get("entries", []):
            if item.get("status") != "quarantined":
                continue
            if bool(item.get("skip_zip", False)):
                continue

            item["status"] = "archived"
            item["archived_at"] = _utcnow_iso()
            item["archive_path"] = str(arc)
            if cleanup_after_days == -1:
                item["delete_after"] = None
            elif cleanup_after_days == 0:
                item["delete_after"] = _utcnow_iso()
            else:
                item["delete_after"] = (datetime.now() + timedelta(days=cleanup_after_days)).isoformat(timespec="seconds")

        _save_state(state_file_path, state)

        return {
            "ok": True,
            "archive_path": str(arc),
            "file_count": len(to_archive),
            "zip_size_bytes": arc.stat().st_size if arc.exists() else 0,
            "skipped_large": skipped_large,
        }
    except (PermissionError, OSError, zipfile.BadZipFile) as exc:
        return {"ok": False, "reason": "zip_error", "detail": str(exc)}
    except RuntimeError as exc:
        try:
            if arc.exists():
                arc.unlink()
        except OSError:
            pass
        return {"ok": False, "reason": "zip_corrupted", "detail": str(exc)}


def check_resume_and_expired(state_file: str, cleanup_after_days: int = 3) -> dict:
    """启动自检：返回未完成条目与已到期条目。"""
    p = Path(state_file)
    if not p.exists():
        return {"in_progress": [], "expired_archived": []}

    state = _load_state(state_file)
    in_progress = [e for e in state.get("entries", []) if e.get("status") == "in_progress"]

    now = datetime.now()
    expired_archived = []
    for item in state.get("entries", []):
        if item.get("status") != "archived":
            continue
        delete_after = _parse_iso(item.get("delete_after"))
        if delete_after and delete_after <= now:
            expired_archived.append(item)
            continue
        if delete_after is None and cleanup_after_days >= 0:
            archived_at = _parse_iso(item.get("archived_at"))
            if archived_at and (archived_at + timedelta(days=cleanup_after_days)) <= now:
                expired_archived.append(item)

    return {"in_progress": in_progress, "expired_archived": expired_archived}


def delete_quarantine_files(session_id: str, state_file_path: str, entry_ids: list[str]) -> dict:
    """删除隔离副本（入回收站），并写入即将清理报告。"""
    reconcile_missing_quarantine_entries(state_file_path)
    state_file = Path(state_file_path)
    state = _load_state(state_file_path)
    now = datetime.now()
    if (now - datetime.fromtimestamp(state_file.stat().st_mtime)).total_seconds() > 300:
        return {"deleted": [], "failed": ["state_stale"], "report_path": ""}

    selected = [e for e in state.get("entries", []) if e.get("fingerprint") in set(entry_ids)]
    if not selected:
        return {"deleted": [], "failed": ["no_entry_selected"], "report_path": ""}

    for item in selected:
        if item.get("status") != "archived":
            return {"deleted": [], "failed": [f"not_archived:{item.get('original_path','')}"], "report_path": ""}

    archive_paths = {item.get("archive_path") for item in selected if item.get("archive_path")}
    for archive_path in archive_paths:
        ap = Path(str(archive_path))
        if not ap.exists():
            return {"deleted": [], "failed": [f"archive_missing:{archive_path}"], "report_path": ""}
        try:
            with zipfile.ZipFile(str(ap), "r", allowZip64=True) as zf:
                bad = zf.testzip()
            if bad is not None:
                return {"deleted": [], "failed": [f"archive_corrupted:{archive_path}:{bad}"], "report_path": ""}
        except (OSError, zipfile.BadZipFile):
            return {"deleted": [], "failed": [f"archive_open_failed:{archive_path}"], "report_path": ""}

    report_path = state_file.parent / f"cleanup_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with report_path.open("w", encoding="utf-8-sig") as f:
        f.write("释放空间助手 - 即将清理报告\n")
        f.write(f"生成时间: {_utcnow_iso()}\n\n")
        for item in selected:
            f.write(f"- {item.get('quarantine_path','')}\n")

    deleted: list[str] = []
    failed: list[str] = []
    for item in selected:
        qp = Path(item.get("quarantine_path", ""))
        if not qp.exists():
            failed.append(str(qp))
            continue
        try:
            send2trash(str(qp))
            item["status"] = "deleted"
            item["deleted_at"] = _utcnow_iso()
            deleted.append(str(qp))
        except Exception:
            failed.append(str(qp))

    _save_state(state_file_path, state)
    return {"deleted": deleted, "failed": failed, "report_path": str(report_path)}


def check_resume(state_dir: str) -> list[dict]:
    """扫描 state_dir 下 state_*.json，返回 in_progress 条目列表。"""
    base = Path(state_dir)
    if not base.exists():
        return []

    result: list[dict] = []
    for f in base.glob("state_*.json"):
        try:
            state = _load_state(str(f))
            for item in state.get("entries", []):
                if item.get("status") == "in_progress":
                    row = dict(item)
                    row["_state_file"] = str(f)
                    result.append(row)
        except (OSError, json.JSONDecodeError):
            continue
    return result


def check_expired_quarantine(state_dir: str, cleanup_after_days: int = 3) -> list[dict]:
    """检测到期 archived 条目，仅检测不删除。cleanup_after_days=0 表示立即可删。"""
    base = Path(state_dir)
    if not base.exists():
        return []

    now = datetime.now()
    expired: list[dict] = []
    for f in base.glob("state_*.json"):
        try:
            state = _load_state(str(f))
            for item in state.get("entries", []):
                if item.get("status") != "archived":
                    continue
                if cleanup_after_days == 0:
                    row = dict(item)
                    row["_state_file"] = str(f)
                    expired.append(row)
                    continue

                delete_after = _parse_iso(item.get("delete_after"))
                if delete_after and delete_after <= now:
                    row = dict(item)
                    row["_state_file"] = str(f)
                    expired.append(row)
                    continue

                if delete_after is None and cleanup_after_days > 0:
                    archived_at = _parse_iso(item.get("archived_at"))
                    if archived_at and (archived_at + timedelta(days=cleanup_after_days)) <= now:
                        row = dict(item)
                        row["_state_file"] = str(f)
                        expired.append(row)
        except (OSError, json.JSONDecodeError):
            continue
    return expired


def purge_quarantine_now(quarantine_dir: str, state_dir: str) -> dict:
    """手动清空隔离箱：将隔离目录中的文件送入回收站，并更新状态。"""
    q_dir = Path(quarantine_dir)
    if not q_dir.exists():
        return {"deleted": [], "failed": [], "updated_states": 0}

    if Path(state_dir).exists():
        for sf in Path(state_dir).glob("state_*.json"):
            reconcile_missing_quarantine_entries(str(sf))

    deleted: list[str] = []
    failed: list[str] = []
    tracked_paths: set[str] = set()

    for p in q_dir.glob("*"):
        if p.is_dir():
            continue
        try:
            send2trash(str(p))
            deleted.append(str(p))
            tracked_paths.add(str(p))
        except Exception:
            failed.append(str(p))

    updated_states = 0
    s_dir = Path(state_dir)
    if s_dir.exists():
        for sf in s_dir.glob("state_*.json"):
            try:
                state = _load_state(str(sf))
            except (OSError, json.JSONDecodeError):
                continue

            changed = False
            for item in state.get("entries", []):
                qp = str(item.get("quarantine_path", ""))
                if qp in tracked_paths and item.get("status") not in {"deleted", "restored"}:
                    item["status"] = "deleted"
                    item["deleted_at"] = _utcnow_iso()
                    changed = True

            if changed:
                _save_state(str(sf), state)
                updated_states += 1

    return {"deleted": deleted, "failed": failed, "updated_states": updated_states}


def mark_in_progress_as_failed(state_file: str) -> int:
    """用户放弃恢复时，将 in_progress 标记为 failed。"""
    state = _load_state(state_file)
    changed = 0
    for item in state.get("entries", []):
        if item.get("status") == "in_progress":
            item["status"] = "failed"
            item["failed_at"] = _utcnow_iso()
            changed += 1
    _save_state(state_file, state)
    return changed


def build_extreme_release_plan(state_file_path: str, max_state_age_seconds: int = 900) -> dict:
    """构建极限释放计划，包含十项关键风险检查。"""
    heal_result = reconcile_missing_quarantine_entries(state_file_path)

    checks: list[dict] = []
    blockers: list[str] = []
    warnings: list[str] = []
    candidate_ids: list[str] = []
    candidate_bytes = 0

    state_file = Path(state_file_path)

    # 1) 状态文件存在
    check1_ok = state_file.exists()
    checks.append(
        {
            "name": "状态文件存在",
            "ok": check1_ok,
            "detail": str(state_file) if check1_ok else "state 文件不存在",
        }
    )
    if not check1_ok:
        blockers.append("state_missing")
        return {
            "checks": checks,
            "blockers": blockers,
            "warnings": warnings,
            "candidate_entry_ids": candidate_ids,
            "candidate_count": 0,
            "candidate_bytes": 0,
        }

    # 2) 状态文件可解析
    try:
        state = _load_state(state_file_path)
        check2_ok = True
        detail2 = "json 可读取"
    except Exception as exc:  # pragma: no cover - 防御性兜底
        state = {"entries": []}
        check2_ok = False
        detail2 = f"json 解析失败: {exc}"
        blockers.append("state_unreadable")
    checks.append({"name": "状态文件可读取", "ok": check2_ok, "detail": detail2})
    if not check2_ok:
        return {
            "checks": checks,
            "blockers": blockers,
            "warnings": warnings,
            "candidate_entry_ids": candidate_ids,
            "candidate_count": 0,
            "candidate_bytes": 0,
        }

    entries = state.get("entries", [])

    # 3) 存在条目
    check3_ok = len(entries) > 0
    checks.append({"name": "状态条目非空", "ok": check3_ok, "detail": f"entries={len(entries)}"})
    if not check3_ok:
        blockers.append("empty_state_entries")

    archived = [e for e in entries if e.get("status") == "archived"]
    if int(heal_result.get("changed", 0)) > 0:
        warnings.append(f"state_reconciled:{int(heal_result.get('changed', 0))}")

    # 4) 存在已归档条目
    check4_ok = len(archived) > 0
    checks.append({"name": "存在已归档条目", "ok": check4_ok, "detail": f"archived={len(archived)}"})
    if not check4_ok:
        blockers.append("no_archived_entries")

    # 5) 所有归档条目有指纹
    missing_fp = [e.get("original_path", "") for e in archived if not e.get("fingerprint")]
    check5_ok = len(missing_fp) == 0
    checks.append(
        {
            "name": "归档条目指纹完整",
            "ok": check5_ok,
            "detail": "全部完整" if check5_ok else f"缺失 {len(missing_fp)} 条",
        }
    )
    if not check5_ok:
        blockers.append("fingerprint_missing")

    # 6) 归档路径字段完整
    missing_arc_field = [e.get("original_path", "") for e in archived if not e.get("archive_path")]
    check6_ok = len(missing_arc_field) == 0
    checks.append(
        {
            "name": "归档路径字段完整",
            "ok": check6_ok,
            "detail": "全部完整" if check6_ok else f"缺失 {len(missing_arc_field)} 条",
        }
    )
    if not check6_ok:
        blockers.append("archive_path_missing")

    archive_paths = {str(e.get("archive_path")) for e in archived if e.get("archive_path")}

    # 7) 归档文件存在
    missing_archive_files = [p for p in archive_paths if not Path(p).exists()]
    check7_ok = len(missing_archive_files) == 0
    checks.append(
        {
            "name": "归档文件存在",
            "ok": check7_ok,
            "detail": "全部存在" if check7_ok else f"缺失 {len(missing_archive_files)} 个",
        }
    )
    if not check7_ok:
        blockers.append("archive_file_missing")

    # 8) 归档完整性校验通过
    bad_archives = []
    for ap in archive_paths:
        p = Path(ap)
        if not p.exists():
            continue
        try:
            with zipfile.ZipFile(str(p), "r", allowZip64=True) as zf:
                bad = zf.testzip()
            if bad is not None:
                bad_archives.append(f"{ap}:{bad}")
        except (OSError, zipfile.BadZipFile):
            bad_archives.append(ap)
    check8_ok = len(bad_archives) == 0
    checks.append(
        {
            "name": "归档完整性校验",
            "ok": check8_ok,
            "detail": "全部通过" if check8_ok else f"损坏/不可读 {len(bad_archives)} 个",
        }
    )
    if not check8_ok:
        blockers.append("archive_integrity_failed")

    # 9) 隔离副本存在且未被占用
    missing_q = []
    locked_q = []
    for item in archived:
        qp = Path(item.get("quarantine_path", ""))
        if not qp.exists():
            missing_q.append(str(qp))
            continue
        if is_file_locked(str(qp)):
            locked_q.append(str(qp))
            continue
        fp = str(item.get("fingerprint", "")).strip()
        if fp:
            candidate_ids.append(fp)
            candidate_bytes += int(item.get("size_bytes", 0))

    check9_ok = len(missing_q) == 0 and len(locked_q) == 0
    detail9_parts = []
    if missing_q:
        detail9_parts.append(f"缺失 {len(missing_q)}")
    if locked_q:
        detail9_parts.append(f"占用 {len(locked_q)}")
    detail9 = "全部可访问" if not detail9_parts else "；".join(detail9_parts)
    checks.append({"name": "隔离副本可访问", "ok": check9_ok, "detail": detail9})
    if missing_q:
        warnings.append("quarantine_missing_reconciled")
    if locked_q:
        warnings.append("quarantine_locked_skipped")

    # 10) 状态文件新鲜度检查
    is_stale = True
    try:
        is_stale = (datetime.now() - datetime.fromtimestamp(state_file.stat().st_mtime)).total_seconds() > max_state_age_seconds
    except OSError:
        is_stale = True
    check10_ok = not is_stale
    checks.append(
        {
            "name": "状态文件新鲜度",
            "ok": check10_ok,
            "detail": "状态文件有效" if check10_ok else f"超过 {max_state_age_seconds} 秒，需重新扫描",
        }
    )
    if not check10_ok:
        blockers.append("state_stale")

    if not candidate_ids:
        blockers.append("no_candidate_for_extreme_release")

    return {
        "checks": checks,
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "candidate_entry_ids": sorted(set(candidate_ids)),
        "candidate_count": len(set(candidate_ids)),
        "candidate_bytes": candidate_bytes,
    }


def assert_no_deleted_entries(state_file_path: str) -> None:
    """防御性断言：推荐压缩流程中不允许出现自动删除。"""
    state = _load_state(state_file_path)
    deleted = [e for e in state.get("entries", []) if e.get("status") == "deleted"]
    if deleted:
        raise RuntimeError("unexpected_deleted_entries")
