"""扫描引擎（V2）。"""

from __future__ import annotations

import binascii
import fnmatch
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class FileEntry:
    path: str
    long_path: str
    size_bytes: int
    fingerprint: str
    rule_matched: str
    is_duplicate: bool
    companion_files: list[str] = field(default_factory=list)
    action_suggestion: str = "quarantine"
    skip_zip: bool = False


def make_long_path(path: str) -> str:
    r"""Windows 长路径转换：若路径超过 200 字符，自动添加 \\?\ 前缀。"""
    if sys.platform != "win32":
        return path

    p = str(Path(path))
    if p.startswith("\\\\?\\"):
        return p
    if len(p) <= 200:
        return p

    if p.startswith("\\\\"):
        # UNC 路径转换到 \\?\UNC\server\share
        return "\\\\?\\UNC\\" + p.lstrip("\\")
    return "\\\\?\\" + p


def is_hardlink(path: str) -> bool:
    """检测文件是否为硬链接（nlink > 1）。"""
    try:
        st = os.stat(make_long_path(path))
        return getattr(st, "st_nlink", 1) > 1
    except (PermissionError, OSError):
        return False


def is_file_locked(path: str) -> bool:
    """检测文件是否被其他进程占用。"""
    try:
        lp = make_long_path(path)
        if sys.platform == "win32":
            import msvcrt

            with open(lp, "r+b") as fh:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    return False
                except OSError:
                    return True

        with open(lp, "r+b"):
            return False
    except (PermissionError, OSError):
        return True


def compute_fingerprint(path: str) -> str:
    """计算复合指纹：size:head_crc32:ext。"""
    p = Path(path)
    file_size = p.stat().st_size
    with open(make_long_path(str(p)), "rb") as f:
        head = f.read(4096)
    crc = binascii.crc32(head) & 0xFFFFFFFF
    return f"{file_size}:{crc:08x}:{p.suffix.lower()}"


def _dir_size_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(make_long_path(str(cur))) as it:
                for de in it:
                    p = Path(cur, de.name)
                    try:
                        if de.is_dir(follow_symlinks=False):
                            stack.append(p)
                        elif de.is_file(follow_symlinks=False):
                            total += de.stat(follow_symlinks=False).st_size
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            continue
    return total


def is_excluded(path: str, exclude_dirs: list[str], exclude_extensions: list[str]) -> bool:
    """排除规则优先级高于扫描规则。"""
    p = Path(path).resolve()
    ext = p.suffix.lower()

    normalized_exclude_dirs = [Path(os.path.expandvars(d)).resolve() for d in exclude_dirs if d]
    for excluded in normalized_exclude_dirs:
        try:
            if os.path.commonpath([str(p), str(excluded)]) == str(excluded):
                return True
        except ValueError:
            continue

    if ext in {e.lower() for e in exclude_extensions}:
        return True

    lowered = str(p).lower()
    keywords = ["documents", "pictures", "videos", "source", "src", ".git", "node_modules"]
    return any(k in lowered for k in keywords)


def _match_rules(path: Path, rules: dict) -> str | None:
    name_lower = path.name.lower()
    stem_lower = path.stem.lower()
    ext_lower = path.suffix.lower()

    for pattern in rules.get("name_patterns", []):
        lowered_pattern = pattern.lower()
        if any(ch in lowered_pattern for ch in "*?[]"):
            if fnmatch.fnmatch(name_lower, lowered_pattern):
                return f"name_pattern:{pattern}"
        elif lowered_pattern in name_lower:
            return f"name_pattern:{pattern}"

    for suffix in rules.get("suffix_patterns", []):
        if suffix.lower() in stem_lower:
            return f"suffix_pattern:{suffix}"

    if ext_lower in {e.lower() for e in rules.get("target_extensions", [])}:
        return f"target_extension:{ext_lower}"

    if ext_lower in {e.lower() for e in rules.get("log_extensions", [])}:
        return f"log_extension:{ext_lower}"

    return None


def _match_rules_by_mode(path: Path, rules: dict, mode: str) -> str | None:
    rule_sets = rules.get("modes", {})
    keys = rule_sets.get(mode, rule_sets.get("conservative", []))
    name_lower = path.name.lower()
    stem_lower = path.stem.lower()
    ext_lower = path.suffix.lower()

    if "name_patterns" in keys:
        for pattern in rules.get("name_patterns", []):
            lowered_pattern = pattern.lower()
            if any(ch in lowered_pattern for ch in "*?[]"):
                if fnmatch.fnmatch(name_lower, lowered_pattern):
                    return f"name:{pattern}"
            elif lowered_pattern in name_lower:
                return f"name:{pattern}"

    if "suffix_patterns" in keys:
        for suffix in rules.get("suffix_patterns", []):
            if suffix.lower() in stem_lower:
                return f"suffix:{suffix}"

    if "target_extensions" in keys and ext_lower in {e.lower() for e in rules.get("target_extensions", [])}:
        return f"ext:{ext_lower}"

    if "log_extensions" in keys and ext_lower in {e.lower() for e in rules.get("log_extensions", [])}:
        return f"log:{ext_lower}"

    return None


def _is_social_cache_scope(path: Path) -> tuple[bool, str]:
    lowered = str(path).lower().replace("/", "\\")
    scopes = [
        ("msgattach", "wechat_msgattach_scope"),
        ("filestorage\\cache", "wechat_filestorage_cache_scope"),
        ("image_cache", "qq_image_cache_scope"),
    ]
    for scope, reason in scopes:
        if scope in lowered:
            return True, reason
    return False, ""


def _find_companions(path: Path, companion_exts: list[str]) -> list[Path]:
    if path.suffix.lower() != ".exe":
        return []

    companions: list[Path] = []
    for ext in companion_exts:
        candidate = path.with_suffix(ext)
        if candidate.exists() and candidate.is_file():
            companions.append(candidate)
    return companions


def scan_directory(
    target_dir: str,
    rules: dict,
    config: dict,
    progress_callback: Callable[[int], None] | None = None,
) -> dict:
    """扫描指定目录并返回候选与跳过列表。"""
    exclude_dirs = config.get("exclude_dirs", [])
    exclude_exts = config.get("exclude_extensions", [])
    min_size = int(config.get("min_file_size_kb", 0)) * 1024
    mode = str(config.get("cleanup_mode", "conservative"))

    companion_exts = [e.lower() for e in rules.get("companion_extensions", [])]

    candidates: list[FileEntry] = []
    skipped_permission: list[str] = []
    skipped_locked: list[str] = []
    skipped_hardlink: list[str] = []
    skipped_exclude: list[str] = []

    total_scanned = 0
    estimated_free_bytes = 0
    fingerprint_seen: set[str] = set()

    root = Path(os.path.expandvars(target_dir))
    if not root.exists() or not root.is_dir():
        return {
            "candidates": [],
            "skipped_permission": [str(root)],
            "skipped_locked": [],
            "skipped_hardlink": [],
            "skipped_exclude": [],
            "total_scanned": 0,
            "estimated_free_bytes": 0,
        }

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(make_long_path(str(current))) as it:
                entries = list(it)
        except (PermissionError, OSError):
            skipped_permission.append(str(current))
            continue

        for de in entries:
            current_path = Path(current, de.name)
            total_scanned += 1
            if progress_callback and total_scanned % 500 == 0:
                progress_callback(total_scanned)

            try:
                if de.is_dir(follow_symlinks=False):
                    if not is_excluded(str(current_path), exclude_dirs, exclude_exts):
                        stack.append(current_path)
                    else:
                        skipped_exclude.append(str(current_path))
                    continue

                if not de.is_file(follow_symlinks=False):
                    continue

                if is_excluded(str(current_path), exclude_dirs, exclude_exts):
                    skipped_exclude.append(str(current_path))
                    continue

                stat_obj = de.stat(follow_symlinks=False)
                if stat_obj.st_size < min_size:
                    continue

                if is_hardlink(str(current_path)):
                    skipped_hardlink.append(str(current_path))
                    continue

                if is_file_locked(str(current_path)):
                    skipped_locked.append(str(current_path))
                    continue

                special_hit, special_reason = _is_social_cache_scope(current_path)
                rule_hit = _match_rules_by_mode(current_path, rules, mode)
                if not rule_hit and not special_hit:
                    continue

                companions = _find_companions(current_path, companion_exts)
                companion_paths = [str(c) for c in companions]

                # 依赖关联文件必须整组处理；有一个不安全就整体跳过。
                group_safe = True
                for companion in companions:
                    c_str = str(companion)
                    if is_excluded(c_str, exclude_dirs, exclude_exts):
                        skipped_exclude.append(c_str)
                        group_safe = False
                    elif is_hardlink(c_str):
                        skipped_hardlink.append(c_str)
                        group_safe = False
                    elif is_file_locked(c_str):
                        skipped_locked.append(c_str)
                        group_safe = False

                if not group_safe:
                    skipped_exclude.append(str(current_path))
                    continue

                fingerprint = compute_fingerprint(str(current_path))
                is_dup = fingerprint in fingerprint_seen
                fingerprint_seen.add(fingerprint)

                candidate = FileEntry(
                    path=str(current_path),
                    long_path=make_long_path(str(current_path)),
                    size_bytes=stat_obj.st_size,
                    fingerprint=fingerprint,
                    rule_matched=rule_hit or f"special_scope:{special_reason}",
                    is_duplicate=is_dup,
                    companion_files=companion_paths,
                    skip_zip=stat_obj.st_size > int(3.9 * 1024 * 1024 * 1024),
                )
                candidates.append(candidate)
                estimated_free_bytes += candidate.size_bytes

                for companion in companions:
                    try:
                        c_fp = compute_fingerprint(str(companion))
                        c_stat = companion.stat()
                        c_dup = c_fp in fingerprint_seen
                        fingerprint_seen.add(c_fp)
                        candidates.append(
                            FileEntry(
                                path=str(companion),
                                long_path=make_long_path(str(companion)),
                                size_bytes=c_stat.st_size,
                                fingerprint=c_fp,
                                rule_matched="companion_of:" + current_path.name,
                                is_duplicate=c_dup,
                                companion_files=[str(current_path)],
                                skip_zip=c_stat.st_size > int(3.9 * 1024 * 1024 * 1024),
                            )
                        )
                        estimated_free_bytes += c_stat.st_size
                    except (PermissionError, OSError):
                        skipped_permission.append(str(companion))
            except (PermissionError, OSError):
                skipped_permission.append(str(current_path))
                continue

    if progress_callback:
        progress_callback(total_scanned)

    quarantine_dir = Path(config.get("quarantine_dir", "")) if config.get("quarantine_dir") else None
    current_quarantine_bytes = _dir_size_bytes(quarantine_dir) if quarantine_dir else 0

    return {
        "candidates": candidates,
        "skipped_permission": sorted(set(skipped_permission)),
        "skipped_locked": sorted(set(skipped_locked)),
        "skipped_hardlink": sorted(set(skipped_hardlink)),
        "skipped_exclude": sorted(set(skipped_exclude)),
        "total_scanned": total_scanned,
        "estimated_free_bytes": estimated_free_bytes,
        "space_panel": {
            "immediate_free_bytes": estimated_free_bytes,
            "after_delete_quarantine_bytes": estimated_free_bytes,
            "current_quarantine_bytes": current_quarantine_bytes,
        },
    }


def _is_recommended_cache_file(path: Path) -> tuple[bool, str]:
    ext = path.suffix.lower()
    lowered = str(path).lower().replace("/", "\\")

    ext_hits = {
        ".dat": "wechat_or_qq_cache_ext",
        ".idx": "wechat_cache_idx",
        ".msg": "wechat_msg_cache",
        ".db-wal": "qq_db_wal",
        ".db-shm": "qq_db_shm",
        ".tmp": "temp_cache",
    }
    if ext in ext_hits:
        return True, ext_hits[ext]

    keyword_rules = [
        ("msgattach", "wechat_msgattach"),
        ("filestorage\\cache", "wechat_filestorage_cache"),
        ("image_cache", "qq_image_cache"),
        ("\\temp\\", "qq_temp_dir"),
    ]
    for kw, reason in keyword_rules:
        if kw in lowered:
            return True, reason

    return False, ""


def scan_recommended_directory(
    target_dir: str,
    rules: dict,
    config: dict,
    progress_callback: Callable[[int], None] | None = None,
) -> dict:
    """推荐压缩：基于标准规则扫描，并追加 IM 缓存特征候选。"""
    local_config = dict(config)
    local_config["cleanup_mode"] = "standard"
    base = scan_directory(target_dir, rules, local_config, progress_callback=progress_callback)

    candidates: list[FileEntry] = list(base.get("candidates", []))
    skipped_permission: list[str] = list(base.get("skipped_permission", []))
    skipped_locked: list[str] = list(base.get("skipped_locked", []))
    skipped_hardlink: list[str] = list(base.get("skipped_hardlink", []))
    skipped_exclude: list[str] = list(base.get("skipped_exclude", []))
    estimated_free_bytes = int(base.get("estimated_free_bytes", 0))
    total_scanned = int(base.get("total_scanned", 0))

    exclude_dirs = local_config.get("exclude_dirs", [])
    exclude_exts = local_config.get("exclude_extensions", [])
    min_size = int(local_config.get("min_file_size_kb", 0)) * 1024

    root = Path(os.path.expandvars(target_dir))
    if not root.exists() or not root.is_dir():
        return base

    seen_paths = {str(getattr(c, "path", "")).lower() for c in candidates}
    seen_fp = {str(getattr(c, "fingerprint", "")).lower() for c in candidates}

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(make_long_path(str(current))) as it:
                entries = list(it)
        except (PermissionError, OSError):
            skipped_permission.append(str(current))
            continue

        for de in entries:
            current_path = Path(current, de.name)
            total_scanned += 1
            if progress_callback and total_scanned % 500 == 0:
                progress_callback(total_scanned)

            try:
                if de.is_dir(follow_symlinks=False):
                    if not is_excluded(str(current_path), exclude_dirs, exclude_exts):
                        stack.append(current_path)
                    else:
                        skipped_exclude.append(str(current_path))
                    continue

                if not de.is_file(follow_symlinks=False):
                    continue

                norm = str(current_path).lower()
                if norm in seen_paths:
                    continue

                if is_excluded(str(current_path), exclude_dirs, exclude_exts):
                    skipped_exclude.append(str(current_path))
                    continue

                stat_obj = de.stat(follow_symlinks=False)
                if stat_obj.st_size < min_size:
                    continue

                if is_hardlink(str(current_path)):
                    skipped_hardlink.append(str(current_path))
                    continue

                if is_file_locked(str(current_path)):
                    skipped_locked.append(str(current_path))
                    continue

                special_hit, special_reason = _is_social_cache_scope(current_path)
                hit, reason = _is_recommended_cache_file(current_path)
                if not hit and not special_hit:
                    continue

                fp = compute_fingerprint(str(current_path))
                if fp.lower() in seen_fp:
                    continue

                seen_fp.add(fp.lower())
                seen_paths.add(norm)
                candidates.append(
                    FileEntry(
                        path=str(current_path),
                        long_path=make_long_path(str(current_path)),
                        size_bytes=stat_obj.st_size,
                        fingerprint=fp,
                        rule_matched=f"recommended:{reason}" if hit else f"special_scope:{special_reason}",
                        is_duplicate=False,
                        companion_files=[],
                        skip_zip=stat_obj.st_size > int(3.9 * 1024 * 1024 * 1024),
                    )
                )
                estimated_free_bytes += stat_obj.st_size
            except (PermissionError, OSError):
                skipped_permission.append(str(current_path))
                continue

    if progress_callback:
        progress_callback(total_scanned)

    panel = dict(base.get("space_panel", {}))
    panel["immediate_free_bytes"] = estimated_free_bytes
    panel["after_delete_quarantine_bytes"] = estimated_free_bytes

    return {
        "candidates": candidates,
        "skipped_permission": sorted(set(skipped_permission)),
        "skipped_locked": sorted(set(skipped_locked)),
        "skipped_hardlink": sorted(set(skipped_hardlink)),
        "skipped_exclude": sorted(set(skipped_exclude)),
        "total_scanned": total_scanned,
        "estimated_free_bytes": estimated_free_bytes,
        "space_panel": panel,
    }
