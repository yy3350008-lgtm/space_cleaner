from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import main
import ui
from scanner import scan_recommended_directory
from safety import atomic_save_json
from safety import build_extreme_release_plan


class UsbPlanRequirementsTest(unittest.TestCase):
    def test_scan_progress_invocation_no_typeerror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "a.tmp"
            sample.write_bytes(b"123")

            rules = {
                "modes": {"standard": ["target_extensions"]},
                "target_extensions": [".tmp"],
                "name_patterns": [],
                "suffix_patterns": [],
                "log_extensions": [],
                "companion_extensions": [],
            }
            config = {
                "cleanup_mode": "standard",
                "exclude_dirs": [],
                "exclude_extensions": [],
                "min_file_size_kb": 0,
                "quarantine_dir": str(root / "q"),
            }

            result = ui.run_scanner_with_progress(
                scan_recommended_directory,
                str(root),
                rules,
                config,
            )
            self.assertIsInstance(result, dict)
            self.assertIn("candidates", result)

    def test_scan_progress_raises_worker_exceptions(self) -> None:
        def broken_scan(*args, **kwargs):
            raise PermissionError("no access")

        with self.assertRaises(PermissionError):
            ui.run_scanner_with_progress(broken_scan, "x", {}, {})

    def test_menu_is_merged_to_smart_scan(self) -> None:
        source = Path(ui.__file__).read_text(encoding="utf-8")
        self.assertIn("智能扫描并建议压缩", source)
        self.assertNotIn("自动扫描推荐文件", source)
        self.assertNotIn("推荐压缩当前目录", source)

    def test_custom_selection_uses_folder_dialog(self) -> None:
        source = Path(ui.__file__).read_text(encoding="utf-8")
        self.assertIn("askdirectory", source)

    def test_extreme_release_requires_archived_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state = {
                "session_id": "s1",
                "created_at": "2026-01-01T00:00:00",
                "entries": [
                    {
                        "original_path": "C:/a.tmp",
                        "quarantine_path": str(Path(tmp) / "q.tmp"),
                        "fingerprint": "fp1",
                        "status": "quarantined",
                    }
                ],
            }
            atomic_save_json(state, str(state_path))

            plan = build_extreme_release_plan(str(state_path), max_state_age_seconds=3600)
            blockers = set(plan.get("blockers", []))
            self.assertIn("no_archived_entries", blockers)

    def test_recommended_scan_hits_common_temp_installer_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            samples = [
                root / "MySetupTool.exe",
                root / "VendorInstaller.msi",
                root / "ChromeSetup.exe",
                root / "cache.tmp",
                root / "activity.log",
                root / "backup.old",
                root / "MsgAttach" / "mail.dat",
                root / "FileStorage" / "cache" / "thumb.bin",
                root / "Image_Cache" / "preview.dat",
            ]
            for sample in samples:
                sample.parent.mkdir(parents=True, exist_ok=True)
                sample.write_bytes(b"sample-data")

            rules = json.loads((Path(__file__).resolve().parents[1] / "rules" / "builtin_rules.json").read_text(encoding="utf-8"))
            config = {
                "cleanup_mode": "standard",
                "exclude_dirs": [],
                "exclude_extensions": [],
                "min_file_size_kb": 0,
                "quarantine_dir": str(root / "q"),
            }

            result = scan_recommended_directory(str(root), rules, config)
            names = {Path(item.path).name for item in result.get("candidates", [])}

            expected = {
                "MySetupTool.exe",
                "VendorInstaller.msi",
                "ChromeSetup.exe",
                "cache.tmp",
                "activity.log",
                "backup.old",
                "mail.dat",
                "thumb.bin",
                "preview.dat",
            }
            self.assertTrue(expected.issubset(names))

    def test_missing_quarantine_files_are_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            missing_q = root / "gone.bin"
            state = {
                "session_id": "s1",
                "created_at": "2026-01-01T00:00:00",
                "entries": [
                    {
                        "original_path": "C:/gone.bin",
                        "quarantine_path": str(missing_q),
                        "fingerprint": "fp2",
                        "status": "quarantined",
                    }
                ],
            }
            atomic_save_json(state, str(state_path))

            from safety import reconcile_missing_quarantine_entries

            result = reconcile_missing_quarantine_entries(str(state_path))
            self.assertEqual(result.get("changed"), 1)
            updated = json.loads(state_path.read_text(encoding="utf-8-sig"))
            self.assertEqual(updated["entries"][0]["status"], "missing")

    def test_history_restore_ui_has_multi_select_and_full_restore(self) -> None:
        source = Path(main.__file__).read_text(encoding="utf-8")
        self.assertIn("questionary.checkbox", source)
        self.assertIn("完全恢复", source)
        self.assertIn("确认恢复", source)


if __name__ == "__main__":
    unittest.main()
