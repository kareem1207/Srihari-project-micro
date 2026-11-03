"""Tests for the opt-in synthetic disposable-directory storage validation harness."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.security.storage_validation_harness import (
    StorageValidationError,
    _assert_root_unchanged,
    _path_identity,
    _remove_harness_lock,
    _remove_harness_receipt,
    main,
    run_storage_validation,
)


class StorageValidationHarnessTests(unittest.TestCase):
    def make_target(self, parent: Path) -> Path:
        target = parent / ".securework-storage-validation-0123456789abcdef0123456789abcdef"
        target.mkdir()
        return target

    def test_requires_explicit_empty_disposable_directory_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = self.make_target(Path(temporary))
            with self.assertRaises(StorageValidationError):
                run_storage_validation(target)
            (target / "existing.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaises(StorageValidationError):
                run_storage_validation(target, confirm_disposable=True)
            self.assertEqual((target / "existing.txt").read_text(encoding="utf-8"), "preserve")

    def test_synthetic_validation_cleans_only_its_expected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = self.make_target(Path(temporary))
            result = run_storage_validation(target, confirm_disposable=True)
            self.assertEqual(result.validation_directory, str(target))
            self.assertIn("existing-session collision rejection", result.verified_checks)
            self.assertIn("publish interruption via injected directory rename failure", result.simulated_checks)
            self.assertFalse(list(target.iterdir()))

    def test_rejects_missing_ambiguous_and_project_targets(self) -> None:
        relative_target = Path(".securework-storage-validation-0123456789abcdef0123456789abcdef")
        with self.assertRaisesRegex(StorageValidationError, "explicit absolute path"):
            run_storage_validation(relative_target, confirm_disposable=True)

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            missing = parent / ".securework-storage-validation-0123456789abcdef0123456789abcdef"
            with self.assertRaises(StorageValidationError):
                run_storage_validation(missing, confirm_disposable=True)
            wrong_name = parent / "validation"
            wrong_name.mkdir()
            with self.assertRaises(StorageValidationError):
                run_storage_validation(wrong_name, confirm_disposable=True)
        with self.assertRaises(StorageValidationError):
            run_storage_validation(Path.cwd(), confirm_disposable=True)

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows-only test")
    def test_rejects_disposable_child_beneath_an_ancestor_junction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            backing = parent / "backing"
            backing.mkdir()
            junction = parent / "junction"
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(backing)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            try:
                target = self.make_target(junction)
                with self.assertRaises(StorageValidationError):
                    run_storage_validation(target, confirm_disposable=True)
            finally:
                subprocess.run(["cmd", "/c", "rmdir", str(junction)], check=False, capture_output=True)

    def test_detects_regular_root_replacement_before_a_later_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = self.make_target(parent)
            identity = _path_identity(target)
            target.rename(parent / "replaced-original")
            target.mkdir()
            with self.assertRaises(StorageValidationError):
                _assert_root_unchanged(target, identity)

    def test_replacement_lock_or_receipt_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / ".test.live-flow.lock"
            lock.write_text("owner", encoding="ascii")
            lock_identity = _path_identity(lock)
            lock.unlink()
            lock.write_text("replacement", encoding="ascii")
            with self.assertRaises(StorageValidationError):
                _remove_harness_lock(lock, lock_identity, "owner")
            self.assertEqual(lock.read_text(encoding="ascii"), "replacement")

            receipt = root / "receipt.json"
            receipt.write_text('{"session_id": "session-001", "verification": "session_directory_absent"}', encoding="utf-8")
            receipt_identity = _path_identity(receipt)
            receipt.unlink()
            receipt.write_text('{"session_id": "replacement", "verification": "session_directory_absent"}', encoding="utf-8")
            with self.assertRaises(StorageValidationError):
                _remove_harness_receipt(receipt, receipt_identity, "session-001")
            self.assertIn("replacement", receipt.read_text(encoding="utf-8"))

    def test_cli_refuses_to_run_without_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = self.make_target(Path(temporary))
            output = io.StringIO()
            with patch.object(sys, "argv", ["storage_validation_harness", "--validation-dir", str(target)]):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(), 1)
            self.assertIn("Refusing to run without explicit disposable-target confirmation", output.getvalue())
