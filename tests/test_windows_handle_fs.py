"""Windows-only tests for the limited handle-bound storage primitives."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from app.security.windows_handle_fs import (
    HeldSessionLock,
    VerifiedDirectoryChain,
    WindowsHandleFilesystemError,
    is_available,
)


@unittest.skipUnless(is_available(), "Windows handle primitives require Windows")
class WindowsHandleFilesystemTests(unittest.TestCase):
    def test_retained_root_handle_keeps_original_identity_after_path_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "root"
            root.mkdir()
            with VerifiedDirectoryChain.open(root) as guard:
                root.rename(parent / "replacement")
                guard.verify_root_identity()
                self.assertFalse(root.exists())
                self.assertTrue((parent / "replacement").is_dir())

    def test_held_lock_blocks_rename_and_is_deleted_by_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_path = root / ".session-001.live-flow.lock"
            lock = HeldSessionLock.create(lock_path, "a" * 32)
            try:
                with self.assertRaises(PermissionError):
                    lock_path.rename(root / "replacement.lock")
                with self.assertRaises(PermissionError):
                    lock_path.unlink()
            finally:
                lock.release()
            self.assertFalse(lock_path.exists())

    def test_native_backend_rejects_a_final_reparse_point(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            junction = root / "junction"
            result = os.system(f'cmd /c mklink /J "{junction}" "{target}" >nul 2>nul')
            if result != 0:
                self.skipTest("junction creation is unavailable")
            try:
                with self.assertRaises(WindowsHandleFilesystemError):
                    VerifiedDirectoryChain.open(junction)
            finally:
                os.system(f'cmd /c rmdir "{junction}" >nul 2>nul')
