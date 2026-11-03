"""Narrow Windows handle primitives for SecureWork's offline exporter.

Only the operations in this module are handle-bound.  It deliberately does not
offer path-based recursive deletion or publication helpers: those require a
directory-handle-relative implementation that Python's standard library does
not expose safely.
"""
from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path


class WindowsHandleFilesystemError(RuntimeError):
    """A verified Windows handle operation could not be completed safely."""


@dataclass(frozen=True)
class WindowsFileIdentity:
    volume_serial: int
    file_id: bytes


if os.name == "nt":
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _DELETE = 0x00010000
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FSCTL_GET_REPARSE_POINT = 0x000900A8
    _FILE_ID_INFO_CLASS = 18
    _FILE_DISPOSITION_INFO_CLASS = 4
    _ERROR_FILE_EXISTS = 80
    _ERROR_ALREADY_EXISTS = 183

    class _FILE_ID_128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_byte * 16)]

    class _FILE_ID_INFO(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", _FILE_ID_128),
        ]

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("CreationTimeLow", wintypes.DWORD),
            ("CreationTimeHigh", wintypes.DWORD),
            ("LastAccessTimeLow", wintypes.DWORD),
            ("LastAccessTimeHigh", wintypes.DWORD),
            ("LastWriteTimeLow", wintypes.DWORD),
            ("LastWriteTimeHigh", wintypes.DWORD),
            ("VolumeSerialNumber", wintypes.DWORD),
            ("FileSizeHigh", wintypes.DWORD),
            ("FileSizeLow", wintypes.DWORD),
            ("NumberOfLinks", wintypes.DWORD),
            ("FileIndexHigh", wintypes.DWORD),
            ("FileIndexLow", wintypes.DWORD),
        ]

    class _FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    _kernel32.DeviceIoControl.restype = wintypes.BOOL
    _kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    _kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL


def is_available() -> bool:
    return os.name == "nt"


def _require_windows() -> None:
    if os.name != "nt":
        raise WindowsHandleFilesystemError("Windows handle operations are unavailable on this platform.")


def _raise_last_error(action: str) -> None:
    error = ctypes.get_last_error()
    raise WindowsHandleFilesystemError(f"{action} failed with Windows error {error}.")


def _close(handle: int) -> None:
    if not _kernel32.CloseHandle(handle):
        _raise_last_error("CloseHandle")


def _identity(handle: int) -> WindowsFileIdentity:
    info = _FILE_ID_INFO()
    if not _kernel32.GetFileInformationByHandleEx(
        handle, _FILE_ID_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)
    ):
        _raise_last_error("GetFileInformationByHandleEx(FileIdInfo)")
    return WindowsFileIdentity(info.VolumeSerialNumber, bytes(info.FileId.Identifier))


def _attributes(handle: int) -> int:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        _raise_last_error("GetFileInformationByHandle")
    return int(info.FileAttributes)


def _reject_reparse_point(handle: int) -> None:
    if not (_attributes(handle) & _FILE_ATTRIBUTE_REPARSE_POINT):
        return
    # Reading the tag is intentional: fail closed if Windows cannot inspect it.
    output = ctypes.create_string_buffer(16 * 1024)
    returned = wintypes.DWORD()
    if not _kernel32.DeviceIoControl(
        handle, _FSCTL_GET_REPARSE_POINT, None, 0, output, len(output), ctypes.byref(returned), None
    ):
        _raise_last_error("DeviceIoControl(FSCTL_GET_REPARSE_POINT)")
    raise WindowsHandleFilesystemError("Reparse-point paths are not supported for SecureWork exports.")


def _open_directory(path: Path) -> int:
    handle = _kernel32.CreateFileW(
        str(path),
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        _raise_last_error(f"CreateFileW({path})")
    return handle


class VerifiedDirectoryChain:
    """Retains a non-delete-shared handle to a verified output root.

    Ancestor inspection remains path-based in this increment because opening
    every ancestor can require permissions that an otherwise valid output-root
    operator does not hold. A future native helper must provide directory-handle
    relative traversal for complete ancestor binding. Windows does not provide a
    portable guarantee here that retaining this directory handle blocks rename,
    so callers must not treat it as a mutation-safe root capability.
    """

    def __init__(self, path: Path, handles: list[int], identity: WindowsFileIdentity) -> None:
        self.path = path
        self._handles = handles
        self.identity = identity

    @classmethod
    def open(cls, path: str | Path) -> "VerifiedDirectoryChain":
        _require_windows()
        absolute = Path(path).absolute()
        if not absolute.is_absolute() or not absolute.is_dir():
            raise WindowsHandleFilesystemError("Output root must be an existing absolute directory.")
        handles: list[int] = []
        try:
            handle = _open_directory(absolute)
            handles.append(handle)
            _reject_reparse_point(handle)
            return cls(absolute, handles, _identity(handle))
        except Exception:
            for handle in reversed(handles):
                try:
                    _close(handle)
                except WindowsHandleFilesystemError:
                    pass
            raise

    def verify_root_identity(self) -> None:
        if _identity(self._handles[-1]) != self.identity:
            raise WindowsHandleFilesystemError("Output-root handle identity changed unexpectedly.")

    def close(self) -> None:
        errors: list[WindowsHandleFilesystemError] = []
        for handle in reversed(self._handles):
            try:
                _close(handle)
            except WindowsHandleFilesystemError as exc:
                errors.append(exc)
        self._handles.clear()
        if errors:
            raise errors[0]

    def __enter__(self) -> "VerifiedDirectoryChain":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


class HeldSessionLock:
    """A create-new lock whose active handle denies competing delete/write opens."""

    def __init__(self, path: Path, handle: int, identity: WindowsFileIdentity) -> None:
        self.path = path
        self._handle = handle
        self.identity = identity

    @classmethod
    def create(cls, path: str | Path, owner_token: str) -> "HeldSessionLock":
        _require_windows()
        lock_path = Path(path)
        handle = _kernel32.CreateFileW(
            str(lock_path),
            _GENERIC_READ | _GENERIC_WRITE | _DELETE,
            _FILE_SHARE_READ,
            None,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if error in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
                raise FileExistsError(str(lock_path))
            raise WindowsHandleFilesystemError(f"CreateFileW({lock_path}) failed with Windows error {error}.")
        try:
            _reject_reparse_point(handle)
            data = owner_token.encode("ascii")
            written = wintypes.DWORD()
            buffer = ctypes.create_string_buffer(data)
            if not _kernel32.WriteFile(handle, buffer, len(data), ctypes.byref(written), None) or written.value != len(data):
                _raise_last_error("WriteFile(session lock)")
            return cls(lock_path, handle, _identity(handle))
        except Exception:
            try:
                _close(handle)
            except WindowsHandleFilesystemError:
                pass
            raise

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            if _identity(self._handle) != self.identity:
                raise WindowsHandleFilesystemError("Session-lock handle identity changed unexpectedly.")
            disposition = _FILE_DISPOSITION_INFO(True)
            if not _kernel32.SetFileInformationByHandle(
                self._handle,
                _FILE_DISPOSITION_INFO_CLASS,
                ctypes.byref(disposition),
                ctypes.sizeof(disposition),
            ):
                _raise_last_error("SetFileInformationByHandle(FileDispositionInfo)")
        finally:
            handle, self._handle = self._handle, None
            _close(handle)
