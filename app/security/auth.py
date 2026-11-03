"""Local Argon2id authentication with explicit account provisioning.

Passwords are accepted only in memory, passed to ``argon2-cffi`` for hashing
or verification, and are never logged or written to the account document.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ACCOUNT_STORE = PROJECT_ROOT / "data" / "accounts.json"
ACCOUNT_DOCUMENT_VERSION = 1
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
_PASSWORD_HASHER = PasswordHasher()


class AccountStoreStatus(str, Enum):
    """Safe, non-sensitive account-store readiness states for the UI."""

    READY = "ready"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"


class AccountStorageError(RuntimeError):
    """Account storage is missing, malformed, or inaccessible."""


class AccountProvisioningError(ValueError):
    """A requested local-account creation is invalid or unsafe."""


class LocalAccountStore:
    """A local store containing only Argon2 encoded password hashes."""

    def __init__(self, path: str | Path = DEFAULT_ACCOUNT_STORE) -> None:
        self.path = Path(path)

    def status(self) -> AccountStoreStatus:
        """Return a non-sensitive readiness state without repairing storage."""
        if not self.path.exists():
            return AccountStoreStatus.MISSING
        try:
            self._load_accounts()
        except AccountStorageError:
            return AccountStoreStatus.UNAVAILABLE
        return AccountStoreStatus.READY

    def authenticate(self, username: str, password: str) -> bool:
        """Verify a supplied password, failing closed for every storage error."""
        if not _valid_username(username) or not isinstance(password, str) or not password:
            return False
        try:
            accounts = self._load_accounts()
            password_hash = accounts.get(username)
            if password_hash is None:
                return False
            return _PASSWORD_HASHER.verify(password_hash, password)
        except (AccountStorageError, InvalidHashError, VerificationError, VerifyMismatchError):
            return False

    def provision(self, username: str, password: str) -> None:
        """Create one explicitly requested account without storing its password."""
        if not _valid_username(username):
            raise AccountProvisioningError("Username must be 3-64 safe characters.")
        if not isinstance(password, str) or len(password) < 12:
            raise AccountProvisioningError("Password must contain at least 12 characters.")

        if self.path.exists():
            accounts = self._load_accounts()
            if username in accounts:
                raise AccountProvisioningError("That local account already exists.")
        else:
            accounts = {}

        try:
            password_hash = _PASSWORD_HASHER.hash(password)
        except Exception as exc:  # pragma: no cover - library/system failure
            raise AccountStorageError("Password hashing failed.") from exc

        accounts[username] = password_hash
        self._write_accounts(accounts)

    def _load_accounts(self) -> dict[str, str]:
        try:
            raw = self.path.read_text(encoding="utf-8")
            document = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AccountStorageError("Local account storage is unavailable.") from exc

        if not isinstance(document, dict) or set(document) != {"version", "accounts"}:
            raise AccountStorageError("Local account storage is malformed.")
        if document["version"] != ACCOUNT_DOCUMENT_VERSION or not isinstance(document["accounts"], dict):
            raise AccountStorageError("Local account storage is malformed.")

        accounts: dict[str, str] = {}
        for username, entry in document["accounts"].items():
            if not _valid_username(username) or not isinstance(entry, dict) or set(entry) != {"password_hash"}:
                raise AccountStorageError("Local account storage is malformed.")
            password_hash = entry["password_hash"]
            if not isinstance(password_hash, str) or not password_hash:
                raise AccountStorageError("Local account storage is malformed.")
            try:
                extract_parameters(password_hash)
            except InvalidHashError as exc:
                raise AccountStorageError("Local account storage is malformed.") from exc
            accounts[username] = password_hash
        return accounts

    def _write_accounts(self, accounts: dict[str, str]) -> None:
        document: dict[str, Any] = {
            "version": ACCOUNT_DOCUMENT_VERSION,
            "accounts": {username: {"password_hash": password_hash} for username, password_hash in accounts.items()},
        }
        temporary_path: Path | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent, prefix=".accounts-", suffix=".tmp", delete=False
            ) as stream:
                json.dump(document, stream, ensure_ascii=True, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
                temporary_path = Path(stream.name)
            os.replace(temporary_path, self.path)
        except (OSError, TypeError, ValueError) as exc:
            try:
                if temporary_path is not None and temporary_path.exists():
                    temporary_path.unlink()
            except OSError:
                pass
            raise AccountStorageError("Local account storage could not be written.") from exc


def authenticate(username: str, password: str, *, account_store: LocalAccountStore | None = None) -> bool:
    """Authenticate against the explicit local account store, failing closed."""
    return (account_store or LocalAccountStore()).authenticate(username, password)


def account_store_status(*, account_store: LocalAccountStore | None = None) -> AccountStoreStatus:
    """Expose only safe account-store readiness information to the login UI."""
    return (account_store or LocalAccountStore()).status()


def _valid_username(value: object) -> bool:
    return isinstance(value, str) and _USERNAME.fullmatch(value) is not None
