"""Tests for explicit local Argon2id authentication storage."""
from __future__ import annotations

import json
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.security.auth import (
    AccountStorageError,
    AccountStoreStatus,
    LocalAccountStore,
    account_store_status,
    authenticate,
)


class LocalAccountStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.store = LocalAccountStore(Path(self.temporary_directory.name) / "accounts.json")
        self.username = f"user-{secrets.token_hex(8)}"
        self.password = secrets.token_urlsafe(24)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_correct_password_authenticates_without_plaintext_storage(self) -> None:
        self.store.provision(self.username, self.password)

        self.assertTrue(authenticate(self.username, self.password, account_store=self.store))
        document = self.store.path.read_text(encoding="utf-8")
        self.assertNotIn(self.password, document)
        self.assertIn("argon2id", document)

    def test_incorrect_password_is_rejected(self) -> None:
        self.store.provision(self.username, self.password)

        self.assertFalse(authenticate(self.username, secrets.token_urlsafe(24), account_store=self.store))

    def test_missing_account_store_and_unknown_account_fail_closed(self) -> None:
        self.assertEqual(account_store_status(account_store=self.store), AccountStoreStatus.MISSING)
        self.assertFalse(authenticate(self.username, self.password, account_store=self.store))

        self.store.provision(self.username, self.password)
        self.assertFalse(authenticate(f"user-{secrets.token_hex(8)}", self.password, account_store=self.store))

    def test_malformed_hash_is_rejected(self) -> None:
        self.store.path.write_text(
            json.dumps({"version": 1, "accounts": {self.username: {"password_hash": "not-a-valid-hash"}}}),
            encoding="utf-8",
        )

        self.assertFalse(authenticate(self.username, self.password, account_store=self.store))
        self.assertEqual(account_store_status(account_store=self.store), AccountStoreStatus.UNAVAILABLE)

    def test_storage_failure_fails_closed(self) -> None:
        self.store.provision(self.username, self.password)
        with patch.object(self.store, "_load_accounts", side_effect=AccountStorageError("unavailable")):
            self.assertFalse(authenticate(self.username, self.password, account_store=self.store))
            self.assertEqual(account_store_status(account_store=self.store), AccountStoreStatus.UNAVAILABLE)
