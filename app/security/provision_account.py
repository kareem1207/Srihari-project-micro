"""Explicit local-account provisioning command for SecureWork AI."""
from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from app.security.auth import DEFAULT_ACCOUNT_STORE, AccountProvisioningError, AccountStorageError, LocalAccountStore


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision a local SecureWork AI account.")
    parser.add_argument("--store", type=Path, default=DEFAULT_ACCOUNT_STORE, help="Explicit local account-store path.")
    parser.add_argument("--username", help="Local username. If omitted, it is requested interactively.")
    arguments = parser.parse_args()

    username = arguments.username or input("Username: ").strip()
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.")
        return 2

    try:
        LocalAccountStore(arguments.store).provision(username, password)
    except (AccountProvisioningError, AccountStorageError) as exc:
        print(f"Account provisioning failed: {exc}")
        return 1
    print("Local account provisioned. Keep the account-store file protected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
