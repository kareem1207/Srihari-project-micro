"""Admin CLI: create the first user. Password is read from the terminal or env var."""
import argparse
import getpass
import os

from .db import init_engine, session
from .models import User
from .security import ROLES, hash_password


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("username")
    ap.add_argument("--role", choices=ROLES, default="admin")
    a = ap.parse_args()
    pw = os.getenv("SECUREWORK_NEW_PASSWORD") or getpass.getpass("Password (min 10 chars): ")
    if len(pw) < 10:
        raise SystemExit("Password too short")
    init_engine()
    with session()() as db:
        if db.query(User).filter_by(username=a.username).first():
            raise SystemExit("User already exists")
        db.add(User(username=a.username, password_hash=hash_password(pw), role=a.role))
        db.commit()
    print(f"Created {a.role} '{a.username}'")


if __name__ == "__main__":
    main()
