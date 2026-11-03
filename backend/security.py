"""Password hashing (Argon2id), JWT tokens, role-based access control."""
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import User

_ph = PasswordHasher()
_bearer = HTTPBearer(auto_error=False)
ROLES = ("admin", "analyst", "agent")


def hash_password(p: str) -> str:
    return _ph.hash(p)


def verify_password(h: str, p: str) -> bool:
    try:
        return _ph.verify(h, p)
    except (VerifyMismatchError, Exception):
        return False


def make_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=config.JWT_MINUTES)
    return jwt.encode({"sub": user.username, "role": user.role, "exp": exp}, config.jwt_secret(), "HS256")


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(_bearer),
                 db: Session = Depends(get_db)) -> User:
    if not cred:
        raise HTTPException(401, "Authentication required")
    try:
        data = jwt.decode(cred.credentials, config.jwt_secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.query(User).filter_by(username=data["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(401, "Unknown or disabled account")
    return user


def require(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient role")
        return user
    return dep
