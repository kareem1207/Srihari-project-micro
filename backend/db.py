from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from . import config

_engine = None
_Session = None


def init_engine(url: str | None = None):
    global _engine, _Session
    url = url or config.database_url()
    if url.startswith("sqlite:///") and not url.endswith(":memory:"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {"pool_pre_ping": True}
    if url.endswith(":memory:"):
        from sqlalchemy.pool import StaticPool
        kw["poolclass"] = StaticPool
    _engine = create_engine(url, **kw)
    _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    from .models import Base
    Base.metadata.create_all(_engine)  # schema initialisation (see db/schema.sql for PostgreSQL DDL)
    return _engine


def get_db():
    if _Session is None:
        init_engine()
    s = _Session()
    try:
        yield s
    finally:
        s.close()


def session() -> "sessionmaker":
    if _Session is None:
        init_engine()
    return _Session
