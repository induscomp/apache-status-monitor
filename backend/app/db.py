from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache
def session_factory() -> sessionmaker[Session]:
    engine = create_engine(get_settings().db_url(), pool_pre_ping=True, pool_size=5, max_overflow=5)
    return sessionmaker(engine, expire_on_commit=False)


def get_db() -> Generator[Session]:
    with session_factory()() as db:
        yield db
