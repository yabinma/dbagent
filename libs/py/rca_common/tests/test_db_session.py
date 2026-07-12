"""Sanity tests for the engine/session-factory helpers. Uses an in-memory
sqlite DSN so no real Postgres is required in the unit tier."""
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from rca_common.db.session import make_engine, make_session_factory


def test_make_engine_returns_engine_bound_to_dsn():
    engine = make_engine("sqlite:///:memory:")
    assert isinstance(engine, Engine)
    assert str(engine.url) == "sqlite:///:memory:"


def test_make_session_factory_produces_working_sessions():
    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    with factory() as session:
        assert isinstance(session, Session)
        assert session.bind is engine
