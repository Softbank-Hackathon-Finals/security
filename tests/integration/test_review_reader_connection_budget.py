"""Sequential role capacity checks in the exact owned private PostgreSQL fixture."""

from contextlib import ExitStack
import secrets
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database

database = isolated_database
pytestmark = pytest.mark.postgres


@pytest.fixture
def bounded_reader(database, scope):
    import psycopg
    from psycopg import sql
    from sova_security.adapters.review_database import reader_statements

    dsn, _, _ = database
    role, password = "budget_reader_" + uuid4().hex, secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=role, tenant_id=scope.tenant_id, connection_limit=2):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    try:
        yield dsn, role, password
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_raw_reader_connection_capacity_is_limited_and_recovers(bounded_reader, scope):
    import psycopg
    from sova_security.adapters.review_database import require_reader

    dsn, role, password = bounded_reader
    with ExitStack() as stack:
        for _ in range(2):
            connection = stack.enter_context(psycopg.connect(dsn, user=role, password=password, connect_timeout=2))
            require_reader(connection, tenant_id=scope.tenant_id)
        with pytest.raises(psycopg.OperationalError, match="too many connections for role"):
            psycopg.connect(dsn, user=role, password=password, connect_timeout=2)
        # An unrelated login retains capacity; this does not certify global load.
        with psycopg.connect(dsn) as admin:
            assert admin.execute("SELECT 1").fetchone() == (1,)
    with psycopg.connect(dsn, user=role, password=password, connect_timeout=2) as connection:
        require_reader(connection, tenant_id=scope.tenant_id)
        assert connection.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.parametrize("limit", [-1, 0, 65])
def test_existing_reader_session_rejects_connection_limit_drift(bounded_reader, scope, limit):
    import psycopg
    from psycopg import sql
    from sova_security.adapters.review_database import require_reader
    from sova_security.contracts.commands import ContractError

    dsn, role, password = bounded_reader
    with psycopg.connect(dsn, user=role, password=password) as connection:
        require_reader(connection, tenant_id=scope.tenant_id)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("ALTER ROLE {} CONNECTION LIMIT {}").format(sql.Identifier(role), sql.Literal(limit)))
        with pytest.raises(ContractError):
            require_reader(connection, tenant_id=scope.tenant_id)
