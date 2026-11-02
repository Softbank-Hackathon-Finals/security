"""Package-only PostgreSQL: no Sova schema or lifecycle implementation."""

from dataclasses import replace
from datetime import UTC, datetime
import os
import secrets
from uuid import uuid4

import pytest

from bravo_security.contracts.commands import ContractError
from bravo_security.contracts.repositories import RecordNotFound
from bravo_security.domain.governance import SecurityHold
from bravo_security.migrations import MIGRATIONS, migration_sql

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def database():
    dsn = os.environ.get("BRAVO_SECURITY_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("Explicit isolated BRAVO_SECURITY_TEST_POSTGRES_DSN required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql

    role = "security_test_" + uuid4().hex
    password = secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert admin.execute(
            "SELECT current_setting('cluster_name'),current_database()"
        ).fetchone() == ("bravo-security-test", "bravo_security_test")
        admin.execute("CREATE SCHEMA IF NOT EXISTS sova_control")
        for name in MIGRATIONS:
            admin.execute(migration_sql(name))
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD {}"
            ).format(sql.Identifier(role), sql.Literal(password))
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        admin.execute(
            sql.SQL(
                "GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA sova_control TO {}"
            ).format(sql.Identifier(role))
        )
    try:
        yield dsn, role, password
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_runtime_tenant_visibility_and_append_only_rights(database, scope):
    import psycopg
    from bravo_security.adapters.postgres_governance import PostgresSecurityHolds

    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    first = PostgresSecurityHolds(connect, tenant_id=scope.tenant_id)
    hold = SecurityHold(
        uuid4().hex, scope, "detector", "controlled-test", datetime.now(UTC)
    )
    assert first.open_hold(hold).hold == hold
    assert first.get_hold(scope.application_id, hold.hold_id).active
    second = PostgresSecurityHolds(connect, tenant_id="tenant-b")
    with pytest.raises(RecordNotFound):
        second.get_hold(scope.application_id, hold.hold_id)
    assert second.active_holds(scope.application_id) == ()
    with pytest.raises(ContractError):
        first.open_hold(replace(hold, scope=replace(scope, tenant_id="tenant-b")))
    with connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM sova_control.security_hold_events")


def test_privileged_connection_cannot_be_runtime(database, scope):
    import psycopg
    from bravo_security.adapters.postgres_session import ScopedPostgresSession

    dsn, _, _ = database
    session = ScopedPostgresSession(
        lambda: psycopg.connect(dsn), tenant_id=scope.tenant_id
    )
    with pytest.raises(ContractError, match="must not own or bypass"):
        with session.transaction():
            pytest.fail("Admin transaction must never be admitted")


def test_public_tables_never_need_host_operations_schema(database):
    import psycopg

    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT to_regclass('sova_control.operations')"
        ).fetchone() == (None,)
