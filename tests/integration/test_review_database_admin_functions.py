"""Owned database only: privileged builtin grants must not escape the reader."""

import secrets
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database
from sova_security.contracts.commands import ContractError

database = isolated_database
pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("grant_to", ["role", "public"])
def test_reader_refuses_newly_granted_server_file_function(database, scope, grant_to):
    import psycopg
    from psycopg import sql
    from sova_security.adapters.review_database import reader_statements, require_reader

    dsn, _, _ = database
    role, password = "review_builtin_" + uuid4().hex, secrets.token_urlsafe(32)
    recipient = sql.Identifier(role) if grant_to == "role" else sql.SQL("PUBLIC")
    grant = sql.SQL("GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO {}").format(recipient)
    revoke = sql.SQL("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM {}").format(recipient)
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=role, tenant_id=scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    try:
        with psycopg.connect(dsn, user=role, password=password, autocommit=True) as reader:
            require_reader(reader, tenant_id=scope.tenant_id)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                reader.execute("SELECT pg_catalog.pg_read_file('PG_VERSION')")
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(grant)
            # Read only this disposable cluster's public major-version file.
            # No config, credentials, user records, or host files are accessed.
            major = reader.execute("SELECT pg_catalog.pg_read_file('PG_VERSION')").fetchone()[0].strip()
            assert major == str(reader.info.server_version // 10000)
            with pytest.raises(ContractError):
                require_reader(reader, tenant_id=scope.tenant_id)
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(revoke)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                reader.execute("SELECT pg_catalog.pg_read_file('PG_VERSION')")
            require_reader(reader, tenant_id=scope.tenant_id)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(revoke)
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
