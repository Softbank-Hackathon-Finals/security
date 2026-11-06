"""Owned private DB only: SELECT reader must not create temporary/large objects."""

import secrets
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database

database = isolated_database
pytestmark = pytest.mark.postgres


@pytest.mark.xfail(strict=True, reason="Reproduction: PUBLIC TEMP/large-object creators remain available to SELECT reader")
@pytest.mark.parametrize("operation", [
    "CREATE TEMP TABLE owned_storage_probe(value integer)",
    "SELECT pg_catalog.lo_create(0)",
    "SELECT pg_catalog.lo_creat(-1)",
    "SELECT pg_catalog.lo_from_bytea(0, decode('01','hex'))",
])
def test_select_reader_cannot_allocate_temp_or_large_objects(database, scope, operation):
    import psycopg
    from psycopg import sql
    from sova_security.adapters.review_database import reader_statements, require_reader

    dsn, _, _ = database
    role, password = "storage_reader_" + uuid4().hex, secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=role, tenant_id=scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    try:
        # A stolen login can omit the application's read-only connection option.
        # One tiny owned object only; failure inside the context rolls it back.
        with psycopg.connect(dsn, user=role, password=password) as connection:
            require_reader(connection, tenant_id=scope.tenant_id)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(operation)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
