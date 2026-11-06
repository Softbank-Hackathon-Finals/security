"""Real PostgreSQL indirect privilege paths, entirely synthetic private records."""

from dataclasses import replace
from datetime import UTC, datetime
import secrets
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database
from sova_security.contracts.commands import ContractError

database = isolated_database
pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("path", ["public-definer", "public-view"])
def test_reader_detects_and_operator_removes_indirect_cross_tenant_read(database, scope, path):
    import psycopg
    from psycopg import sql
    from sova_security.adapters.postgres_governance import PostgresSecurityHolds
    from sova_security.adapters.review_database import reader_statements, require_reader
    from sova_security.domain.governance import SecurityHold

    dsn, registrar, password = database
    role, reader_password = "review_escape_" + uuid4().hex, secrets.token_urlsafe(32)
    object_name = "escape_" + uuid4().hex
    object_id = sql.Identifier("sova_control", object_name)
    foreign = replace(scope, tenant_id="foreign-" + uuid4().hex)
    hold_id = uuid4().hex
    PostgresSecurityHolds(lambda: psycopg.connect(dsn, user=registrar, password=password), tenant_id=foreign.tenant_id).open_hold(
        SecurityHold(hold_id, foreign, "test-owner", "isolated-canary", datetime.now(UTC)))
    query = sql.SQL("SELECT hold_id FROM sova_control.security_hold_events WHERE hold_id={}").format(sql.Literal(hold_id))
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=role, tenant_id=scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(reader_password)))
    try:
        with psycopg.connect(dsn, user=role, password=reader_password, autocommit=True) as reader:
            require_reader(reader, tenant_id=scope.tenant_id)
            reader.execute("SELECT set_config('sova.tenant_id',%s,false)", (foreign.tenant_id,))
            assert reader.execute(query).fetchall() == []
            with psycopg.connect(dsn, autocommit=True) as admin:
                if path == "public-definer":
                    admin.execute(sql.SQL("CREATE FUNCTION {}() RETURNS SETOF text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS {}")
                                  .format(object_id, sql.Literal(query.as_string(admin))))
                    indirect = sql.SQL("SELECT * FROM {}()").format(object_id)
                else:
                    admin.execute(sql.SQL("CREATE VIEW {} AS ").format(object_id) + query)
                    admin.execute(sql.SQL("GRANT SELECT ON {} TO PUBLIC").format(object_id))
                    indirect = sql.SQL("SELECT * FROM {}").format(object_id)
            # A real misconfiguration can bypass the base table's fixed RLS.
            assert reader.execute(indirect).fetchone() == (hold_id,)
            with pytest.raises(ContractError):
                require_reader(reader, tenant_id=scope.tenant_id)
            # Only the separate owner repairs PUBLIC grants. The service cannot.
            with psycopg.connect(dsn, autocommit=True) as admin:
                if path == "public-definer":
                    admin.execute(sql.SQL("REVOKE ALL ON FUNCTION {}() FROM PUBLIC").format(object_id))
                else:
                    admin.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(object_id))
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                reader.execute(indirect)
            require_reader(reader, tenant_id=scope.tenant_id)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            kind = "FUNCTION" if path == "public-definer" else "VIEW"
            admin.execute(sql.SQL("DROP " + kind + " IF EXISTS {}" + ("()" if path == "public-definer" else "")).format(object_id))
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


@pytest.mark.parametrize("privilege", ["column-write", "replication", "schema-create", "database-create",
                                      "extra-table-column", "sequence", "large-object"])
def test_reader_rejects_non_table_and_column_level_privilege_drift(database, scope, privilege):
    import psycopg
    from psycopg import sql
    from sova_security.adapters.review_database import reader_statements, require_reader

    dsn, _, _ = database
    role, password = "review_drift_" + uuid4().hex, secrets.token_urlsafe(32)
    obj = sql.Identifier("sova_control", "drift_" + uuid4().hex)
    large_object = None
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=role, tenant_id=scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    try:
        with psycopg.connect(dsn, user=role, password=password, autocommit=True) as reader:
            require_reader(reader, tenant_id=scope.tenant_id)
            with psycopg.connect(dsn, autocommit=True) as admin:
                user = sql.Identifier(role)
                if privilege == "column-write":
                    admin.execute(sql.SQL("GRANT UPDATE(document) ON sova_control.security_hold_events TO {}").format(user))
                    assert reader.execute("SELECT has_table_privilege(current_user,'sova_control.security_hold_events','UPDATE')").fetchone() == (False,)
                elif privilege == "replication":
                    admin.execute(sql.SQL("ALTER ROLE {} REPLICATION").format(user))
                elif privilege == "schema-create":
                    admin.execute(sql.SQL("GRANT CREATE ON SCHEMA public TO {}").format(user))
                elif privilege == "database-create":
                    admin.execute(sql.SQL("GRANT CREATE ON DATABASE sova_security_test TO {}").format(user))
                elif privilege == "extra-table-column":
                    admin.execute(sql.SQL("CREATE TABLE {} (value text)").format(obj))
                    admin.execute(sql.SQL("GRANT SELECT(value) ON {} TO {}").format(obj, user))
                elif privilege == "sequence":
                    admin.execute(sql.SQL("CREATE SEQUENCE {}").format(obj))
                    admin.execute(sql.SQL("GRANT USAGE ON SEQUENCE {} TO {}").format(obj, user))
                else:
                    large_object = admin.execute("SELECT lo_create(0)").fetchone()[0]
                    admin.execute(sql.SQL("GRANT SELECT ON LARGE OBJECT {} TO {}").format(sql.Literal(large_object), user))
            with pytest.raises(ContractError):
                require_reader(reader, tenant_id=scope.tenant_id)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            if privilege == "extra-table-column":
                admin.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(obj))
            if privilege == "sequence":
                admin.execute(sql.SQL("DROP SEQUENCE IF EXISTS {}").format(obj))
            if large_object is not None:
                admin.execute("SELECT lo_unlink(%s)", (large_object,))
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
