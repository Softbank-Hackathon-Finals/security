"""Direct TCP/TLS boundary on an explicitly owned disposable PG cluster only."""

from ipaddress import ip_address
import os
from pathlib import Path, PurePosixPath
import secrets
import time
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database
from sova_security.adapters.review_database_network import reader_hba_rules

database = isolated_database
pytestmark = pytest.mark.postgres


def install_owned_hba(admin, path, contents):
    """Exact bytes, using only the already-guarded fixture's administrator."""
    assert admin.execute("SELECT current_setting('cluster_name'),current_database()").fetchone() == (
        "sova-security-test", "sova_security_test")
    assert admin.info.host.startswith("/")
    directory = PurePosixPath(admin.execute("SHOW data_directory").fetchone()[0])
    assert directory.is_absolute() and PurePosixPath(path) == directory / "pg_hba.conf"
    assert 0 < len(contents) <= 65536 and b"\0" not in contents
    oid = admin.execute("SELECT lo_from_bytea(0,%s)", (contents,)).fetchone()[0]
    try:
        assert admin.execute("SELECT lo_export(%s,%s)", (oid, path)).fetchone() == (1,)
    finally:
        assert admin.execute("SELECT lo_unlink(%s)", (oid,)).fetchone() == (1,)
    assert admin.execute("SELECT pg_read_binary_file(%s)", (path,)).fetchone()[0] == contents
    assert not admin.execute("SELECT error FROM pg_hba_file_rules WHERE error IS NOT NULL").fetchall()
    before = admin.execute("SELECT pg_conf_load_time()").fetchone()[0]
    assert admin.execute("SELECT pg_reload_conf()").fetchone() == (True,)
    deadline = time.monotonic() + 5
    while admin.execute("SELECT pg_conf_load_time()").fetchone()[0] <= before:
        assert time.monotonic() < deadline, "Owned HBA reload deadline exceeded"
        time.sleep(0.02)


def test_database_scoped_hba_blocks_stolen_login_cross_database_and_plaintext(database, scope):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from sova_security.adapters.review_database import reader_statements, require_reader

    configured_ca = os.environ.get("SOVA_TEST_REVIEW_DB_CA")
    if not configured_ca:
        pytest.skip("Explicit private test PostgreSQL TLS CA required")
    ca = Path(configured_ca)
    assert ca.is_absolute() and ca.is_file()
    dsn, _, _ = database
    role = "review_ingress_" + uuid4().hex
    other = "sova_hba_other_" + uuid4().hex
    password = secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert admin.info.host.startswith("/")
        assert admin.execute("SELECT current_setting('cluster_name'),current_database(),current_setting('ssl')").fetchone() == (
            "sova-security-test", "sova_security_test", "on")
        hba = admin.execute("SHOW hba_file").fetchone()[0]
        directory = PurePosixPath(admin.execute("SHOW data_directory").fetchone()[0])
        assert directory.is_absolute() and PurePosixPath(hba) == directory / "pg_hba.conf"
        original = bytes(admin.execute("SELECT pg_read_binary_file(%s)", (hba,)).fetchone()[0])
        assert len(original) <= 60000
        created_role = created_database = False
        prior = None
        try:
            for statement in reader_statements(role=role, tenant_id=scope.tenant_id):
                admin.execute(statement)
                created_role = True
            admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            with psycopg.connect(dsn, user=role, password=password) as reader:
                require_reader(reader, tenant_id=scope.tenant_id)
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(other)))
            created_database = True
            with psycopg.connect(dsn, dbname=other, autocommit=True) as owner:
                owner.execute("CREATE TABLE public.ingress_canary (value text)")
                owner.execute("INSERT INTO public.ingress_canary VALUES ('synthetic-other-database')")
                owner.execute("GRANT SELECT ON public.ingress_canary TO PUBLIC")
            connection_info = make_conninfo(dsn, host="localhost", port=admin.info.port,
                hostaddr=os.environ.get("SOVA_TEST_REVIEW_DB_HOSTADDR", "127.0.0.1"),
                user=role, password=password, sslmode="verify-full", sslrootcert=str(ca),
                sslcert=str(ca.parent / "absent-client.crt"), sslkey=str(ca.parent / "absent-client.key"),
                connect_timeout=2)
            # Positive reproduction: current-database RLS does not cover another DB.
            prior = psycopg.connect(connection_info, dbname=other, autocommit=True)
            assert prior.execute("SELECT value FROM public.ingress_canary").fetchone() == ("synthetic-other-database",)
            client = ip_address(str(prior.execute("SELECT inet_client_addr()").fetchone()[0]))
            network = str(client) + ("/32" if client.version == 4 else "/128")

            def install(network):
                rules = reader_hba_rules(role=role, database="sova_security_test", client_networks=[network])
                install_owned_hba(admin, hba, ("\n".join(rules) + "\n").encode() + original)

            install(network)
            with psycopg.connect(connection_info) as reader:
                require_reader(reader, tenant_id=scope.tenant_id)
                assert reader.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone() == (True,)
            with pytest.raises(psycopg.OperationalError, match="pg_hba.conf rejects connection"):
                psycopg.connect(connection_info, dbname=other)
            with pytest.raises(psycopg.OperationalError, match="pg_hba.conf rejects connection"):
                psycopg.connect(connection_info, sslmode="disable")
            # Rule reload applies to new sessions; it does not revoke existing ones.
            assert prior.execute("SELECT value FROM public.ingress_canary").fetchone() == ("synthetic-other-database",)
            denied_network = "127.0.0.2/32" if network != "127.0.0.2/32" else "127.0.0.3/32"
            install(denied_network)
            with pytest.raises(psycopg.OperationalError, match="pg_hba.conf rejects connection"):
                psycopg.connect(connection_info)
            # Existing administrator ingress and other roles remain unchanged.
            with psycopg.connect(dsn, dbname=other) as owner:
                assert owner.execute("SELECT count(*) FROM public.ingress_canary").fetchone() == (1,)
        finally:
            if prior is not None:
                prior.close()
            install_owned_hba(admin, hba, original)
            if created_database:
                assert other.startswith("sova_hba_other_")
                admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(other)))
            if created_role:
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
