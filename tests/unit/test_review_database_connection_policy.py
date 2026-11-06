"""Reject unsafe mounted libpq routing before handing credentials to a client."""

import json
from types import SimpleNamespace

import pytest

from sova_security.contracts.commands import ContractError
from sova_security.interfaces.review_server import app_from_config
from tls_review_support import certificates


@pytest.fixture
def configured_connection(tmp_path):
    ca, _, _ = certificates(tmp_path)
    dsn_file = tmp_path / "database.dsn"
    config = dict(schema_version=1, tenant_id="tenant-a", database_dsn_file=str(dsn_file),
        tokenreview_origin="https://issuer.example.invalid", tokenreview_ca_file=str(ca),
        reviewer_token_file=str(tmp_path / "reviewer.token"), audience="security-review",
        grants_file=str(tmp_path / "grants.json"), local_audit_file=str(tmp_path / "audit.jsonl"))
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    def prepare(dsn):
        dsn_file.write_text(dsn)
        app = app_from_config(path)
        return app.endpoint.review_scope.__self__.open_connection
    return prepare


@pytest.mark.parametrize("dsn", [
    "host=db.example.invalid port=5432 dbname=security user=reader sslmode=disable",
    "host=db.example.invalid port=5432 dbname=security user=reader sslmode=prefer",
    "host=/missing,db.example.invalid port=5432 dbname=security user=reader sslmode=disable",
    "port=5432 dbname=security user=reader sslmode=verify-full",
    "host=db.example.invalid dbname=security user=reader sslmode=verify-full",
    "host=db.example.invalid port=5432 dbname=security user=reader sslmode=verify-full",
    "host=/private port=5432 dbname=security user=reader hostaddr=127.0.0.1",
    "host=/private port=5432 dbname=security user=reader service=unregistered",
    "host=/private port=5432 dbname='host=other' user=reader",
    "host=/private port=5432,5433 dbname=security user=reader",
    "host=/private port=5432 dbname=security",
    "host=/private/../other port=5432 dbname=security user=reader",
])
def test_unsafe_dsn_is_rejected_before_database_client_io(configured_connection, monkeypatch, dsn):
    import psycopg
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Unsafe connection reached database client")
    monkeypatch.setattr(psycopg, "connect", forbidden)
    with pytest.raises(ContractError):
        configured_connection(dsn)()
    assert calls == []


@pytest.mark.parametrize("variable", ["PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR"])
def test_ambient_routing_cannot_redirect_private_socket(configured_connection, monkeypatch, variable):
    import psycopg
    monkeypatch.setenv(variable, "unregistered")
    def forbidden(*args, **kwargs):
        pytest.fail("Ambient routing reached database client")
    monkeypatch.setattr(psycopg, "connect", forbidden)
    with pytest.raises(ContractError):
        configured_connection("host=/private port=5432 dbname=security user=reader")()


@pytest.mark.parametrize("network", [False, True])
def test_explicit_connection_preserves_rotation_and_enforces_options(configured_connection, tmp_path, monkeypatch, network):
    import psycopg
    from psycopg.conninfo import make_conninfo
    for name in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR"):
        monkeypatch.delenv(name, raising=False)
    captured = []
    host = "db.example.invalid" if network else "/private"
    parameters = dict(host=host, port=5432, dbname="security", user="reader", password="synthetic-first",
        options="-c default_transaction_read_only=off", connect_timeout=120)
    if network:
        parameters.update(sslmode="verify-full", sslrootcert=str(tmp_path / "db-ca.pem"),
            hostaddr="127.0.0.1", gssencmode="require")
    def connect(**kwargs):
        captured.append(kwargs)
        return SimpleNamespace(info=SimpleNamespace(get_parameters=lambda: dict(host=host, sslmode="verify-full"),
            ssl_in_use=network), close=lambda: None)
    monkeypatch.setattr(psycopg, "connect", connect)
    opened = configured_connection(make_conninfo(**parameters))
    opened()
    # The same mounted DSN path is reread for the next request after rotation.
    parameters["password"] = "synthetic-second"
    configured_connection(make_conninfo(**parameters))
    opened()
    assert [p["password"] for p in captured] == ["synthetic-first", "synthetic-second"]
    assert all(p["host"] == host and p["connect_timeout"] == 2 and p["gssencmode"] == "disable" for p in captured)
    assert all("default_transaction_read_only=on" in p["options"] and "search_path=pg_catalog" in p["options"] for p in captured)


@pytest.mark.parametrize("fault", ["host", "tls"])
def test_post_connection_checks_still_close_inconsistent_client(configured_connection, tmp_path, monkeypatch, fault):
    import psycopg
    from psycopg.conninfo import make_conninfo
    closed = []
    info = SimpleNamespace(get_parameters=lambda: dict(host="other" if fault == "host" else "db.example.invalid", sslmode="verify-full"),
        ssl_in_use=fault != "tls")
    monkeypatch.setattr(psycopg, "connect", lambda **_: SimpleNamespace(info=info, close=lambda: closed.append(True)))
    dsn = make_conninfo(host="db.example.invalid", port=5432, dbname="security", user="reader",
        sslmode="verify-full", sslrootcert=str(tmp_path / "db-ca.pem"))
    with pytest.raises(ContractError):
        configured_connection(dsn)()
    assert closed == [True]


@pytest.mark.parametrize("address", ["127.0.0.1,127.0.0.2", "db.example.invalid", "127.0.0.999"])
def test_network_hostaddr_is_one_numeric_address(tmp_path, address):
    from psycopg.conninfo import make_conninfo
    from sova_security.adapters.review_connections import review_connection_parameters
    dsn = make_conninfo(host="db.example.invalid", hostaddr=address, port=5432, dbname="security", user="reader",
        sslmode="verify-full", sslrootcert=str(tmp_path / "ca.pem"))
    with pytest.raises(ContractError):
        review_connection_parameters(dsn)
