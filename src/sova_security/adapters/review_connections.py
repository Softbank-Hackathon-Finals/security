"""One lazy read connection per request; no rows, grants or PASS cache."""

from contextlib import contextmanager
from contextvars import ContextVar
from ipaddress import ip_address
import os
from pathlib import Path, PurePosixPath
import re

from sova_security.contracts.commands import ContractError


def review_connection_parameters(dsn):
    """Validate fixed routing/trust before libpq can perform authentication.

    Explicit fields prevent ambient defaults and host-list fallback from changing
    the registered endpoint. Other protected libpq credential options remain
    operator-owned; no password or complete DSN is included in an error.
    """
    from psycopg.conninfo import conninfo_to_dict
    try:
        parameters = conninfo_to_dict(dsn)
    except Exception:
        raise ContractError("Explicit review database connection parameters required") from None
    if parameters.get("service") or os.environ.get("PGSERVICE") or os.environ.get("PGSERVICEFILE"):
        raise ContractError("Indirect database service profiles are not supported")
    host = parameters.get("host", "")
    if (not host or len(host) > 1024 or "," in host
            or any(ord(char) < 33 or ord(char) > 126 for char in host)):
        raise ContractError("One explicit registered database host required")
    for name in ("user", "dbname"):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,62}", parameters.get(name, "")):
            raise ContractError("Explicit database and reader identity required")
    port = parameters.get("port", "")
    if not port.isascii() or not port.isdecimal() or len(port) > 5 or not 1 <= int(port) <= 65535:
        raise ContractError("One explicit database port required")
    address = parameters.get("hostaddr")
    if os.environ.get("PGHOSTADDR") and not address:
        raise ContractError("Ambient database address cannot override registered routing")
    if host.startswith("/"):
        if address or not PurePosixPath(host).is_absolute() or ".." in PurePosixPath(host).parts:
            raise ContractError("One registered private socket directory required")
    else:
        if "/" in host or host.startswith("@"):
            raise ContractError("Registered database TLS host required")
        if address:
            try:
                ip_address(address)
            except ValueError:
                raise ContractError("One numeric registered database address required") from None
        root = parameters.get("sslrootcert", "")
        if parameters.get("sslmode") != "verify-full" or not root or not Path(root).is_absolute():
            raise ContractError("Explicit verify-full TLS and absolute CA mount required before connection")
    parameters.update(connect_timeout=2,
        # GSS encryption can otherwise take precedence over sslmode in libpq.
        gssencmode="disable",
        options="-c statement_timeout=2000 -c default_transaction_read_only=on -c idle_in_transaction_session_timeout=3000 -c search_path=pg_catalog")
    return parameters


class RequestScopedReader:
    def __init__(self, open_connection, *, validate):
        self.open_connection, self.validate = open_connection, validate
        self.current = ContextVar("security_review_connection", default=None)

    @contextmanager
    def request(self):
        if self.current.get() is not None:
            raise ContractError("Nested review request context is not allowed")
        state = {"connection": None}
        token = self.current.set(state)
        try:
            yield
            if state["connection"] is not None:
                self.validate(state["connection"])
        finally:
            try:
                if state["connection"] is not None:
                    state["connection"].close()
            finally:
                self.current.reset(token)

    @contextmanager
    def connect(self):
        state = self.current.get()
        if state is None:
            raise ContractError("Explicit request-scoped reader required")
        if state["connection"] is None:
            state["connection"] = self.open_connection()
            self.validate(state["connection"])
        yield state["connection"]
