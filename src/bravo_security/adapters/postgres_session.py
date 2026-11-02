"""Tenant-scoped transactions only; no plan persistence or implicit connection.

Use an authenticated tenant and non-owner NOBYPASSRLS runtime role. This is not
isolation from an attacker who already owns the shared database credential.
"""

from contextlib import contextmanager
from datetime import UTC, datetime
from bravo_security.contracts.commands import ContractError, identifier


class ScopedPostgresSession:
    def __init__(self, connect, *, tenant_id, clock=lambda: datetime.now(UTC)):
        identifier(tenant_id, "tenant_id")
        self.connect, self.tenant_id, self.clock = connect, tenant_id, clock

    @contextmanager
    def transaction(self):
        with self.connect() as conn:
            with conn.transaction():
                privileged = conn.execute("""SELECT rolsuper OR rolbypassrls OR EXISTS (
                    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='sova_control' AND c.relowner=pg_roles.oid)
                    FROM pg_roles WHERE rolname=current_user""").fetchone()
                if not privileged or privileged[0]:
                    raise ContractError(
                        "Lifecycle runtime role must not own or bypass row security"
                    )
                conn.execute(
                    "SELECT set_config('sova.tenant_id',%s,true)", (self.tenant_id,)
                )
                yield conn
