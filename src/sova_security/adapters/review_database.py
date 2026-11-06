"""Operator-only SQL preparation and runtime verification of a tenant-fixed reader.

No connection, role creation or schema mutation happens during import/rendering.
Apply the returned statements with a separate administrator before service use.
"""

import hashlib
import re

from sova_security.contracts.commands import ContractError, identifier

REVIEW_TABLES = (
    "security_artifacts_v1", "security_artifact_events_v1", "signed_security_evidence",
    "verifier_trust_events", "security_hold_events",
)


def policy_name(role):
    if type(role) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", role):
        raise ContractError("Explicit lowercase PostgreSQL role name required")
    return "review_tenant_" + hashlib.sha256(role.encode()).hexdigest()[:16]


def reader_statements(*, role, tenant_id):
    """New dedicated role only; duplicates fail instead of changing existing roles.

    Login credentials/rotation are provisioned through the host's secret manager.
    Do not grant memberships to this role. Existing tables must have FORCE RLS.
    """
    from psycopg import sql
    identifier(tenant_id)
    policy = policy_name(role)
    user = sql.Identifier(role)
    statements = [sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT").format(user),
                  sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(user)]
    for name in REVIEW_TABLES:
        table = sql.Identifier("sova_control", name)
        statements.extend([
            sql.SQL("GRANT SELECT ON {} TO {}").format(table, user),
            sql.SQL("CREATE POLICY {} ON {} AS RESTRICTIVE FOR ALL TO {} USING (tenant_id = {}) WITH CHECK (false)").format(
                sql.Identifier(policy), table, user, sql.Literal(tenant_id)),
        ])
    return tuple(statements)


def require_reader(connection, *, tenant_id):
    """Reject drift before any service store query, including inherited privileges."""
    identifier(tenant_id)
    role = connection.execute("""SELECT current_user, session_user, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole,
        EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid),
        has_schema_privilege(current_user,'sova_control','CREATE')
        FROM pg_roles r WHERE rolname=current_user""").fetchone()
    if not role or role[0] != role[1] or any(role[2:]):
        raise ContractError("Independent unprivileged review reader required")
    policy = policy_name(role[0])
    rows = connection.execute("""SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
        c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user),
        has_table_privilege(current_user,c.oid,'SELECT'),
        has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
        p.polpermissive, p.polcmd, p.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname=current_user)],
        pg_get_expr(p.polqual,p.polrelid)=format('(tenant_id = %%L::text)',%s::text),
        pg_get_expr(p.polwithcheck,p.polrelid)='false'
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_policy p ON p.polrelid=c.oid AND p.polname=%s
        WHERE n.nspname='sova_control' AND c.relname=ANY(%s)""", (tenant_id, policy, list(REVIEW_TABLES))).fetchall()
    if len(rows) != len(REVIEW_TABLES) or any(
        tuple(row[1:]) != (True, True, False, True, False, False, "*", True, True, True) for row in rows
    ):
        raise ContractError("Fixed tenant, FORCE RLS and SELECT-only review policy required")
