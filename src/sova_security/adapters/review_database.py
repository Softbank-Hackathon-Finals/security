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
STORAGE_CREATORS = ("lo_create(oid)", "lo_creat(integer)", "lo_from_bytea(oid,bytea)")


def reader_database_statements(*, database):
    """Operator preparation for a dedicated security DB, never automatic.

    PUBLIC grants cannot be denied to only one reader. Review other users and
    explicitly grant their required privileges before applying these statements.
    Do not use this helper to alter a shared platform DB without that review.
    """
    from psycopg import sql
    policy_name(database)
    if database in {"postgres", "template0", "template1"}:
        raise ContractError("Dedicated security database required")
    return (
        sql.SQL("REVOKE TEMPORARY ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)),
        *(sql.SQL("REVOKE EXECUTE ON FUNCTION pg_catalog.{} FROM PUBLIC").format(sql.SQL(signature))
          for signature in STORAGE_CREATORS),
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
        rolreplication,
        EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid),
        has_schema_privilege(current_user,'sova_control','CREATE'),
        has_database_privilege(current_user,current_database(),'CREATE'),
        has_database_privilege(current_user,current_database(),'TEMPORARY')
        FROM pg_roles r WHERE rolname=current_user""").fetchone()
    if not role or role[0] != role[1] or any(role[2:]):
        raise ContractError("Independent unprivileged review reader required")
    policy = policy_name(role[0])
    rows = connection.execute("""SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
        c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user),
        has_table_privilege(current_user,c.oid,'SELECT'),
        (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')),
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
    # PUBLIC grants are additive: REVOKE FROM this role cannot cancel them.
    # Owner-rights views and definer routines can bypass the underlying RLS.
    # Refuse the unsafe deployment; only a separate owner may repair grants.
    extra = connection.execute("""SELECT
        EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname !~ '^pg_'
            AND n.nspname <> 'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE')),
        EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            JOIN pg_language l ON l.oid=p.prolang
            WHERE has_schema_privilege(current_user,n.oid,'USAGE') AND has_function_privilege(current_user,p.oid,'EXECUTE')
              AND (p.prosecdef OR p.oid IN ('pg_catalog.lo_create(oid)'::regprocedure,
                    'pg_catalog.lo_creat(integer)'::regprocedure, 'pg_catalog.lo_from_bytea(oid,bytea)'::regprocedure)
                OR (NOT l.lanpltrusted AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema')
                OR EXISTS(SELECT 1 FROM pg_init_privs i
                    WHERE i.classoid='pg_catalog.pg_proc'::regclass AND i.objoid=p.oid AND i.objsubid=0
                      AND NOT EXISTS(SELECT 1 FROM aclexplode(i.initprivs) a
                          WHERE a.grantee=0 AND a.privilege_type='EXECUTE')))),
        EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
              AND c.relkind IN ('r','p','v','m','f') AND has_schema_privilege(current_user,n.oid,'USAGE')
              AND NOT (n.nspname='sova_control' AND c.relname=ANY(%s))
              AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                   OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))),
        EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE c.relkind='S' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
              AND has_schema_privilege(current_user,n.oid,'USAGE') AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE')),
        (current_setting('lo_compat_privileges') <> 'off' OR EXISTS(
            SELECT 1 FROM pg_largeobject_metadata l
            WHERE l.lomowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
              OR EXISTS(SELECT 1 FROM aclexplode(l.lomacl) a
                  WHERE a.grantee IN (0,(SELECT oid FROM pg_roles WHERE rolname=current_user))
                    AND a.privilege_type IN ('SELECT','UPDATE'))))
        """, (list(REVIEW_TABLES),)).fetchone()
    if not extra or any(extra):
        raise ContractError("Review reader has an indirect or unrelated database privilege")
