"""Content-addressed security artifacts with append-only CAS revocation.

Authorization and issuer authentication precede this repository. A row is not
an approval. Runtime role is non-owner, NOBYPASSRLS, SELECT/INSERT only.
"""

import json

from psycopg.types.json import Jsonb
from sova_security.adapters.modernization_codec import decode, encode, kind_of
from sova_security.adapters.postgres_session import ScopedPostgresSession
from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    digest,
    identifier,
)
from sova_security.contracts.repositories import RecordNotFound, RepositoryConflict
from sova_security.domain.remediation import (
    RehearsalRequest,
    RehearsalReceipt,
    RehearsalDecision,
)
from sova_security.ports.modernization import StoredSecurityArtifact


class PostgresSecurityArtifacts:
    def __init__(self, connect, *, tenant_id):
        self.tenant_id = identifier(tenant_id)
        self.transactions = ScopedPostgresSession(connect, tenant_id=tenant_id)

    def _scope(self, scope):
        if not isinstance(scope, ResourceScope) or scope.tenant_id != self.tenant_id:
            raise ContractError("Authenticated tenant scope required")

    def _lock(self, conn, scope, fingerprint):
        key = json.dumps([self.tenant_id, scope.application_id, fingerprint])
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))

    def _get(self, conn, scope, fingerprint):
        row = conn.execute(
            """SELECT a.artifact_kind,a.envelope,e.revision,e.event_kind
            FROM sova_control.security_artifacts_v1 a
            JOIN sova_control.security_artifact_events_v1 e
              USING (tenant_id,application_id,artifact_digest)
            WHERE a.tenant_id=%s AND a.application_id=%s AND a.artifact_digest=%s
              AND a.environment_id=%s AND a.resource_id=%s
            ORDER BY e.revision DESC LIMIT 1""",
            (
                self.tenant_id,
                scope.application_id,
                fingerprint,
                scope.environment_id,
                scope.resource_id,
            ),
        ).fetchone()
        if row is None:
            raise RecordNotFound("Security artifact not found")
        value = decode(json.dumps(row[1]).encode())
        if (
            value.fingerprint != fingerprint
            or kind_of(value) != row[0]
            or (row[2], row[3]) not in {(1, "registered"), (2, "revoked")}
        ):
            raise ContractError("Persisted security artifact integrity mismatch")
        self._validate_scope(conn, scope, value)
        return StoredSecurityArtifact(scope, value, row[2], row[3] == "revoked")

    def _validate_scope(self, conn, scope, value):
        if isinstance(value, RehearsalRequest):
            own = value.proposal.scope
        elif isinstance(value, (RehearsalReceipt, RehearsalDecision)):
            # Derive scope through the registered request, never a caller label.
            parent = self._get(conn, scope, value.request_digest)
            if not isinstance(parent.value, RehearsalRequest):
                raise ContractError("Registered rehearsal parent required")
            if (
                isinstance(value, RehearsalReceipt)
                and value.proposal_digest != parent.value.proposal.fingerprint
            ):
                raise ContractError("Receipt proposal differs from registered request")
            own = parent.scope
        else:
            own = getattr(value, "scope", None)
        if own != scope:
            raise ContractError("Security artifact scope mismatch")

    def register(self, scope, value, *, actor_id):
        self._scope(scope)
        identifier(actor_id)
        body = json.loads(encode(value))
        fingerprint = value.fingerprint
        with self.transactions.transaction() as conn:
            if isinstance(value, RehearsalRequest):
                # Stable request IDs cannot be rebound to another content digest.
                self._lock(conn, scope, "request-id:" + value.request_id)
                row = conn.execute(
                    """SELECT artifact_digest FROM sova_control.security_artifacts_v1
                    WHERE tenant_id=%s AND application_id=%s AND artifact_kind='rehearsal-request.v1'
                    AND envelope #>> '{value,request_id}'=%s""",
                    (self.tenant_id, scope.application_id, value.request_id),
                ).fetchone()
                if row is not None and row[0] != fingerprint:
                    raise RepositoryConflict("Rehearsal request ID cannot be rebound")
            self._lock(conn, scope, fingerprint)
            self._validate_scope(conn, scope, value)
            try:
                existing = self._get(conn, scope, fingerprint)
            except RecordNotFound:
                existing = None
            if existing is not None:
                if existing.revoked:
                    raise RepositoryConflict(
                        "Revoked artifact cannot be registered again"
                    )
                return existing
            conn.execute(
                """INSERT INTO sova_control.security_artifacts_v1
                (tenant_id,application_id,artifact_digest,artifact_kind,environment_id,
                 resource_id,envelope,registered_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    self.tenant_id,
                    scope.application_id,
                    fingerprint,
                    kind_of(value),
                    scope.environment_id,
                    scope.resource_id,
                    Jsonb(body),
                    actor_id,
                ),
            )
            conn.execute(
                """INSERT INTO sova_control.security_artifact_events_v1
                (tenant_id,application_id,artifact_digest,revision,event_kind,actor_id,reason)
                VALUES (%s,%s,%s,1,'registered',%s,'authenticated-registration')""",
                (self.tenant_id, scope.application_id, fingerprint, actor_id),
            )
            return StoredSecurityArtifact(scope, value, 1, False)

    def request(self, scope, request_id):
        self._scope(scope)
        identifier(request_id)
        with self.transactions.transaction() as conn:
            row = conn.execute(
                """SELECT artifact_digest FROM sova_control.security_artifacts_v1
                WHERE tenant_id=%s AND application_id=%s AND environment_id=%s AND resource_id=%s
                AND artifact_kind='rehearsal-request.v1'
                AND envelope #>> '{value,request_id}'=%s""",
                (
                    self.tenant_id,
                    scope.application_id,
                    scope.environment_id,
                    scope.resource_id,
                    request_id,
                ),
            ).fetchone()
            if row is None:
                raise RecordNotFound("Registered rehearsal request not found")
            stored = self._get(conn, scope, row[0])
            if stored.revoked:
                raise RepositoryConflict("Rehearsal request revoked")
            return stored.value

    def get(self, scope, fingerprint, *, require_active=True):
        self._scope(scope)
        digest(fingerprint)
        if type(require_active) is not bool:
            raise ContractError("Explicit active lookup mode required")
        with self.transactions.transaction() as conn:
            stored = self._get(conn, scope, fingerprint)
            if require_active and stored.revoked:
                raise RepositoryConflict("Security artifact revoked")
            return stored

    def revoke(self, scope, fingerprint, *, expected_revision, actor_id, reason):
        self._scope(scope)
        digest(fingerprint)
        identifier(actor_id)
        identifier(reason, limit=1024)
        if type(expected_revision) is not int or expected_revision != 1:
            raise RepositoryConflict("Only active revision one can be revoked")
        with self.transactions.transaction() as conn:
            self._lock(conn, scope, fingerprint)
            stored = self._get(conn, scope, fingerprint)
            if stored.revoked or stored.revision != expected_revision:
                raise RepositoryConflict("Security artifact revocation CAS conflict")
            conn.execute(
                """INSERT INTO sova_control.security_artifact_events_v1
                (tenant_id,application_id,artifact_digest,revision,event_kind,actor_id,reason)
                VALUES (%s,%s,%s,2,'revoked',%s,%s)""",
                (self.tenant_id, scope.application_id, fingerprint, actor_id, reason),
            )
            return StoredSecurityArtifact(scope, stored.value, 2, True)
