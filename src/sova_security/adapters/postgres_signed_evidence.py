"""Immutable signed envelopes. Consumers must still verify current issuer trust."""

from psycopg.types.json import Jsonb
from sova_security.adapters.postgres_session import ScopedPostgresSession
from sova_security.adapters.signed_evidence_codec import decode_envelope
from sova_security.contracts.commands import ContractError, identifier
from sova_security.contracts.repositories import RepositoryConflict, RecordNotFound


class PostgresSignedEvidence:
    def __init__(self, connect, *, tenant_id):
        self.tenant_id = identifier(tenant_id)
        self.lifecycle = ScopedPostgresSession(connect, tenant_id=tenant_id)

    def save_envelope(self, envelope):
        scope = envelope.evidence.scope
        if scope.tenant_id != self.tenant_id:
            raise ContractError("Signed evidence tenant mismatch")
        with self.lifecycle.transaction() as conn:
            conn.execute(
                """INSERT INTO sova_control.signed_security_evidence
             (tenant_id,application_id,evidence_id,issuer_id,key_id,digest,document) VALUES(%s,%s,%s,%s,%s,%s,%s)
             ON CONFLICT DO NOTHING""",
                (
                    self.tenant_id,
                    scope.application_id,
                    envelope.evidence.evidence_id,
                    envelope.issuer_id,
                    envelope.key_id,
                    envelope.fingerprint,
                    Jsonb(envelope.document),
                ),
            )
            row = conn.execute(
                "SELECT digest FROM sova_control.signed_security_evidence WHERE tenant_id=%s AND application_id=%s AND evidence_id=%s",
                (self.tenant_id, scope.application_id, envelope.evidence.evidence_id),
            ).fetchone()
            if not row or row[0] != envelope.fingerprint:
                raise RepositoryConflict(
                    "Signed evidence ID cannot be overwritten or resigned"
                )

    def get_envelope(self, application_id, evidence_id):
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                "SELECT issuer_id,key_id,digest,document FROM sova_control.signed_security_evidence WHERE tenant_id=%s AND application_id=%s AND evidence_id=%s",
                (self.tenant_id, application_id, evidence_id),
            ).fetchone()
            if not row:
                raise RecordNotFound("Signed evidence not found")
            envelope = decode_envelope(row[3])
            record = envelope.evidence
            if (
                record.scope.tenant_id,
                record.scope.application_id,
                record.evidence_id,
                envelope.issuer_id,
                envelope.key_id,
                envelope.fingerprint,
            ) != (self.tenant_id, application_id, evidence_id, row[0], row[1], row[2]):
                raise ContractError("Stored signed evidence integrity/scope mismatch")
            return envelope

    def find_envelope(self, scope, *, artifact_digest, verifier_version):
        """Exact bounded lookup for a registered typed document's attestation.

        This resolves an identity, never trust. Consumers still authenticate the
        signature/current issuer. Ambiguous re-attestations require explicit IDs.
        """
        from sova_security.contracts.commands import ResourceScope, digest

        if not isinstance(scope, ResourceScope) or scope.tenant_id != self.tenant_id:
            raise ContractError("Signed lookup scope mismatch")
        digest(artifact_digest)
        identifier(verifier_version)
        with self.lifecycle.transaction() as conn:
            rows = conn.execute(
                """SELECT evidence_id FROM sova_control.signed_security_evidence
                WHERE tenant_id=%s AND application_id=%s
                AND document #>> '{evidence,scope,environment_id}'=%s
                AND document #>> '{evidence,scope,resource_id}'=%s
                AND document #>> '{evidence,artifact_digest}'=%s
                AND document #>> '{evidence,verifier_version}'=%s
                LIMIT 2""",
                (
                    self.tenant_id,
                    scope.application_id,
                    scope.environment_id,
                    scope.resource_id,
                    artifact_digest,
                    verifier_version,
                ),
            ).fetchall()
        if len(rows) != 1:
            raise ContractError("Exact unambiguous signed evidence identity required")
        result = self.get_envelope(scope.application_id, rows[0][0])
        if (
            result.evidence.scope != scope
            or result.evidence.artifact_digest != artifact_digest
            or result.evidence.verifier_version != verifier_version
        ):
            raise ContractError("Signed evidence lookup integrity mismatch")
        return result
