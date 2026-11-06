"""Real local TLS/process/PG, synthetic signed measurements and token issuer."""

from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import timedelta
import json
import secrets
import ssl
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tokenreview_tls_support import LocalTokenReview
from tls_review_support import review_process, tls_server
from sova_security.adapters.review_https import BearerCredential, HTTPSJSONTransport


def signed_program(write, registration, evidence, now):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
    from sova_security.domain.program_evidence import ProgramEvidenceRoute, ProgramSource
    from sova_security.domain.signed_evidence import VerifierTrust
    from sova_security.domain.verifier_registry import VerifierTrustChange

    scope = registration.scope
    artifacts = PostgresSecurityArtifacts(write, tenant_id=scope.tenant_id)
    originals = tuple(replace(record, evidence_id=uuid4().hex, obligation_id="producer:" + binding.check_id,
        verifier_version="test-only-original:" + binding.check_id)
        for binding, record in zip(registration.program.bindings, evidence, strict=True))
    signer = Ed25519EvidenceSigner(Ed25519PrivateKey.generate(), issuer_id=uuid4().hex, key_id="test-key")
    trust_store = PostgresVerifierRegistry(write, tenant_id=scope.tenant_id, application_id=scope.application_id)
    trust = VerifierTrust(signer.issuer_id, signer.key_id, signer.public_key_hex,
        (registration.program.source, scope), tuple(r.verifier_version for r in originals),
        now - timedelta(seconds=1), registration.valid_until)
    change = VerifierTrustChange(scope.tenant_id, scope.application_id, 1, trust,
        "registrar", "independent-reviewer", "synthetic-full-program", now, now + timedelta(minutes=1))
    trust_store.publish(change)
    signed = PostgresSignedEvidence(write, tenant_id=scope.tenant_id)
    for binding, original in zip(registration.program.bindings, originals, strict=True):
        signed.save_envelope(signer.sign(original, issued_at=now))
        artifacts.register(scope, ProgramEvidenceRoute(registration.program.fingerprint, binding.check_id,
            (ProgramSource(signer.issuer_id, original),)), actor_id="registrar")
    return trust_store, change


@contextmanager
def registered_review_runtime(database, directory, *, registration, evidence, principal, now):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.adapters.review_database import reader_statements

    dsn, registrar, password = database
    with psycopg.connect(dsn, autocommit=True) as admin:
        if not admin.info.host.startswith("/"):
            pytest.skip("Standalone runtime requires explicitly isolated private socket")
    def write():
        return psycopg.connect(dsn, user=registrar, password=password)
    artifacts = PostgresSecurityArtifacts(write, tenant_id=registration.scope.tenant_id)
    artifacts.register(registration.scope, registration.program, actor_id="registrar")
    artifacts.register(registration.scope, registration, actor_id="registrar")
    trust, change = signed_program(write, registration, evidence, now)
    reader, reader_password = "review_reader_" + uuid4().hex, secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=reader, tenant_id=registration.scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(reader), sql.Literal(reader_password)))
    issuer = LocalTokenReview(now)
    def mount(name, value):
        path = directory / name
        path.write_text(value)
        path.chmod(0o600)
        return str(path)
    grants = dict(schema_version=1, grants=[dict(username=issuer.username, uid=issuer.uid,
        subject_id=principal.subject_id, tenant_id=principal.tenant_id,
        scopes=[asdict(s) for s in principal.scopes], modes=list(principal.modes),
        issued_at=principal.issued_at.isoformat(), valid_until=principal.valid_until.isoformat())])
    try:
        with tls_server(issuer, directory, name="issuer") as (issuer_origin, issuer_ca):
            config = dict(schema_version=1, tenant_id=registration.scope.tenant_id,
                database_dsn_file=mount("database.dsn", make_conninfo(dsn, user=reader, password=reader_password)),
                tokenreview_origin=issuer_origin, tokenreview_ca_file=str(issuer_ca),
                reviewer_token_file=mount("reviewer.token", issuer.reviewer_token), audience=issuer.audience,
                grants_file=mount("grants.json", json.dumps(grants)), local_audit_file=str(directory / "audit.jsonl"))
            with review_process(mount("config.json", json.dumps(config)), directory) as (origin, ca):
                yield SimpleNamespace(artifacts=artifacts, trust_store=trust, trust_change=change, issuer=issuer,
                    transport=HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)), timeout=5),
                    credential=BearerCredential(issuer.client_token, now + timedelta(minutes=2)))
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(reader)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(reader)))
