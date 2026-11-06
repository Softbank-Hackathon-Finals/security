"""Actual TLS + online signed-token simulator + SELECT-only PostgreSQL chain."""

from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import json
import secrets
import ssl
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database
from review_service_support import service_bundle
from tls_review_support import review_process, tls_server
from tokenreview_tls_support import LocalTokenReview
from sova_security.adapters.modernization_codec import encode, decode
from sova_security.adapters.review_https import BearerCredential, HTTPSJSONTransport, ReviewTransportError

pytestmark = pytest.mark.postgres
database = isolated_database


@pytest.mark.parametrize("fault", ["issuer-revoked", "uid-replaced", "grant-revoked", "reviewer-rotated", "registration-revoked", "audit-unavailable", "signed-producer-revoked"])
def test_standalone_review_runtime_reads_current_authority(database, scope, tmp_path, fault):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.interfaces.review_server import app_from_config
    from sova_security.adapters.review_database import reader_statements

    dsn, registrar, password = database
    reader, reader_password = "review_reader_" + uuid4().hex, secrets.token_urlsafe(32)
    scope = replace(scope, application_id="review-runtime-" + uuid4().hex)
    now = datetime.now(UTC)
    state, _, request = service_bundle(scope, now)
    issuer = LocalTokenReview(now)
    def write():
        return psycopg.connect(dsn, user=registrar, password=password)
    artifacts = PostgresSecurityArtifacts(write, tenant_id=scope.tenant_id)
    artifacts.register(scope, state.registration.program, actor_id="registrar")
    artifacts.register(scope, state.registration, actor_id="registrar")
    trust_store = trust_change = None
    if fault == "signed-producer-revoked":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
        from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
        from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
        from sova_security.domain.program_evidence import ProgramEvidenceRoute, ProgramSource
        from sova_security.domain.signed_evidence import VerifierTrust
        from sova_security.domain.verifier_registry import VerifierTrustChange
        originals = tuple(replace(record, evidence_id=uuid4().hex, obligation_id="producer:" + binding.check_id,
            verifier_version="test-only-original:" + binding.check_id)
            for binding, record in zip(state.registration.program.bindings, state.evidence, strict=True))
        signer = Ed25519EvidenceSigner(Ed25519PrivateKey.generate(), issuer_id=uuid4().hex, key_id="test-key")
        trust_store = PostgresVerifierRegistry(write, tenant_id=scope.tenant_id, application_id=scope.application_id)
        trust = VerifierTrust(signer.issuer_id, signer.key_id, signer.public_key_hex,
            (state.registration.program.source, scope), tuple(r.verifier_version for r in originals),
            now - timedelta(seconds=1), state.registration.valid_until)
        trust_change = VerifierTrustChange(scope.tenant_id, scope.application_id, 1, trust,
            "registrar", "independent-reviewer", "synthetic-full-program", now, now + timedelta(minutes=1))
        trust_store.publish(trust_change)
        signed = PostgresSignedEvidence(write, tenant_id=scope.tenant_id)
        for binding, original in zip(state.registration.program.bindings, originals, strict=True):
            signed.save_envelope(signer.sign(original, issued_at=now))
            artifacts.register(scope, ProgramEvidenceRoute(state.registration.program.fingerprint, binding.check_id,
                (ProgramSource(signer.issuer_id, original),)), actor_id="registrar")
    with psycopg.connect(dsn, autocommit=True) as admin:
        # The standalone service accepts only verified TLS or this registered private Unix socket.
        if not admin.info.host.startswith("/"):
            pytest.skip("Standalone runtime requires explicit private socket or verified TLS fixture")
        for statement in reader_statements(role=reader, tenant_id=scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(reader), sql.Literal(reader_password)))
    try:
        def mount(name, value):
            path = tmp_path / name
            path.write_text(value)
            path.chmod(0o600)
            return str(path)
        p = state.principal
        grants = dict(schema_version=1, grants=[dict(username=issuer.username, uid=issuer.uid,
            subject_id=p.subject_id, tenant_id=p.tenant_id, scopes=[asdict(s) for s in p.scopes], modes=list(p.modes),
            issued_at=p.issued_at.isoformat(), valid_until=p.valid_until.isoformat())])
        with tls_server(issuer, tmp_path, name="issuer") as (issuer_origin, issuer_ca):
            config = dict(schema_version=1, tenant_id=scope.tenant_id, database_dsn_file=mount("database.dsn", make_conninfo(dsn, user=reader, password=reader_password)),
                tokenreview_origin=issuer_origin, tokenreview_ca_file=str(issuer_ca),
                reviewer_token_file=mount("reviewer.token", issuer.reviewer_token), audience=issuer.audience,
                grants_file=mount("grants.json", json.dumps(grants)), local_audit_file=str(tmp_path / "audit.jsonl"))
            config_path = mount("config.json", json.dumps(config))
            app = app_from_config(config_path)
            server = review_process(config_path, tmp_path) if fault == "issuer-revoked" else tls_server(app, tmp_path, name="review")
            with server as (origin, ca):
                transport = HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)), timeout=5)
                credential = BearerCredential(issuer.client_token, now + timedelta(minutes=2))
                def call():
                    return decode(transport.post("/v1/program-reviews", encode(request).encode(), credential))
                result = call()
                assert result.subject_id == p.subject_id
                assert result.review.passed is (fault == "signed-producer-revoked")
                assert all(r.result.value == ("pass" if fault == "signed-producer-revoked" else "unknown") for r in result.review.results)
                assert issuer.calls >= 2  # online identity rechecked around protected work
                if fault == "issuer-revoked":
                    issuer.active = False
                elif fault == "uid-replaced":
                    issuer.uid = "recreated-account-uid"
                elif fault == "grant-revoked":
                    mount("grants.json", '{"schema_version":1,"grants":[]}')
                elif fault == "reviewer-rotated":
                    mount("reviewer.token", issuer.issue("different-reviewer", "api-server"))
                elif fault == "registration-revoked":
                    artifacts.revoke(scope, state.registration.fingerprint, expected_revision=1, actor_id="registrar", reason="test")
                elif fault == "signed-producer-revoked":
                    trust_store.publish(replace(trust_change, revision=2, trust=replace(trust_change.trust, revoked=True)))
                else:
                    (tmp_path / "audit.jsonl").unlink()
                    (tmp_path / "audit.jsonl").mkdir()
                with pytest.raises(ReviewTransportError):
                    call()
                if fault != "audit-unavailable":
                    audit = (tmp_path / "audit.jsonl").read_text()
                    assert issuer.client_token not in audit and reader_password not in audit
                    assert '"stage":"computed"' in audit
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(reader)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(reader)))
