"""Package-only PostgreSQL: no Sova schema or lifecycle implementation."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import os
import secrets
from uuid import uuid4

import pytest

from sova_security.contracts.commands import ContractError
from sova_security.contracts.repositories import RecordNotFound
from sova_security.domain.governance import SecurityHold
from sova_security.migrations import MIGRATIONS, migration_sql

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def database():
    dsn = os.environ.get("SOVA_SECURITY_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("Explicit isolated SOVA_SECURITY_TEST_POSTGRES_DSN required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql

    role = "security_test_" + uuid4().hex
    password = secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert admin.execute(
            "SELECT current_setting('cluster_name'),current_database()"
        ).fetchone() == ("sova-security-test", "sova_security_test")
        admin.execute("CREATE SCHEMA IF NOT EXISTS sova_control")
        for name in MIGRATIONS:
            admin.execute(migration_sql(name))
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD {}"
            ).format(sql.Identifier(role), sql.Literal(password))
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        admin.execute(
            sql.SQL(
                "GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA sova_control TO {}"
            ).format(sql.Identifier(role))
        )
    try:
        yield dsn, role, password
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_runtime_tenant_visibility_and_append_only_rights(database, scope):
    import psycopg
    from sova_security.adapters.postgres_governance import PostgresSecurityHolds

    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    first = PostgresSecurityHolds(connect, tenant_id=scope.tenant_id)
    hold = SecurityHold(
        uuid4().hex, scope, "detector", "controlled-test", datetime.now(UTC)
    )
    assert first.open_hold(hold).hold == hold
    assert first.get_hold(scope.application_id, hold.hold_id).active
    second = PostgresSecurityHolds(connect, tenant_id="tenant-b")
    with pytest.raises(RecordNotFound):
        second.get_hold(scope.application_id, hold.hold_id)
    assert second.active_holds(scope.application_id) == ()
    with pytest.raises(ContractError):
        first.open_hold(replace(hold, scope=replace(scope, tenant_id="tenant-b")))
    with connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM sova_control.security_hold_events")


def test_privileged_connection_cannot_be_runtime(database, scope):
    import psycopg
    from sova_security.adapters.postgres_session import ScopedPostgresSession

    dsn, _, _ = database
    session = ScopedPostgresSession(
        lambda: psycopg.connect(dsn), tenant_id=scope.tenant_id
    )
    with pytest.raises(ContractError, match="must not own or bypass"):
        with session.transaction():
            pytest.fail("Admin transaction must never be admitted")


def test_public_tables_never_need_host_operations_schema(database):
    import psycopg

    with psycopg.connect(database[0]) as conn:
        assert conn.execute(
            "SELECT to_regclass('sova_control.operations')"
        ).fetchone() == (None,)


def test_modernization_artifacts_are_immutable_scoped_and_revocable(
    database, scope, now
):
    import psycopg
    from modernization_support import rehearsal_bundle
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.contracts.repositories import RepositoryConflict

    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    repo = PostgresSecurityArtifacts(connect, tenant_id=scope.tenant_id)
    _, _, request, receipt = rehearsal_bundle(scope, now)
    request = replace(request, request_id=uuid4().hex)
    receipt = replace(receipt, request_digest=request.fingerprint)
    saved = repo.register(scope, request, actor_id="registered-operator")
    assert repo.request(scope, request.request_id) == request
    with pytest.raises(RepositoryConflict, match="cannot be rebound"):
        repo.register(
            scope,
            replace(request, valid_until=request.valid_until - timedelta(seconds=1)),
            actor_id="operator",
        )
    assert repo.register(scope, request, actor_id="registered-operator") == saved
    assert (
        repo.register(scope, receipt, actor_id="registered-verifier").value == receipt
    )
    assert repo.get(scope, request.fingerprint).value == request
    other = PostgresSecurityArtifacts(connect, tenant_id="tenant-b")
    with pytest.raises(RecordNotFound):
        other.get(replace(scope, tenant_id="tenant-b"), request.fingerprint)
    with pytest.raises(ContractError, match="scope mismatch"):
        repo.register(replace(scope, resource_id="other"), request, actor_id="operator")
    assert repo.revoke(
        scope,
        request.fingerprint,
        expected_revision=1,
        actor_id="reviewer",
        reason="invalidated",
    ).revoked
    assert repo.get(scope, request.fingerprint, require_active=False).revision == 2
    with pytest.raises(RepositoryConflict):
        repo.get(scope, request.fingerprint)
    with pytest.raises(RepositoryConflict):
        repo.request(scope, request.request_id)
    with pytest.raises(RepositoryConflict):
        repo.register(scope, request, actor_id="operator")
    with pytest.raises(RepositoryConflict):
        repo.revoke(
            scope,
            request.fingerprint,
            expected_revision=1,
            actor_id="reviewer",
            reason="again",
        )
    with connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "UPDATE sova_control.security_artifacts_v1 SET registered_by='attacker'"
            )


def test_orphan_receipt_cannot_be_registered_under_an_arbitrary_scope(
    database, scope, now
):
    import psycopg
    from modernization_support import rehearsal_bundle
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts

    dsn, role, password = database
    repo = PostgresSecurityArtifacts(
        lambda: psycopg.connect(dsn, user=role, password=password),
        tenant_id=scope.tenant_id,
    )
    _, _, _, receipt = rehearsal_bundle(scope, now)
    with pytest.raises(RecordNotFound):
        repo.register(
            scope, replace(receipt, request_digest="0" * 64), actor_id="verifier"
        )


def test_artifact_revocation_cas_serializes_concurrent_reviewers(database, scope, now):
    from concurrent.futures import ThreadPoolExecutor
    import psycopg
    from modernization_support import rehearsal_bundle
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.contracts.repositories import RepositoryConflict

    dsn, role, password = database
    repo = PostgresSecurityArtifacts(
        lambda: psycopg.connect(dsn, user=role, password=password),
        tenant_id=scope.tenant_id,
    )
    _, _, request, _ = rehearsal_bundle(scope, now)
    request = replace(request, request_id=uuid4().hex)
    repo.register(scope, request, actor_id="operator")

    def revoke(actor):
        try:
            repo.revoke(
                scope,
                request.fingerprint,
                expected_revision=1,
                actor_id=actor,
                reason="review",
            )
            return "revoked"
        except RepositoryConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(revoke, ("reviewer-a", "reviewer-b"))) == [
            "conflict",
            "revoked",
        ]


def test_continuous_drift_persists_deduplicated_hold_and_immutable_review(
    database, scope, now
):
    import psycopg
    from modernization_support import rehearsal_bundle
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.adapters.postgres_governance import PostgresSecurityHolds
    from sova_security.application.assessment import AssessmentService
    from sova_security.application.continuous_security import ContinuousSecurityMonitor
    from sova_security.domain.continuous_security import RuntimeSecurityBaseline
    from sova_security.domain.remediation import TestedArtifact as Artifact

    scope = replace(scope, resource_id="monitor-" + uuid4().hex)
    inputs, accepted, _, _ = rehearsal_bundle(scope, now)
    baseline = RuntimeSecurityBaseline(
        scope,
        "e" * 64,
        Artifact(
            scope,
            inputs[0].image_digest,
            inputs[0].source_digest,
            inputs[0].configuration_digest,
            "f" * 64,
        ),
        inputs[0].resource_revision,
        accepted,
        now + timedelta(seconds=1),
        now + timedelta(hours=1),
    )
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    artifacts = PostgresSecurityArtifacts(connect, tenant_id=scope.tenant_id)
    holds = PostgresSecurityHolds(connect, tenant_id=scope.tenant_id)
    artifacts.register(scope, baseline, actor_id="deployment-registry")
    changed = replace(inputs[0], image_digest="0" * 64)
    state = {
        "inputs": (
            changed,
            replace(
                inputs[1],
                inventory_digest=changed.fingerprint,
                image_digest=changed.image_digest,
            ),
            replace(inputs[2], inventory_digest=changed.fingerprint),
            inputs[3],
        )
    }
    service = ContinuousSecurityMonitor(
        assessment_service=AssessmentService(
            authorize=lambda *_: None,
            authenticate_input=lambda *_: None,
            current_inputs=lambda _: state["inputs"],
            clock=lambda: now + timedelta(seconds=4),
        ),
        current_inputs=lambda _: state["inputs"],
        baseline_provider=lambda _: artifacts.get(scope, baseline.fingerprint).value,
        authenticate_baseline=lambda _: None,
        artifacts=artifacts,
        holds=holds,
        authorize=lambda *_: None,
        clock=lambda: now + timedelta(seconds=4),
    )
    first = service.run_once("monitor", scope=scope)
    assert first.triggers == ("artifact-drift",)
    assert artifacts.get(scope, first.fingerprint).value == first
    service.run_once("monitor", scope=scope)
    active = tuple(
        v for v in holds.active_holds(scope.application_id) if v.hold.scope == scope
    )
    assert len(active) == 1
    state["inputs"] = inputs
    assert service.run_once("monitor", scope=scope).triggers == ()
    assert (
        tuple(
            v for v in holds.active_holds(scope.application_id) if v.hold.scope == scope
        )
        == active
    )


def test_configuration_report_storage_preserves_scope_and_revocation(
    database, scope, now
):
    from sova_security.contracts.repositories import RepositoryConflict
    import json
    import psycopg
    from prowler_support import configuration_registration, event
    from sova_security.adapters.prowler_reports import prowler_configuration
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts

    scope = replace(scope, resource_id="configuration-" + uuid4().hex)
    registration = configuration_registration(scope, now)
    report = json.dumps(
        [event(registration, now, check=c) for c in registration.expected_checks]
    ).encode()
    snapshot = prowler_configuration(report, registration=registration, now=now)
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    artifacts = PostgresSecurityArtifacts(connect, tenant_id=scope.tenant_id)
    for value in (registration, snapshot):
        artifacts.register(scope, value, actor_id="registered-collector")
        assert artifacts.get(scope, value.fingerprint).value == value
    with pytest.raises(ContractError, match="scope mismatch"):
        artifacts.register(
            replace(scope, resource_id="foreign"), snapshot, actor_id="collector"
        )
    foreign = PostgresSecurityArtifacts(connect, tenant_id="tenant-b")
    with pytest.raises(RecordNotFound):
        foreign.get(replace(scope, tenant_id="tenant-b"), snapshot.fingerprint)
    artifacts.revoke(
        scope,
        snapshot.fingerprint,
        expected_revision=1,
        actor_id="security-owner",
        reason="collector-revoked",
    )
    with pytest.raises(RepositoryConflict):
        artifacts.get(scope, snapshot.fingerprint)


def test_signed_prowler_collection_uses_existing_evidence_and_pg_repositories(
    database, scope, now
):
    import hashlib
    import json
    import psycopg
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from prowler_support import configuration_registration, event
    from sova_security.adapters.ed25519_evidence import (
        Ed25519EvidenceSigner,
        Ed25519EvidenceVerifier,
    )
    from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.application.signed_evidence import SignedEvidenceAuthority
    from sova_security.application.configuration_scan import (
        ConfigurationAssessmentService,
        COLLECTOR,
    )
    from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
    from sova_security.domain.signed_evidence import VerifierTrust

    scope = replace(scope, resource_id="signed-config-" + uuid4().hex)
    registration = configuration_registration(scope, now)
    raw = json.dumps(
        [event(registration, now, check=c) for c in registration.expected_checks]
    ).encode()
    record = EvidenceRecord(
        uuid4().hex,
        "prowler-collection:" + registration.fingerprint,
        scope,
        registration.revisions,
        COLLECTOR,
        now,
        now + timedelta(minutes=1),
        VerificationResult.PASS,
        "synthetic-raw-report",
        hashlib.sha256(raw).hexdigest(),
    )
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="independent-collector",
        key_id="ephemeral-test-key",
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (COLLECTOR,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    state = {"trust": trust, "raw": raw}
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    artifacts = PostgresSecurityArtifacts(connect, tenant_id=scope.tenant_id)
    artifacts.register(scope, registration, actor_id="policy-owner")
    signed = SignedEvidenceAuthority(
        PostgresSignedEvidence(connect, tenant_id=scope.tenant_id),
        Ed25519EvidenceVerifier(lambda *_: state["trust"]),
        clock=lambda: now,
    )
    signed.ingest(signer.sign(record, issued_at=now))
    service = ConfigurationAssessmentService(
        registration_provider=lambda _: (
            artifacts.get(scope, registration.fingerprint).value
        ),
        report_provider=lambda _: (state["raw"], record),
        authenticate_registration=lambda r: (
            artifacts.get(scope, r.fingerprint).value == r
        ),
        authenticate_report=signed.authenticate,
        authorize=lambda *_: None,
        artifacts=artifacts,
        clock=lambda: now,
    )
    result = service.collect("operator", scope=scope)
    assert result.all_selected_checks_pass
    assert artifacts.get(scope, result.fingerprint).value == result
    state["raw"] = raw + b" "
    with pytest.raises(ContractError, match="does not bind"):
        service.collect("operator", scope=scope)
    state["raw"] = raw
    state["trust"] = replace(trust, revoked=True)
    with pytest.raises(ContractError):
        service.collect("operator", scope=scope)


def test_team_control_contract_stores_without_copying_commands_or_claiming_runtime(
    database, scope, now
):
    from team_controls_support import team_control_bundle
    from sova_security.adapters.team_control_results import import_control_run
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.adapters.modernization_codec import encode
    from sova_security.contracts.repositories import RepositoryConflict
    import json
    import psycopg

    body, profile, observed = team_control_bundle()
    profile = replace(
        profile,
        scope=replace(profile.scope, resource_id="team-controls-" + uuid4().hex),
    )
    imported = import_control_run(
        json.dumps(body).encode(), registration=profile, now=observed
    )
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    repository = PostgresSecurityArtifacts(connect, tenant_id=profile.scope.tenant_id)
    for value in (profile, imported):
        repository.register(profile.scope, value, actor_id="team-collector")
        assert repository.get(profile.scope, value.fingerprint).value == value
    assert "curl -s" not in encode(imported)
    assert "excerpt" not in encode(imported)
    repository.revoke(
        profile.scope,
        imported.fingerprint,
        expected_revision=1,
        actor_id="security-owner",
        reason="probe-version-revoked",
    )
    with pytest.raises(RepositoryConflict):
        repository.get(profile.scope, imported.fingerprint)


def test_assessment_input_key_revocation_is_live_in_postgres(database, scope):
    import psycopg
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from modernization_support import rehearsal_bundle
    from sova_security.adapters.assessment_evidence import (
        AssessmentInputAuthority,
        assessment_input_record,
    )
    from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
    from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova_security.adapters.postgres_verifier_registry import (
        PostgresVerifierRegistry,
    )
    from sova_security.domain.signed_evidence import VerifierTrust
    from sova_security.domain.verifier_registry import VerifierTrustChange
    from sova_security.contracts.evidence import RevisionSet

    now = datetime.now(UTC)
    scope = replace(scope, resource_id="signed-input-" + uuid4().hex)
    inputs, _, _, _ = rehearsal_bundle(scope, now)
    value = inputs[0]
    revisions = RevisionSet(
        value.source_digest, value.configuration_digest, inputs[3].fingerprint, "e" * 64
    )
    record = assessment_input_record(
        value, revisions=revisions, evidence_id="input-" + uuid4().hex
    )
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="collector-" + uuid4().hex,
        key_id="test-only-key",
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (record.verifier_version,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=20),
    )
    change = VerifierTrustChange(
        scope.tenant_id,
        scope.application_id,
        1,
        trust,
        "requester",
        "approver",
        "controlled-test-registration",
        now,
        now + timedelta(minutes=5),
    )
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    registry = PostgresVerifierRegistry(
        connect, tenant_id=scope.tenant_id, application_id=scope.application_id
    )
    registry.publish(change)
    signed = PostgresSignedEvidence(connect, tenant_id=scope.tenant_id)
    envelope = signer.sign(record, issued_at=now)
    signed.save_envelope(envelope)
    state = {"armed": False, "calls": 0}

    def authorize(*_):
        state["calls"] += 1
        if state["armed"] and state["calls"] == 2:
            registry.publish(
                replace(change, revision=2, trust=replace(trust, revoked=True))
            )
        return True

    authority = AssessmentInputAuthority(
        envelope_provider=lambda *_: signed.get_envelope(
            scope.application_id, record.evidence_id
        ),
        current_revisions=lambda _: revisions,
        issuers_for=lambda *_: (signer.issuer_id,),
        resolve_trust=registry.resolve,
        authorize=authorize,
        clock=lambda: datetime.now(UTC),
    )
    assert authority("operator", scope, value) is None
    state.update(armed=True, calls=0)
    with pytest.raises(ContractError, match="revoked"):
        authority("operator", scope, value)
    assert registry.resolve(signer.issuer_id, signer.key_id).revoked
    assert signed.get_envelope(scope.application_id, record.evidence_id) == envelope


def test_kev_match_uses_signed_collection_and_scoped_pg_without_publishing_exposure(
    database, scope, now
):
    import psycopg
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from exploitation_support import intelligence_bundle
    from sova_security.adapters.ed25519_evidence import (
        Ed25519EvidenceSigner, Ed25519EvidenceVerifier,
    )
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
    from sova_security.application.exploitation_intelligence import ExploitationIntelligenceService
    from sova_security.application.signed_evidence import SignedEvidenceAuthority
    from sova_security.domain.signed_evidence import VerifierTrust
    from sova_security.domain.verifier_registry import VerifierTrustChange

    now = datetime.now(UTC)
    scope = replace(scope, resource_id="kev-" + uuid4().hex)
    inputs, catalog, record, _ = intelligence_bundle(scope, now)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="kev-" + uuid4().hex,
        key_id="ephemeral-test-key",
    )
    trust = VerifierTrust(
        signer.issuer_id, signer.key_id, signer.public_key_hex, (scope,),
        (record.verifier_version,), now - timedelta(seconds=1),
        now + timedelta(hours=2),
    )
    change = VerifierTrustChange(
        scope.tenant_id, scope.application_id, 1, trust, "requester", "approver",
        "controlled-kev-collector-registration", now, now + timedelta(minutes=5),
    )
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    artifacts = PostgresSecurityArtifacts(connect, tenant_id=scope.tenant_id)
    registry = PostgresVerifierRegistry(
        connect, tenant_id=scope.tenant_id, application_id=scope.application_id,
    )
    registry.publish(change)
    signed = SignedEvidenceAuthority(
        PostgresSignedEvidence(connect, tenant_id=scope.tenant_id),
        Ed25519EvidenceVerifier(registry.resolve), clock=lambda: now,
    )
    signed.ingest(signer.sign(record, issued_at=now))
    service = ExploitationIntelligenceService(
        current_inputs=lambda _: inputs, catalog_provider=lambda _: (catalog, record),
        current_revisions=lambda _: record.revisions,
        minimum_catalog_version=lambda _: "2026.10.30",
        # Input authentication is covered independently by the live input authority tests.
        authenticate_input=lambda *_: True, authenticate_catalog=signed.authenticate,
        authorize=lambda *_: None, artifacts=artifacts, clock=lambda: now,
    )
    matched, candidate = service.propose("operator", scope=scope)
    assert artifacts.get(scope, matched.fingerprint).value == matched
    assert candidate.known_exploited == ("CVE-2099-0001",)
    assert inputs[2].known_exploited == ()
    with pytest.raises(RecordNotFound):
        artifacts.get(scope, candidate.fingerprint)
    foreign = PostgresSecurityArtifacts(connect, tenant_id="other-tenant")
    with pytest.raises(RecordNotFound):
        foreign.get(replace(scope, tenant_id="other-tenant"), matched.fingerprint)
    registry.publish(replace(change, revision=2, trust=replace(trust, revoked=True)))
    with pytest.raises(ContractError):
        service.propose("operator", scope=scope)
    # Historical match remains audit data; revocation does not turn it into current authority.
    assert artifacts.get(scope, matched.fingerprint).value == matched


def test_monitor_rechecks_live_input_key_after_audit_write_and_preserves_hold(
    database, scope
):
    import psycopg
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from modernization_support import rehearsal_bundle
    from sova_security.adapters.assessment_evidence import (
        AssessmentInputAuthority,
        assessment_input_record,
    )
    from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
    from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
    from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova_security.adapters.postgres_verifier_registry import (
        PostgresVerifierRegistry,
    )
    from sova_security.adapters.postgres_governance import PostgresSecurityHolds
    from sova_security.application.assessment import AssessmentService
    from sova_security.application.continuous_security import ContinuousSecurityMonitor
    from sova_security.contracts.evidence import RevisionSet
    from sova_security.domain.continuous_security import RuntimeSecurityBaseline
    from sova_security.domain.remediation import TestedArtifact as Artifact
    from sova_security.domain.signed_evidence import VerifierTrust
    from sova_security.domain.verifier_registry import VerifierTrustChange

    now = datetime.now(UTC)
    scope = replace(scope, resource_id="monitor-key-" + uuid4().hex)
    original, accepted, *_ = rehearsal_bundle(scope, now)
    inventory = replace(original[0], image_digest="0" * 64)
    inputs = (
        inventory,
        replace(
            original[1],
            inventory_digest=inventory.fingerprint,
            image_digest=inventory.image_digest,
        ),
        replace(original[2], inventory_digest=inventory.fingerprint),
        original[3],
    )
    revisions = RevisionSet(
        inventory.source_digest,
        inventory.configuration_digest,
        inputs[3].fingerprint,
        "f" * 64,
    )
    records = {
        v.fingerprint: assessment_input_record(
            v, revisions=revisions, evidence_id=uuid4().hex
        )
        for v in inputs
    }
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="monitor-" + uuid4().hex,
        key_id="test-only-key",
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        tuple(r.verifier_version for r in records.values()),
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
    )
    change = VerifierTrustChange(
        scope.tenant_id,
        scope.application_id,
        1,
        trust,
        "requester",
        "approver",
        "controlled-monitor-key",
        now,
        now + timedelta(minutes=2),
    )
    dsn, role, password = database

    def connect():
        return psycopg.connect(dsn, user=role, password=password)

    registry = PostgresVerifierRegistry(
        connect, tenant_id=scope.tenant_id, application_id=scope.application_id
    )
    registry.publish(change)
    signed = PostgresSignedEvidence(connect, tenant_id=scope.tenant_id)
    for record in records.values():
        signed.save_envelope(signer.sign(record, issued_at=now))
    authority = AssessmentInputAuthority(
        envelope_provider=lambda a, s, v: signed.get_envelope(
            s.application_id, records[v.fingerprint].evidence_id
        ),
        current_revisions=lambda _: revisions,
        issuers_for=lambda *_: (signer.issuer_id,),
        resolve_trust=registry.resolve,
        authorize=lambda *_: None,
        clock=lambda: now + timedelta(seconds=2),
    )
    baseline = RuntimeSecurityBaseline(
        scope,
        "e" * 64,
        Artifact(
            scope,
            original[0].image_digest,
            original[0].source_digest,
            original[0].configuration_digest,
            "f" * 64,
        ),
        original[0].resource_revision,
        accepted,
        now + timedelta(seconds=1),
        now + timedelta(hours=1),
    )
    holds = PostgresSecurityHolds(connect, tenant_id=scope.tenant_id)
    state = {"revoked": False}

    class RevokingStore(PostgresSecurityArtifacts):
        def register(self, subject, value, *, actor_id):
            receipt = super().register(subject, value, actor_id=actor_id)
            if not state["revoked"]:
                registry.publish(
                    replace(change, revision=2, trust=replace(trust, revoked=True))
                )
                state["revoked"] = True
            return receipt

    service = ContinuousSecurityMonitor(
        assessment_service=AssessmentService(
            authorize=lambda *_: None,
            authenticate_input=authority,
            current_inputs=lambda _: inputs,
            clock=lambda: now + timedelta(seconds=2),
        ),
        current_inputs=lambda _: inputs,
        baseline_provider=lambda _: baseline,
        # Baseline registration authentication is independent of this input-key race test.
        authenticate_baseline=lambda _: None,
        artifacts=RevokingStore(connect, tenant_id=scope.tenant_id),
        holds=holds,
        authorize=lambda *_: None,
        clock=lambda: now + timedelta(seconds=2),
    )
    with pytest.raises(ContractError, match="revoked"):
        service.run_once("monitor", scope=scope)
    assert state["revoked"]
    assert any(v.hold.scope == scope for v in holds.active_holds(scope.application_id))
