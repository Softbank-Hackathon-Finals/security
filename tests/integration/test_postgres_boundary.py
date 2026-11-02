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
