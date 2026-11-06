"""Pinned T10 admission -> actual TLS process -> current signed PostgreSQL evidence.

T13/T14 measurements, token API and remote cutover executor are synthetic. Host
registration rows below are a test adapter, not a new platform migration.
"""

from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from platform_review_support import attach, platform_admission as pinned_admission
from review_runtime_support import registered_review_runtime
from test_postgres_boundary import database as isolated_database
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.platform_review import T10ProgramAuthority
from sova_security.adapters.remote_review import RemoteReviewClient
from sova_security.domain.review_service import ReviewPrincipal

database = isolated_database
platform_admission = pinned_admission
pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("platform_admission", [{"gate_phase": "initial"}, {"gate_phase": "post_apply"}], indirect=True)
@pytest.mark.parametrize("fault", [None, "producer-revoked", "service-registration-revoked", "host-registration-revoked", "workload-revoked"])
def test_real_platform_runtime_enforces_current_service_authority(platform_admission, database, tmp_path, fault):
    from bravo_platform_events.store import EventError

    f = platform_admission
    state, _ = attach(f, resource_id="runtime-" + uuid4().hex)
    registration = state["registration"]
    scope, now = registration.scope, f.state["now"]
    principal = ReviewPrincipal("service-worker", scope.tenant_id, (registration.program.source, scope),
        ("enforce", "shadow"), now, registration.valid_until, "9" * 64)
    # The same existing T10 plan transaction is used by this test registrar and
    # the admission reader. This is not an assertion of distributed DB atomicity.
    with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
        connection.execute("CREATE TABLE test_review_registration (plan_id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        connection.execute("INSERT INTO test_review_registration VALUES (?,?)", (f.plan.plan_id, encode(registration)))
    def locked_registration(connection, *_):
        assert connection.in_transaction
        row = connection.execute("SELECT body FROM test_review_registration WHERE plan_id=?", (f.plan.plan_id,)).fetchone()
        return decode(row["body"].encode()) if row else None
    def current_registration(*_):
        with f.store._transaction(write=False, plan_id=f.plan.plan_id) as connection:
            return locked_registration(connection)
    def clock():
        return datetime.now(UTC)
    with registered_review_runtime(database, tmp_path, registration=registration, evidence=state["evidence"], principal=principal, now=now) as runtime:
        client = RemoteReviewClient(transport=runtime.transport, credential_for=lambda: runtime.credential,
            current_registration=current_registration, subject_id=principal.subject_id, clock=clock)
        f.service.authority = T10ProgramAuthority(upstream=f.adapter, load_session=f.loader,
            load_registration=locked_registration, client=client, scope=scope, clock=clock, baseline_sha=f.platform_baseline)
        approved = f.approve()
        assert not f.requests
        if fault == "producer-revoked":
            change = runtime.trust_change
            runtime.trust_store.publish(replace(change, revision=2, trust=replace(change.trust, revoked=True)))
        elif fault == "service-registration-revoked":
            runtime.artifacts.revoke(scope, registration.fingerprint, expected_revision=1, actor_id="registrar", reason="test")
        elif fault == "host-registration-revoked":
            with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
                connection.execute("DELETE FROM test_review_registration WHERE plan_id=?", (f.plan.plan_id,))
        elif fault == "workload-revoked":
            runtime.issuer.active = False
        if fault:
            with pytest.raises(EventError):
                f.submit(approved)
            assert not f.requests
            assert f.store.snapshot(f.plan.plan_id)["state"] == "SHIFT"
        else:
            f.submit(approved)
            assert f.store.snapshot(f.plan.plan_id)["state"] == "SAFE_HOLD"
            f.submit(approved)
            assert [method for method, _ in f.requests] == ["POST", "GET"]
