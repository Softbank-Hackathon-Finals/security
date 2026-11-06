from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from review_service_support import service_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.remote_review import RemoteReviewClient
from sova_security.adapters.review_https import BearerCredential
from sova_security.application.review_service import ReviewServiceError
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult
from sova_security.domain.review_service import ReviewRegistration
from sova_security.domain.security_program import ProgramPhase


def test_authenticated_review_binds_request_and_roundtrips(scope, now):
    state, endpoint, request = service_bundle(scope, now)
    response = endpoint.review(state.token, request)
    assert response.review.passed and response.execution_authorized is False
    assert response.valid_until == now + timedelta(seconds=5)
    assert response.principal_digest == state.principal.fingerprint
    response.require_for(request, state.registration, subject_id=state.principal.subject_id, now=now)
    for value in (request, state.registration, response):
        assert decode(encode(value).encode()) == value
    assert len(state.audit) == 1 and state.token not in str(state.audit)


@pytest.mark.parametrize("change", ["token", "tenant", "target", "source", "mode", "expired"])
def test_no_producer_lookup_before_target_authorization(scope, now, change):
    state, endpoint, request = service_bundle(scope, now)
    token = state.token
    if change == "token":
        token = "wrong-token"
    elif change == "tenant":
        request = replace(request, scope=replace(scope, tenant_id="other"))
    elif change == "target":
        request = replace(request, scope=replace(scope, resource_id="other"))
    elif change == "source":
        state.principal = replace(state.principal, scopes=(scope,))
    elif change == "mode":
        state.principal = replace(state.principal, modes=("shadow",))
    else:
        state.now += timedelta(minutes=3)
    original = endpoint.service_for
    called = []
    endpoint.service_for = lambda *args: called.append(True) or original(*args)
    with pytest.raises(ReviewServiceError):
        endpoint.review(token, request)
    assert not called
    if change != "source":
        assert state.lookups == 0


@pytest.mark.parametrize("change", ["grant", "registration", "audit-failure", "slow-audit", "clock-regression"])
def test_authority_changes_during_audit_never_escape_as_pass(scope, now, change):
    state, endpoint, request = service_bundle(scope, now)

    def audit(_event):
        if change == "grant":
            state.principal = replace(state.principal, grant_digest="9" * 64)
        elif change == "registration":
            state.registration = replace(state.registration, valid_until=now + timedelta(seconds=30))
        elif change == "audit-failure":
            return None
        elif change == "slow-audit":
            state.now += timedelta(seconds=5)
        else:
            state.now -= timedelta(seconds=1)
        return True

    endpoint.audit = audit
    with pytest.raises(ReviewServiceError):
        endpoint.review(state.token, request)


def test_arbitrary_adapter_exception_does_not_expose_credentials(scope, now):
    state, endpoint, request = service_bundle(scope, now)

    def broken(*args):
        raise RuntimeError("secret-bearing-provider-diagnostic")

    endpoint.registration_for = broken
    with pytest.raises(ReviewServiceError, match="AUTHORITY_UNAVAILABLE") as error:
        endpoint.review(state.token, request)
    assert "secret-bearing" not in str(error.value)
    assert error.value.__suppress_context__


def test_missing_and_failed_evidence_remain_unknown_and_fail(scope, now):
    state, endpoint, request = service_bundle(scope, now)
    state.evidence = ()
    response = endpoint.review(state.token, request)
    assert not response.review.passed
    assert all(row.result == VerificationResult.UNKNOWN for row in response.review.results)
    state, endpoint, request = service_bundle(scope, now)
    state.evidence = tuple(replace(e, result=VerificationResult.FAIL) for e in state.evidence)
    response = endpoint.review(state.token, request)
    assert all(row.result == VerificationResult.FAIL for row in response.review.results)


@pytest.mark.parametrize("change", ["request", "context", "subject", "mode", "expired", "future", "missing-check", "pass-without-evidence", "wrong-reference"])
def test_remote_response_cannot_be_rebound_or_weakened(scope, now, change):
    state, endpoint, request = service_bundle(scope, now)
    response = endpoint.review(state.token, request)
    if change == "request":
        request = replace(request, request_id="9" * 64)
    elif change == "context":
        request = replace(request, context_digest="9" * 64)
    elif change == "subject":
        response = replace(response, subject_id="different-worker")
    elif change == "mode":
        response = replace(response, mode="shadow")
    elif change == "expired":
        now += timedelta(seconds=5)
    elif change == "future":
        now -= timedelta(seconds=1)
    else:
        rows = list(response.review.results)
        if change == "missing-check":
            rows.pop()
        elif change == "pass-without-evidence":
            rows[0] = replace(rows[0], evidence_id=None)
        else:
            rows[0] = replace(rows[0], references=("invented",))
        response = replace(response, review=replace(response.review, results=tuple(rows)))
    with pytest.raises(ContractError):
        response.require_for(request, state.registration, subject_id=state.principal.subject_id, now=now)


def test_host_post_apply_does_not_automatically_mean_program_postflight(scope, now):
    state, endpoint, request = service_bundle(scope, now)
    binding = replace(state.registration.host_binding, gate_phase="post_apply", application_id="actual-apply")
    state.registration = replace(state.registration, host_binding=binding)
    request = replace(request, context_digest=state.registration.fingerprint)
    assert endpoint.review(state.token, request).review.phase == ProgramPhase.PREFLIGHT
    with pytest.raises(ContractError):
        replace(state.registration, phase=ProgramPhase.POSTFLIGHT)
    registration = replace(state.registration, phase=ProgramPhase.POSTFLIGHT, not_before=now, operation_id="actual-op")
    assert decode(encode(registration).encode()) == registration


def client_bundle(scope, now):
    state, endpoint, request = service_bundle(scope, now)
    calls = []

    def post(path, raw, credential):
        calls.append(raw)
        assert path == "/v1/program-reviews"
        return encode(endpoint.review(credential.token, decode(raw))).encode()

    client = RemoteReviewClient(transport=SimpleNamespace(post=post),
                               credential_for=lambda: BearerCredential(state.token, now + timedelta(minutes=1)),
                               current_registration=lambda *_: state.registration,
                               subject_id=state.principal.subject_id, clock=lambda: state.now)
    return state, endpoint, client, calls


def test_client_never_reuses_a_cached_success(scope, now):
    state, endpoint, client, calls = client_bundle(scope, now)
    kwargs = dict(scope=scope, subject_digest=state.registration.program.subject_digest, phase=ProgramPhase.PREFLIGHT)
    first = client.review(**kwargs)
    assert first.review.passed
    second = client.review(**kwargs)
    assert first.request_id != second.request_id and len(calls) == 2
    state.evidence = ()
    assert not client.review(**kwargs).review.passed
    assert len(calls) == 3


def test_client_rejects_replayed_response_and_changed_local_registration(scope, now):
    state, endpoint, client, calls = client_bundle(scope, now)
    kwargs = dict(scope=scope, subject_digest=state.registration.program.subject_digest, phase=ProgramPhase.PREFLIGHT)
    saved = client.review(**kwargs)
    client.transport.post = lambda *_: encode(saved).encode()
    with pytest.raises(ContractError):
        client.review(**kwargs)
    state, endpoint, client, calls = client_bundle(scope, now)
    original = client.transport.post

    def race(*args):
        response = original(*args)
        state.registration = replace(state.registration, valid_until=now + timedelta(seconds=20))
        return response

    client.transport.post = race
    with pytest.raises(ContractError):
        client.review(**kwargs)


def test_client_preserves_credential_expiry(scope, now):
    state, endpoint, client, _calls = client_bundle(scope, now)
    end = now + timedelta(seconds=1)
    client.credential_for = lambda: BearerCredential(state.token, end)
    response = client.review(scope=scope, subject_digest=state.registration.program.subject_digest, phase=ProgramPhase.PREFLIGHT)
    assert response.valid_until == end


@pytest.mark.parametrize("value", [None, True, "PASS", {}])
def test_decoding_or_truthy_values_do_not_establish_local_registration(scope, now, value):
    state, _endpoint, client, _calls = client_bundle(scope, now)
    client.current_registration = lambda *_: value
    with pytest.raises(ContractError):
        client.review(scope=scope, subject_digest=state.registration.program.subject_digest, phase=ProgramPhase.PREFLIGHT)


def test_registration_rejects_unbound_postflight_and_mutated_host_plan(scope, now):
    state, _, _ = service_bundle(scope, now)
    with pytest.raises(ContractError):
        replace(state.registration, host_binding=replace(state.registration.host_binding, plan_digest="9" * 64))
    with pytest.raises(ContractError):
        ReviewRegistration(state.registration.program, state.registration.host_binding, ProgramPhase.POSTFLIGHT,
                           now, state.registration.valid_until, "op", now + timedelta(seconds=1))
