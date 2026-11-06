import base64
from dataclasses import replace
from datetime import timedelta
import json
from types import SimpleNamespace

import pytest

from review_service_support import service_bundle
from sova_security.adapters.review_https import BearerCredential, HTTPSJSONTransport
from sova_security.adapters.review_identity import ExecCredentialProvider, TokenReviewAuthenticator, WorkloadGrant
from sova_security.contracts.commands import ContractError


def identity_bundle(scope, now):
    state, _, _ = service_bundle(scope, now)
    username, uid = "system:serviceaccount:security:test-worker", "test-account-uid"
    claims = dict(sub=username, aud=["security-review"], iat=int(now.timestamp()), nbf=int(now.timestamp()), exp=int((now + timedelta(minutes=1)).timestamp()))
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    # This unit fixture has no signature. Only the simulated online verifier accepts it.
    token = "test-header." + payload + ".test-signature"
    state.response = dict(apiVersion="authentication.k8s.io/v1", kind="TokenReview", status=dict(
        authenticated=True, audiences=["security-review"], user=dict(username=username, uid=uid)))
    state.grant = WorkloadGrant(username, uid, state.principal)
    state.calls = []

    def post(path, raw, credential):
        state.calls.append((path, json.loads(raw), credential))
        return json.dumps(state.response).encode()

    verifier = TokenReviewAuthenticator(audience="security-review", transport=SimpleNamespace(post=post),
                                       reviewer_credential=lambda: BearerCredential("reviewer-test-token", now + timedelta(minutes=2)),
                                       grant_for=lambda *_: state.grant, clock=lambda: state.now)
    return state, verifier, token


def test_online_audience_uid_and_current_grant_are_required(scope, now):
    state, verifier, token = identity_bundle(scope, now)
    principal = verifier(token)
    assert principal.subject_id == state.principal.subject_id
    assert principal.valid_until == now + timedelta(minutes=1)
    assert state.calls[0][0] == "/apis/authentication.k8s.io/v1/tokenreviews"
    assert state.calls[0][1]["spec"] == {"token": token, "audiences": ["security-review"]}
    state.response["status"]["authenticated"] = False
    assert verifier(token) is None
    assert len(state.calls) == 2  # no successful authentication cache


@pytest.mark.parametrize("audience", ["security-review", ["security-review"]])
def test_exact_short_lived_audience_still_requires_current_online_verification(scope, now, audience):
    state, verifier, token = identity_bundle(scope, now)
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    claims.update(aud=audience, exp=claims["iat"] + 600)
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    candidate = "test-header." + payload + ".test-signature"
    assert verifier(candidate) is not None
    state.response["status"]["authenticated"] = False
    assert verifier(candidate) is None
    assert len(state.calls) == 2


@pytest.mark.parametrize("fault", ["missing-audience", "two-audiences", "duplicate-audience", "wrong-type",
                                  "too-long", "old-but-not-expired", "zero-lifetime", "multiple-returned-audiences"])
def test_scope_and_original_lifetime_cannot_be_widened_by_positive_tokenreview(scope, now, fault):
    state, verifier, token = identity_bundle(scope, now)
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    if fault == "missing-audience":
        del claims["aud"]
    elif fault == "two-audiences":
        claims["aud"].append("kubernetes-api")
    elif fault == "duplicate-audience":
        claims["aud"] *= 2
    elif fault == "wrong-type":
        claims["aud"] = {"security-review": True}
    elif fault == "too-long":
        claims["exp"] = claims["iat"] + 601
    elif fault == "old-but-not-expired":
        claims["iat"] -= 86400  # Remaining TTL is short; original lifetime is not.
    elif fault == "zero-lifetime":
        claims["exp"] = claims["iat"]
    else:
        state.response["status"]["audiences"].append("kubernetes-api")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    candidate = "test-header." + payload + ".test-signature"
    assert verifier(candidate) is None
    assert len(state.calls) == (1 if fault == "multiple-returned-audiences" else 0)


@pytest.mark.parametrize("fault", ["audience", "uid", "subject", "error", "truthy", "missing-auth", "no-grant", "revoked", "expired", "reviewer-expired", "clock-backwards", "transport"])
def test_tokenreview_fails_closed(scope, now, fault):
    state, verifier, token = identity_bundle(scope, now)
    status = state.response["status"]
    if fault == "audience":
        status["audiences"] = ["kubernetes-default"]
    elif fault == "uid":
        status["user"]["uid"] = "replacement-account"
    elif fault == "subject":
        status["user"]["username"] = "system:serviceaccount:other:worker"
    elif fault == "error":
        status["error"] = "private-diagnostic"
    elif fault == "truthy":
        status["authenticated"] = 1
    elif fault == "missing-auth":
        del status["authenticated"]
    elif fault == "no-grant":
        state.grant = None
    elif fault == "revoked":
        state.grant = replace(state.grant, principal=replace(state.principal, issued_at=now - timedelta(minutes=2), valid_until=now))
    elif fault == "expired":
        state.now += timedelta(minutes=1)
    elif fault == "reviewer-expired":
        verifier.reviewer_credential = lambda: BearerCredential("reviewer-test-token", now)
    elif fault == "clock-backwards":
        state.now -= timedelta(seconds=1)
    else:
        def fail(*_args):
            raise RuntimeError("private-diagnostic")
        verifier.transport.post = fail
    assert verifier(token) is None


@pytest.mark.parametrize("token", ["", "a.b.c", "abc", "a.!!!!.b", "a\rb", "a b", "x" * 16385])
def test_invalid_credentials_do_not_reach_tokenreview(scope, now, token):
    state, verifier, _ = identity_bundle(scope, now)
    assert verifier(token) is None and not state.calls


def test_existing_exec_provider_consumed_without_new_issuer(now):
    response = dict(apiVersion="client.authentication.k8s.io/v1", kind="ExecCredential", status={
        "token": "test-only-opaque-token", "expirationTimestamp": (now + timedelta(minutes=1)).isoformat()})
    provider = ExecCredentialProvider(lambda: response, clock=lambda: now)
    value = provider()
    assert value.token == response["status"]["token"] and value.token not in repr(value)
    response["status"]["expirationTimestamp"] = now.isoformat()
    with pytest.raises(ContractError):
        provider()


@pytest.mark.parametrize("origin", ["http://localhost", "https://user:password@example.com", "https://example.com/path", "https://example.com?q=secret", "https://example.com/#fragment"])
def test_https_origin_cannot_redirect_credentials(origin):
    with pytest.raises(ContractError):
        HTTPSJSONTransport(origin)


def test_tls_verification_cannot_be_disabled():
    import ssl
    context = ssl.create_default_context()
    context.check_hostname = False
    with pytest.raises(ContractError):
        HTTPSJSONTransport("https://localhost", tls_context=context)

