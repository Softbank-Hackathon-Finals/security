from dataclasses import replace
from datetime import timedelta
import json
import ssl

import pytest

from review_service_support import service_bundle
from tls_review_support import certificates, tls_server
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.remote_review import RemoteReviewClient
from sova_security.adapters.review_https import BearerCredential, HTTPSJSONTransport, ReviewTransportError
from sova_security.domain.security_program import ProgramPhase
from sova_security.interfaces.review_asgi import SecurityReviewApp


def test_actual_tls_client_identity_revocation_and_server_outage(scope, now, tmp_path):
    state, endpoint, request = service_bundle(scope, now)
    with tls_server(SecurityReviewApp(endpoint), tmp_path) as (origin, ca):
        transport = HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)))
        client = RemoteReviewClient(transport=transport,
            credential_for=lambda: BearerCredential(state.token, now + timedelta(minutes=1)),
            current_registration=lambda *_: state.registration, subject_id=state.principal.subject_id,
            clock=lambda: state.now)
        kwargs = dict(scope=scope, subject_digest=state.registration.program.subject_digest, phase=ProgramPhase.PREFLIGHT)
        assert client.review(**kwargs).review.passed
        state.principal = replace(state.principal, modes=("shadow",))
        with pytest.raises(ReviewTransportError):
            client.review(**kwargs)
        assert client.review(**kwargs, mode="shadow").review.passed
        state.evidence = ()
        assert not client.review(**kwargs, mode="shadow").review.passed
    with pytest.raises(ReviewTransportError):
        client.review(**kwargs, mode="shadow")


def test_actual_tls_rejects_wrong_ca_and_hostname(scope, now, tmp_path):
    state, endpoint, request = service_bundle(scope, now)
    credential = BearerCredential(state.token, now + timedelta(minutes=1))
    with tls_server(SecurityReviewApp(endpoint), tmp_path, dns_only=True) as (origin, ca):
        wrong_ca, *_ = certificates(tmp_path, name="wrong")
        for url, trust in ((origin, wrong_ca), (origin, ca)):
            transport = HTTPSJSONTransport(url, tls_context=ssl.create_default_context(cafile=str(trust)))
            with pytest.raises(ReviewTransportError):
                transport.post("/v1/program-reviews", encode(request).encode(), credential)
        assert not state.audit


@pytest.mark.parametrize("fault", ["redirect", "oversize", "compressed", "wrong-type", "truncated", "duplicate-length"])
def test_actual_http_response_rejection_never_retries_or_follows_redirect(scope, now, tmp_path, fault):
    state, _, request = service_bundle(scope, now)
    calls = []

    async def app(_scope, receive, send):
        calls.append(True)
        while (await receive()).get("more_body", False):
            pass
        body = b"{}"
        headers = [(b"content-type", b"application/json")]
        status = 200
        if fault == "redirect":
            status = 307
            headers.append((b"location", b"https://example.invalid/credential-leak"))
        elif fault == "oversize":
            body = b" " * 2049
        elif fault == "compressed":
            headers.append((b"content-encoding", b"gzip"))
        elif fault == "wrong-type":
            headers = [(b"content-type", b"text/html")]
        elif fault == "truncated":
            headers.append((b"content-length", b"100"))
        else:
            headers.extend([(b"content-length", b"2"), (b"content-length", b"9")])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    with tls_server(app, tmp_path) as (origin, ca):
        transport = HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)), max_response=1024)
        with pytest.raises(ReviewTransportError):
            transport.post("/v1/program-reviews", encode(request).encode(), BearerCredential(state.token, now + timedelta(minutes=1)))
    assert len(calls) == 1


def test_wire_output_has_no_authorization_capability(scope, now, tmp_path):
    state, endpoint, request = service_bundle(scope, now)
    with tls_server(SecurityReviewApp(endpoint), tmp_path) as (origin, ca):
        context = ssl.create_default_context(cafile=str(ca))
        # Python 3.13+ enables this by default. Exercise it on older CI runtimes too.
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        transport = HTTPSJSONTransport(origin, tls_context=context)
        raw = transport.post("/v1/program-reviews", encode(request).encode(), BearerCredential(state.token, now + timedelta(minutes=1)))
    assert decode(raw).execution_authorized is False
    assert json.loads(raw)["value"]["execution_authorized"] is False
    assert state.token.encode() not in raw
