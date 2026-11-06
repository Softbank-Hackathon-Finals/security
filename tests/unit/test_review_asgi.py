import asyncio
import json
import threading

import pytest

from review_service_support import service_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.interfaces.review_asgi import SecurityReviewApp


async def invoke(app, token, raw, *, scheme="https", method="POST", path="/v1/program-reviews", extra=(), chunks=None):
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode()),
               (b"authorization", ("Bearer " + token).encode())]
    headers.extend(extra)
    messages = list(chunks) if chunks is not None else [{"type": "http.request", "body": raw}]
    response = []

    async def receive():
        return messages.pop(0)

    async def send(value):
        response.append(value)

    await app(dict(type="http", scheme=scheme, method=method, path=path, query_string=b"", headers=headers), receive, send)
    return response[0]["status"], response[1]["body"], response[0]["headers"]


def test_api_accepts_only_registered_review_request(scope, now):
    state, endpoint, request = service_bundle(scope, now)
    status, raw, headers = asyncio.run(invoke(SecurityReviewApp(endpoint), state.token, encode(request).encode()))
    assert status == 200 and decode(raw).review.passed
    assert (b"cache-control", b"no-store") in headers


@pytest.mark.parametrize("fault,status", [("http", 403), ("write", 404), ("duplicate-header", 400),
                                        ("encoding", 400), ("transfer", 400), ("oversize", 413),
                                        ("duplicate-json", 422), ("extra-field", 422), ("unregistered", 422),
                                        ("token", 403), ("short-body", 422)])
def test_api_rejects_ambiguous_or_untrusted_inputs(scope, now, fault, status):
    state, endpoint, request = service_bundle(scope, now)
    raw, token, kwargs = encode(request).encode(), state.token, {}
    if fault == "http":
        kwargs["scheme"] = "http"
    elif fault == "write":
        kwargs["path"] = "/v1/register"
    elif fault == "duplicate-header":
        kwargs["extra"] = ((b"authorization", b"Bearer different"),)
    elif fault == "encoding":
        kwargs["extra"] = ((b"content-encoding", b"gzip"),)
    elif fault == "transfer":
        kwargs["extra"] = ((b"transfer-encoding", b"chunked"),)
    elif fault == "oversize":
        raw = b" " * 16385
    elif fault == "duplicate-json":
        raw = raw.replace(b'"kind":', b'"kind":"security-review-request.v1","kind":', 1)
    elif fault == "extra-field":
        value = json.loads(raw)
        value["value"]["approved"] = True
        raw = json.dumps(value).encode()
    elif fault == "unregistered":
        raw = encode(state.registration).encode()
    elif fault == "token":
        token = "wrong-test-token"
    else:
        kwargs["chunks"] = [{"type": "http.request", "body": raw[:-1]}]
    observed, _, _ = asyncio.run(invoke(SecurityReviewApp(endpoint), token, raw, **kwargs))
    assert observed == status
    assert not state.audit or (fault == "token" and all(e["stage"] == "rejected" for e in state.audit))


def test_timed_out_worker_keeps_capacity_until_it_finishes(scope, now):
    state, endpoint, request = service_bundle(scope, now)
    release = threading.Event()
    original = endpoint.authenticate

    def blocking(token):
        assert release.wait(3)
        return original(token)

    endpoint.authenticate = blocking
    app = SecurityReviewApp(endpoint, concurrency=1, timeout=0.03)

    async def check():
        try:
            status, raw, _ = await invoke(app, state.token, encode(request).encode())
            assert status == 503 and json.loads(raw)["code"] == "SERVICE_DEADLINE_EXCEEDED"
            status, raw, _ = await invoke(app, state.token, encode(request).encode())
            assert status == 503 and json.loads(raw)["code"] == "SERVICE_BUSY"
        finally:
            release.set()
        for _ in range(100):
            await asyncio.sleep(0.01)
            if app.permits.acquire(blocking=False):
                app.permits.release()
                break
        else:
            pytest.fail("Completed worker did not release its capacity")
        app.timeout = 1  # Capacity recovery, independent of the deliberately tiny fault deadline.
        assert (await invoke(app, state.token, encode(request).encode()))[0] == 200

    asyncio.run(check())


def test_no_sdk_error_or_token_in_public_error(scope, now):
    state, endpoint, request = service_bundle(scope, now)

    def broken(*_):
        raise RuntimeError("private-provider-body: " + state.token)

    endpoint.service_for = broken
    status, raw, _ = asyncio.run(invoke(SecurityReviewApp(endpoint), state.token, encode(request).encode()))
    assert status == 503 and json.loads(raw) == {"code": "AUTHORITY_UNAVAILABLE"}
    assert state.token.encode() not in raw
