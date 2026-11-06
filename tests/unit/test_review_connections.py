from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from threading import Barrier
from types import SimpleNamespace

import pytest

from review_service_support import service_bundle
from sova_security.adapters.review_connections import RequestScopedReader
from sova_security.application.review_service import ReviewServiceError
from sova_security.contracts.commands import ContractError


def test_connection_reuse_is_request_local_and_always_closed():
    opened, validated, closed = [], [], []
    def create():
        value = SimpleNamespace(close=lambda: closed.append(value))
        opened.append(value)
        return value
    reader = RequestScopedReader(create, validate=lambda c: validated.append(c))
    with pytest.raises(ContractError):
        with reader.connect():
            pass
    with reader.request():
        with reader.connect() as first:
            with reader.connect() as second:
                assert first is second
        assert not closed
        with pytest.raises(ContractError):
            with reader.request():
                pass
    assert len(opened) == 1 and validated == [first, first] and closed == [first]
    with pytest.raises(ValueError):
        with reader.request():
            with reader.connect() as fresh:
                assert fresh is not first
                raise ValueError("controlled-test")
    assert closed == [first, fresh]


def test_concurrent_requests_never_share_a_connection():
    barrier = Barrier(2)
    reader = RequestScopedReader(lambda: SimpleNamespace(close=lambda: None), validate=lambda _: None)
    def work():
        with reader.request():
            with reader.connect() as connection:
                barrier.wait(timeout=3)
                return connection
    with ThreadPoolExecutor(max_workers=2) as executor:
        values = list(executor.map(lambda _: work(), range(2)))
    assert values[0] is not values[1]


@pytest.mark.parametrize("fault", ["policy", "deadline"])
def test_scope_exit_validation_cannot_return_old_pass(scope, now, fault):
    state, endpoint, request = service_bundle(scope, now)
    @contextmanager
    def lifetime():
        yield
        if fault == "policy":
            raise ContractError("controlled-policy-drift")
        state.now += timedelta(seconds=6)
    endpoint.review_scope = lifetime
    with pytest.raises(ReviewServiceError):
        endpoint.review(state.token, request)
