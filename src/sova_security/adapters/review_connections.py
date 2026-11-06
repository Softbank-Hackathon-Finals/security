"""One lazy read connection per request; no rows, grants or PASS cache."""

from contextlib import contextmanager
from contextvars import ContextVar

from sova_security.contracts.commands import ContractError


class RequestScopedReader:
    def __init__(self, open_connection, *, validate):
        self.open_connection, self.validate = open_connection, validate
        self.current = ContextVar("security_review_connection", default=None)

    @contextmanager
    def request(self):
        if self.current.get() is not None:
            raise ContractError("Nested review request context is not allowed")
        state = {"connection": None}
        token = self.current.set(state)
        try:
            yield
            if state["connection"] is not None:
                self.validate(state["connection"])
        finally:
            try:
                if state["connection"] is not None:
                    state["connection"].close()
            finally:
                self.current.reset(token)

    @contextmanager
    def connect(self):
        state = self.current.get()
        if state is None:
            raise ContractError("Explicit request-scoped reader required")
        if state["connection"] is None:
            state["connection"] = self.open_connection()
            self.validate(state["connection"])
        yield state["connection"]
