from contextlib import contextmanager

import psycopg
import pytest

from postgres_cleanup_support import drop_fixture_reader


class CleanupConnection:
    autocommit = True

    def __init__(self, failures):
        self.failures = list(failures)
        self.attempts = self.committed = self.rolled_back = 0

    @contextmanager
    def transaction(self):
        self.attempts += 1
        try:
            yield
        except Exception:
            self.rolled_back += 1
            raise
        else:
            self.committed += 1

    def execute(self, statement):
        assert statement.as_string().startswith(('DROP OWNED BY "review_reader_', 'DROP ROLE "review_reader_'))
        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure


def test_cleanup_retries_only_rolled_back_deadlock(monkeypatch):
    monkeypatch.setattr('postgres_cleanup_support.time.sleep', lambda _: None)
    connection = CleanupConnection([None, psycopg.errors.DeadlockDetected('owned fixture race')])
    drop_fixture_reader(connection, 'review_reader_' + 'a' * 32)
    assert (connection.attempts, connection.rolled_back, connection.committed) == (2, 1, 1)


def test_cleanup_stops_after_three_deadlocks(monkeypatch):
    monkeypatch.setattr('postgres_cleanup_support.time.sleep', lambda _: None)
    connection = CleanupConnection([psycopg.errors.DeadlockDetected('owned fixture race')] * 3)
    with pytest.raises(psycopg.errors.DeadlockDetected):
        drop_fixture_reader(connection, 'review_reader_' + 'a' * 32)
    assert (connection.attempts, connection.rolled_back, connection.committed) == (3, 3, 0)


def test_cleanup_does_not_retry_unexpected_errors():
    connection = CleanupConnection([psycopg.errors.InsufficientPrivilege('unexpected')])
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        drop_fixture_reader(connection, 'review_reader_' + 'a' * 32)
    assert connection.attempts == 1


@pytest.mark.parametrize('role', ['postgres', 'reader', 'review_reader_bad', None])
def test_cleanup_rejects_non_fixture_roles(role):
    connection = CleanupConnection([])
    with pytest.raises(ValueError):
        drop_fixture_reader(connection, role)
    assert connection.attempts == 0
