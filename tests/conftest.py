from datetime import UTC, datetime
import pytest
from bravo_security.contracts.commands import ResourceScope


@pytest.fixture
def now():
    return datetime(2026, 10, 31, 7, 0, tzinfo=UTC)


@pytest.fixture
def scope():
    return ResourceScope("tenant-a", "app-a", "environment-a", "owned-ingress")
