import sys
from importlib.abc import MetaPathFinder
from datetime import UTC, datetime
import pytest
from bravo_security.contracts.commands import ResourceScope


@pytest.fixture
def now():
    return datetime(2026, 10, 31, 7, 0, tzinfo=UTC)


@pytest.fixture
def scope():
    return ResourceScope("tenant-a", "app-a", "environment-a", "owned-ingress")


# A development machine may already have Sova installed. Never let that mask
# an accidental host dependency in this standalone package's own tests.


class RejectHostImports(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "sova" or fullname.startswith("sova."):
            raise ModuleNotFoundError(
                "Standalone security tests must not import host Sova"
            )
        return None


_host_import_guard = RejectHostImports()


def pytest_sessionstart(session):
    assert not any(name == "sova" or name.startswith("sova.") for name in sys.modules)
    sys.meta_path.insert(0, _host_import_guard)


def pytest_sessionfinish(session, exitstatus):
    if _host_import_guard in sys.meta_path:
        sys.meta_path.remove(_host_import_guard)
