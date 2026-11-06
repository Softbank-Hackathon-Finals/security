import pytest

from sova_security.adapters.review_database import reader_database_statements
from sova_security.contracts.commands import ContractError


@pytest.mark.parametrize("database", ["postgres", "template0", "template1", "shared;DROP DATABASE x", "a\nb", "../other", "", None])
def test_storage_prerequisites_reject_system_and_ambiguous_database_names(database):
    with pytest.raises(ContractError):
        reader_database_statements(database=database)


def test_storage_prerequisites_only_render_for_an_explicit_database():
    statements = tuple(value.as_string() for value in reader_database_statements(database="security_evidence"))
    assert statements[0] == 'REVOKE TEMPORARY ON DATABASE "security_evidence" FROM PUBLIC'
    assert len(statements) == 4
    assert all(value.startswith("REVOKE EXECUTE ON FUNCTION pg_catalog.lo_") for value in statements[1:])
