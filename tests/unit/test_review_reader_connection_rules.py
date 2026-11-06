import pytest

from sova_security.adapters.review_database import reader_statements
from sova_security.contracts.commands import ContractError


@pytest.mark.parametrize("limit", [-1, 0, 65, True, False, None, "16", 2.0])
def test_reader_budget_rejects_unbounded_or_ambiguous_limits(limit):
    with pytest.raises(ContractError):
        reader_statements(role="review_reader", tenant_id="tenant-a", connection_limit=limit)


def test_reader_budget_renders_operator_selected_limit_without_connecting():
    assert reader_statements(role="review_reader", tenant_id="tenant-a")[0].as_string().endswith("CONNECTION LIMIT 16")
    assert reader_statements(role="review_reader", tenant_id="tenant-a", connection_limit=2)[0].as_string().endswith("CONNECTION LIMIT 2")
