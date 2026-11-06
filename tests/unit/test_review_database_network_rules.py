"""Pure operator ingress rendering; no database connection."""

import pytest

from sova_security.adapters.review_database_network import reader_hba_rules
from sova_security.contracts.commands import ContractError


def test_rules_bind_exact_database_identity_tls_and_client_networks():
    rules = reader_hba_rules(role="review_reader", database="all", client_networks=["10.42.0.0/16", "fd00::/64"])
    assert rules[:2] == ('hostssl "all" "review_reader" 10.42.0.0/16 scram-sha-256',
                         'hostssl "all" "review_reader" fd00::/64 scram-sha-256')
    assert rules[2:] == ('host all "review_reader" 0.0.0.0/0 reject',
                         'host replication "review_reader" 0.0.0.0/0 reject',
                         'host all "review_reader" ::/0 reject',
                         'host replication "review_reader" ::/0 reject',
                         'local all "review_reader" reject')


@pytest.mark.parametrize("field,value", [
    ("role", "postgres"), ("role", "streaming_replica"), ("role", "cnpg_pooler_pgbouncer"),
    ("role", "pg_monitor"), ("role", "reader\nlocal all all trust"), ("role", "+readers"),
    ("role", 'r"'), ("role", "r,"), ("role", "r" * 64), ("role", True),
    ("database", "db,postgres"), ("database", "/.*"), ("database", "@list"), ("database", None),
    ("client_networks", []), ("client_networks", "127.0.0.1/32"),
    ("client_networks", ["0.0.0.0/0"]), ("client_networks", ["::/0"]),
    ("client_networks", ["0.0.0.0/32"]), ("client_networks", ["::/128"]),
    ("client_networks", ["224.0.0.0/4"]), ("client_networks", ["ff00::/8"]),
    ("client_networks", ["10.42.1.1/16"]), ("client_networks", ["10.42.0.0"]),
    ("client_networks", ["db.example.invalid"]), ("client_networks", ["samehost"]),
    ("client_networks", ["127.0.0.1/32\nlocal all all trust"]),
    ("client_networks", ["127.0.0.1/32"] * 2),
    ("client_networks", [f"10.42.0.{i}/32" for i in range(1, 18)]),
])
def test_rules_reject_expanded_or_ambiguous_ingress(field, value):
    arguments = dict(role="review_reader", database="security", client_networks=["127.0.0.1/32"])
    arguments[field] = value
    with pytest.raises(ContractError):
        reader_hba_rules(**arguments)
