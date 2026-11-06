"""Render operator-owned PostgreSQL ingress rules; never apply or read secrets."""

from ipaddress import ip_network
import re

from sova_security.contracts.commands import ContractError


def reader_hba_rules(*, role, database, client_networks):
    """Dedicated direct-reader ingress, placed before any broader matching rule.

    PostgreSQL roles are cluster-wide. Database-local RLS cannot constrain a
    stolen login's connections to other databases. These rules supplement the
    existing SELECT/RLS boundary; they do not terminate established sessions,
    configure a pooler, or prove that the operator installed them.
    """
    for value in (role, database):
        if type(value) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
            raise ContractError("Explicit lowercase database and dedicated reader role required")
    if role in {"postgres", "streaming_replica", "cnpg_pooler_pgbouncer"} or role.startswith("pg_"):
        raise ContractError("Operator, replication and pooler identities cannot be review readers")
    if type(client_networks) not in (tuple, list) or not 1 <= len(client_networks) <= 16:
        raise ContractError("One to sixteen explicit client CIDRs required")
    networks = []
    for value in client_networks:
        if type(value) is not str or len(value) > 64:
            raise ContractError("Canonical numeric client CIDR required")
        try:
            network = ip_network(value, strict=True)
        except ValueError:
            raise ContractError("Canonical numeric client CIDR required") from None
        if (str(network) != value or network.prefixlen == 0 or network.is_multicast
                or network.network_address.is_unspecified or value in networks):
            raise ContractError("Distinct bounded client CIDRs required")
        networks.append(value)
    # Quoting also makes HBA keywords such as a database named 'all' literal.
    user = f'"{role}"'
    rules = [f'hostssl "{database}" {user} {network} scram-sha-256' for network in networks]
    for network in ("0.0.0.0/0", "::/0"):
        rules.extend((f"host all {user} {network} reject", f"host replication {user} {network} reject"))
    rules.append(f"local all {user} reject")
    return tuple(rules)
