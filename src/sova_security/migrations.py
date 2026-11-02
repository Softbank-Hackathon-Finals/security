"""Read-only migration resources. Applying migrations is a host/admin action."""

from importlib.resources import files
from sova_security.contracts.commands import ContractError

MIGRATIONS = (
    "postgres_governance_v1.sql",
    "postgres_governance_v2.sql",
    "postgres_protection_parity_v1.sql",
    "postgres_security_observations_v1.sql",
    "postgres_signed_evidence_v1.sql",
    "postgres_verifier_registry_v1.sql",
)


def migration_sql(name: str) -> str:
    if name not in MIGRATIONS:
        raise ContractError("Unknown security-owned migration")
    return (
        files("sova_security.adapters")
        .joinpath("sql", name)
        .read_text(encoding="utf-8")
    )
