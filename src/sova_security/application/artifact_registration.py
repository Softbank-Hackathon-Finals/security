"""Require a durable, scoped registration receipt before reporting persistence."""

from sova_security.contracts.commands import ContractError
from sova_security.ports.modernization import StoredSecurityArtifact


def register_artifact(repository, scope, value, *, actor_id):
    stored = repository.register(scope, value, actor_id=actor_id)
    if (
        not isinstance(stored, StoredSecurityArtifact)
        or stored.scope != scope
        or stored.value != value
        or stored.revision != 1
        or stored.revoked
        or repository.get(scope, value.fingerprint) != stored
    ):
        raise ContractError("Security artifact persistence was not confirmed")
    return stored
