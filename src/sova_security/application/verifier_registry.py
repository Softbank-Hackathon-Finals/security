"""Administrative authorization is separate from issuer signature verification."""

from sova_security.application.boundary import require_accept, require_authentication

from sova_security.contracts.commands import ContractError


class VerifierRegistryAdministration:
    def __init__(self, repository, *, authorize, authenticate_approval, clock):
        if any(not callable(c) for c in (authorize, authenticate_approval, clock)):
            raise ContractError("Explicit verifier administration authorities required")
        self.repository = repository
        self.authorize = authorize
        self.authenticate_approval = authenticate_approval
        self.clock = clock

    def publish(self, actor, change):
        if actor != change.requested_by or (
            change.tenant_id,
            change.application_id,
        ) != (self.repository.tenant_id, self.repository.application_id):
            raise ContractError("Verifier administration actor/scope mismatch")
        require_accept(
            self.authorize,
            actor,
            change.tenant_id,
            change.application_id,
            "verifier-trust:request",
        )
        require_authentication(self.authenticate_approval, change)
        require_accept(
            self.authorize,
            change.approved_by,
            change.tenant_id,
            change.application_id,
            "verifier-trust:approve",
        )
        change.require_current(self.clock())
        return self.repository.publish(change)
