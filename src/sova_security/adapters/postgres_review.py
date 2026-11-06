"""Read-only composition of the existing registered program/evidence stores."""

from sova_security.adapters.postgres_governance import PostgresSecurityHolds
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova_security.adapters.registered_program import RegisteredProgramAuthority
from sova_security.contracts.commands import ContractError
from sova_security.domain.review_service import ReviewPrincipal, ReviewRegistration


class PostgresReviewHost:
    """Use a SELECT-only non-owner role for connect_read; no schema installation.

    An independently authorized registrar stores/revokes ReviewRegistration via
    PostgresSecurityArtifacts. The network endpoint exposes no registration API.
    Authentication is still required; a PostgreSQL row is not issuer authority.
    """

    def __init__(self, connect_read, *, clock):
        self.connect_read, self.clock = connect_read, clock

    def registration_for(self, principal, scope, fingerprint):
        if type(principal) is not ReviewPrincipal or scope not in principal.scopes:
            raise ContractError("Authenticated principal scope required")
        artifacts = PostgresSecurityArtifacts(self.connect_read, tenant_id=principal.tenant_id)
        saved = artifacts.get(scope, fingerprint)
        if saved.revoked or type(saved.value) is not ReviewRegistration:
            raise ContractError("Active review registration required")
        return saved.value

    def service_for(self, principal, registration, mode):
        scope = registration.scope
        principal.require(scope, mode, self.clock())
        artifacts = PostgresSecurityArtifacts(self.connect_read, tenant_id=principal.tenant_id)
        signed = PostgresSignedEvidence(self.connect_read, tenant_id=principal.tenant_id)
        trust = PostgresVerifierRegistry(self.connect_read, tenant_id=principal.tenant_id, application_id=scope.application_id)
        holds = PostgresSecurityHolds(self.connect_read, tenant_id=principal.tenant_id)
        authority = RegisteredProgramAuthority(artifacts=artifacts, signed_evidence=signed,
            resolve_trust=trust.resolve, scope=scope, subject_digest=registration.program.subject_digest, clock=self.clock)

        def authorize(subject, target, _action):
            if subject != principal.subject_id:
                raise ContractError("Authenticated actor mismatch")
            principal.require(target, mode, self.clock())
            current = self.registration_for(principal, scope, registration.fingerprint)
            if current != registration or authority.current_program() != registration.program:
                raise ContractError("Current program/context registration changed")
            current.require_current(self.clock())
            return True

        def no_holds(target):
            principal.require(target, mode, self.clock())
            active = holds.active_holds(target.application_id)
            if type(active) is not tuple or active:
                raise ContractError("Application security hold requires independent resolution")
            return True

        return authority.service(authorize=authorize, require_no_holds=no_holds)
