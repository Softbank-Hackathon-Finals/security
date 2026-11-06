"""Wire persisted program/route registrations to existing signed evidence stores.

The host must authorize and independently validate registrations before calling
the repositories' write APIs. Read-only workers cannot invent their own routes.
"""

from sova_security.adapters.program_evidence import SignedProgramEvidence
from sova_security.application.security_program import SecurityProgramService
from sova_security.contracts.commands import ContractError, ResourceScope, digest
from sova_security.contracts.repositories import RecordNotFound


class RegisteredProgramAuthority:
    def __init__(
        self, *, artifacts, signed_evidence, resolve_trust, scope, subject_digest, clock
    ):
        if not isinstance(scope, ResourceScope) or (
            artifacts.tenant_id != scope.tenant_id
            or signed_evidence.tenant_id != scope.tenant_id
        ):
            raise ContractError("Tenant-bound program repositories required")
        digest(subject_digest)
        self.artifacts = artifacts
        self.signed_evidence = signed_evidence
        self.scope = scope
        self.subject_digest = subject_digest
        self.clock = clock
        self.producers = SignedProgramEvidence(
            current_program=self.current_program,
            routes_for=lambda program: artifacts.program_routes(
                scope, program.fingerprint
            ),
            authenticate_route=self.authenticate_route,
            authenticate_routes=self.authenticate_routes,
            envelope_for=self.envelope_for,
            resolve_trust=resolve_trust,
            clock=clock,
        )

    def current_program(self):
        return self.artifacts.program(self.scope, self.subject_digest)

    def program_for(self, scope, subject_digest):
        if scope != self.scope or subject_digest != self.subject_digest:
            raise ContractError("Program authority belongs to another execution scope")
        return self.current_program()

    def authenticate_program(self, program):
        if self.current_program() != program:
            raise ContractError("Registered program changed or was revoked")
        return program

    def authenticate_route(self, route):
        saved = self.artifacts.get(self.scope, route.fingerprint)
        if (
            saved.revoked
            or saved.value != route
            or route.program_digest != self.current_program().fingerprint
        ):
            raise ContractError("Registered producer route changed or was revoked")
        return route

    def authenticate_routes(self, bundle):
        """Fresh complete repository read, not a cached collection assertion."""
        if type(bundle) is not tuple or len(bundle) != 2:
            raise ContractError("Exact registered program and route collection required")
        program, routes = bundle
        if (self.current_program() != program
                or self.artifacts.program_routes(self.scope, program.fingerprint) != routes):
            raise ContractError("Registered program route collection changed")
        return True

    def envelope_for(self, source):
        if (
            source.record.scope.tenant_id != self.scope.tenant_id
            or source.record.scope.application_id != self.scope.application_id
        ):
            raise ContractError("Producer lookup crosses tenant/application")
        try:
            return self.signed_evidence.current_envelope(
                source.record.scope,
                obligation_id=source.record.obligation_id,
                issuer_id=source.issuer_id,
            )
        except RecordNotFound:
            return None

    def service(self, *, authorize, require_no_holds):
        return SecurityProgramService(
            program_for=self.program_for,
            evidence_for=self.producers.evidence_for,
            authenticate_program=self.authenticate_program,
            authenticate_evidence=self.producers.authenticate_evidence,
            authenticate_evidence_batch=self.producers.authenticate_batch,
            authorize=authorize,
            require_no_holds=require_no_holds,
            clock=self.clock,
        )
