"""Authenticate current program evidence before composing existing execution gates."""

from sova_security.application.boundary import require_accept, require_authentication
from sova_security.contracts.commands import ContractError, utc
from sova_security.contracts.evidence import EvidenceRecord
from sova_security.domain.assessment import bounded_tuple
from sova_security.domain.security_program import SecurityProgram, review_program


class SecurityProgramService:
    def __init__(
        self,
        *,
        program_for,
        evidence_for,
        authenticate_program,
        authenticate_evidence,
        authorize,
        require_no_holds,
        clock,
    ):
        self.program_for = program_for
        self.evidence_for = evidence_for
        self.authenticate_program = authenticate_program
        self.authenticate_evidence = authenticate_evidence
        self.authorize = authorize
        self.require_no_holds = require_no_holds
        self.clock = clock

    def review(self, actor, *, scope, subject_digest, phase, not_before=None):
        require_accept(self.authorize, actor, scope, "security:review-program")
        program = self.program_for(scope, subject_digest)
        if (
            not isinstance(program, SecurityProgram)
            or program.target != scope
            or program.subject_digest != subject_digest
        ):
            raise ContractError("Current host-bound security program required")
        require_authentication(self.authenticate_program, program)
        # Authorize both environments before any producer lookup, not after
        # potentially disclosing source evidence to a target-only principal.
        for current_scope in {program.source, program.target}:
            require_accept(
                self.authorize, actor, current_scope, "security:review-program"
            )
            require_accept(self.require_no_holds, current_scope)
        evidence = self.evidence_for(program, phase)
        bounded_tuple(evidence, EvidenceRecord)

        def check_authority():
            for current_scope in {program.source, program.target}:
                require_accept(
                    self.authorize, actor, current_scope, "security:review-program"
                )
                require_accept(self.require_no_holds, current_scope)
            require_authentication(self.authenticate_program, program)
            for record in evidence:
                require_authentication(self.authenticate_evidence, record)
            if (
                self.program_for(scope, subject_digest) != program
                or self.evidence_for(program, phase) != evidence
            ):
                raise ContractError("Security program/evidence changed during review")

        started = utc(self.clock())
        check_authority()
        result = review_program(
            program, phase, evidence, now=started, not_before=not_before
        )
        check_authority()
        finished = utc(self.clock())
        if finished < started or finished >= result.valid_until:
            raise ContractError("Security program authority expired during review")
        # Re-evaluate freshness after callbacks; never return an old cached PASS.
        return review_program(
            program, phase, evidence, now=finished, not_before=not_before
        )
