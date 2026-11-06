"""Synthetic measurements and host identity, never a deployable authority."""

from datetime import timedelta
from types import SimpleNamespace

from program_support import program_bundle
from sova_security.application.review_service import SecurityReviewEndpoint
from sova_security.application.security_program import SecurityProgramService
from sova_security.domain.review_service import HostReviewBinding, ReviewPrincipal, ReviewRegistration, ReviewRequest
from sova_security.domain.security_program import ProgramPhase


def service_bundle(scope, now):
    program, evidence = program_bundle(scope, now)
    binding = HostReviewBinding("platform-t10", "f602b39a949b99f3e2e7be901103063e78a52a70",
                               "test-plan", program.subject_digest, "6" * 64, "full", "1")
    registration = ReviewRegistration(program, binding, ProgramPhase.PREFLIGHT, now, program.valid_until)
    principal = ReviewPrincipal("test-worker", scope.tenant_id, (program.source, program.target),
                                ("enforce", "shadow"), now, now + timedelta(minutes=2), "7" * 64)
    state = SimpleNamespace(now=now, registration=registration, principal=principal, evidence=evidence,
                            audit=[], token="test-only-token", lookups=0)

    def lookup(actor, target, fingerprint):
        state.lookups += 1
        assert actor.tenant_id == target.tenant_id
        return state.registration

    def service(actor, reg, mode):
        def authorize(subject, scope, _action):
            assert subject == actor.subject_id
            state.principal.require(scope, mode, state.now)
            return True

        return SecurityProgramService(
            program_for=lambda *_: state.registration.program,
            evidence_for=lambda *_: state.evidence,
            authenticate_program=lambda value: value == state.registration.program,
            authenticate_evidence=lambda value: value in state.evidence,
            authorize=authorize, require_no_holds=lambda *_: True, clock=lambda: state.now,
        )

    def audit(value):
        state.audit.append(value)
        return True

    endpoint = SecurityReviewEndpoint(
        authenticate=lambda token: state.principal if token == state.token else None,
        registration_for=lookup, service_for=service, audit=audit, clock=lambda: state.now,
    )
    request = ReviewRequest(scope, registration.fingerprint, "8" * 64, "enforce")
    return state, endpoint, request
