"""Online authentication and repeated registration checks around pure review."""

from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.review_service import (
    MAX_REVIEW_LIFETIME, RemoteProgramReview, ReviewPrincipal, ReviewRegistration,
    ReviewRequest, validate_review,
)


class ReviewServiceError(ContractError):
    def __init__(self, code):
        if code not in {"ACCESS_DENIED", "AUTHORITY_UNAVAILABLE", "CONTEXT_CHANGED", "AUDIT_UNAVAILABLE"}:
            raise ValueError("Fixed public error code required")
        self.code = code
        super().__init__(code)


class SecurityReviewEndpoint:
    def __init__(self, *, authenticate, registration_for, service_for, audit, clock):
        if not all(callable(v) for v in (authenticate, registration_for, service_for, audit, clock)):
            raise ContractError("Explicit authenticated service dependencies required")
        self.authenticate, self.registration_for, self.service_for = authenticate, registration_for, service_for
        self.audit, self.clock = audit, clock

    def _identity(self, credential, request):
        actor = self.authenticate(credential)
        if type(actor) is not ReviewPrincipal:
            raise ReviewServiceError("ACCESS_DENIED")
        try:
            actor.require(request.scope, request.mode, self.clock())
        except ContractError:
            raise ReviewServiceError("ACCESS_DENIED") from None
        return actor

    def _registration(self, actor, request):
        # Authorization happens before any tenant's repository/evidence lookup.
        actor.require(request.scope, request.mode, self.clock())
        registration = self.registration_for(actor, request.scope, request.context_digest)
        if (type(registration) is not ReviewRegistration or registration.fingerprint != request.context_digest
                or registration.scope != request.scope):
            raise ReviewServiceError("ACCESS_DENIED")
        registration.require_current(self.clock())
        for scope in {registration.program.source, registration.program.target}:
            actor.require(scope, request.mode, self.clock())
        return registration

    def review(self, credential, request):
        if type(request) is not ReviewRequest:
            raise ContractError("Typed bounded review request required")
        started = utc(self.clock())
        try:
            actor = self._identity(credential, request)
            registration = self._registration(actor, request)
            service = self.service_for(actor, registration, request.mode)
            review = service.review(
                actor.subject_id, scope=registration.scope,
                subject_digest=registration.program.subject_digest,
                phase=registration.phase, not_before=registration.not_before,
            )
            validate_review(review, registration)

            def current():
                if self._identity(credential, request) != actor or self._registration(actor, request) != registration:
                    raise ReviewServiceError("CONTEXT_CHANGED")
                now = utc(self.clock())
                if now < started or now - started >= MAX_REVIEW_LIFETIME:
                    raise ReviewServiceError("AUTHORITY_UNAVAILABLE")
                return now

            finished = current()
            # Receipt contains identifiers/digests only; no tokens, raw evidence or provider errors.
            event = dict(kind="security-review.v1", stage="computed", request_id=request.request_id,
                         context_digest=registration.fingerprint, principal_digest=actor.fingerprint,
                         review_digest=review.fingerprint, mode=request.mode,
                         passed=review.passed, observed_at=finished.isoformat())
            if self.audit(event) is not True:
                raise ReviewServiceError("AUDIT_UNAVAILABLE")
            finished = current()
            return RemoteProgramReview(
                registration.fingerprint, request.request_id, actor.subject_id, actor.fingerprint,
                registration.scope, request.mode, review, finished,
                min(started + MAX_REVIEW_LIFETIME, review.valid_until, registration.valid_until, actor.valid_until),
            )
        except ReviewServiceError as error:
            self._rejected(request, error.code)
            raise
        except Exception:
            # Even trusted adapters can include credentials in SDK exceptions.
            self._rejected(request, "AUTHORITY_UNAVAILABLE")
            raise ReviewServiceError("AUTHORITY_UNAVAILABLE") from None

    def _rejected(self, request, code):
        # A rejected request cannot become accepted because its audit sink fails.
        # The sink/collector must separately alert on write failures in deployment.
        try:
            self.audit(dict(kind="security-review.v1", stage="rejected", request_id=request.request_id,
                            context_digest=request.context_digest, mode=request.mode, code=code,
                            observed_at=utc(self.clock()).isoformat()))
        except Exception:
            pass
