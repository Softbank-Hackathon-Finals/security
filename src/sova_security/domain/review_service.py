"""Registered remote-review contracts. No document is an execution capability."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import re

from sova_security.contracts.commands import ContractError, ResourceScope, digest, identifier, utc
from sova_security.contracts.evidence import VerificationResult
from sova_security.domain.assessment import Document, bounded_tuple
from sova_security.domain.security_program import (
    ProgramPhase, ProgramReview, SecurityProgram, checks_for,
)

MAX_REVIEW_LIFETIME = timedelta(seconds=5)
MODES = frozenset({"enforce", "shadow"})


@dataclass(frozen=True, slots=True)
class HostReviewBinding(Document):
    """Values copied from the trusted host, using its original digest rules.

    T10 post_apply and program postflight are independent axes. A migration
    preflight may legitimately consume a post_apply gate session.
    """

    host: str
    baseline_sha: str
    plan_id: str
    plan_digest: str
    context_digest: str
    profile_id: str
    profile_version: str
    gate_phase: str = "initial"
    application_id: str | None = None

    def __post_init__(self):
        if self.host not in {"sova", "platform-t10"}:
            raise ContractError("Known host required")
        if type(self.baseline_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", self.baseline_sha):
            raise ContractError("Pinned host source revision required")
        for value in (self.plan_id, self.profile_id):
            identifier(value)
        for value in (self.plan_digest, self.context_digest):
            digest(value)
        identifier(self.profile_version)
        if self.gate_phase not in {"initial", "post_apply"} or (
            (self.gate_phase == "post_apply") != (self.application_id is not None)
        ):
            raise ContractError("Host gate phase/application binding required")
        if self.application_id is not None:
            identifier(self.application_id)


@dataclass(frozen=True, slots=True)
class ReviewRegistration(Document):
    program: SecurityProgram
    host_binding: HostReviewBinding
    phase: ProgramPhase
    issued_at: datetime
    valid_until: datetime
    operation_id: str | None = None
    not_before: datetime | None = None

    def __post_init__(self):
        if type(self.program) is not SecurityProgram or type(self.host_binding) is not HostReviewBinding:
            raise ContractError("Typed current program and host binding required")
        if self.program.subject_digest != self.host_binding.plan_digest or type(self.phase) is not ProgramPhase:
            raise ContractError("Exact host plan and review phase required")
        start, end = utc(self.issued_at), utc(self.valid_until)
        if not self.program.issued_at <= start < end <= self.program.valid_until:
            raise ContractError("Review registration exceeds program lifetime")
        object.__setattr__(self, "issued_at", start)
        object.__setattr__(self, "valid_until", end)
        if self.phase == ProgramPhase.POSTFLIGHT:
            identifier(self.operation_id)
            boundary = utc(self.not_before)
            if boundary > start:
                raise ContractError("Postflight must follow the actual operation start")
            object.__setattr__(self, "not_before", boundary)
        elif self.not_before is not None or self.operation_id is not None:
            raise ContractError("Preflight cannot claim operation observations")

    @property
    def scope(self):
        return self.program.target

    def require_current(self, now):
        if not self.issued_at <= utc(now) < self.valid_until:
            raise ContractError("Review registration is not current")


@dataclass(frozen=True, slots=True)
class ReviewRequest(Document):
    scope: ResourceScope
    context_digest: str
    request_id: str
    mode: str

    def __post_init__(self):
        if type(self.scope) is not ResourceScope or self.mode not in MODES:
            raise ContractError("Exact scope and review mode required")
        digest(self.context_digest)
        digest(self.request_id)


@dataclass(frozen=True, slots=True)
class ReviewPrincipal(Document):
    """Produced only by a trusted online authenticator, never decoded from HTTP."""

    subject_id: str
    tenant_id: str
    scopes: tuple[ResourceScope, ...]
    modes: tuple[str, ...]
    issued_at: datetime
    valid_until: datetime
    grant_digest: str

    def __post_init__(self):
        identifier(self.subject_id)
        identifier(self.tenant_id)
        digest(self.grant_digest)
        bounded_tuple(self.scopes, ResourceScope, limit=64, nonempty=True)
        if len(set(self.scopes)) != len(self.scopes) or any(s.tenant_id != self.tenant_id for s in self.scopes):
            raise ContractError("Distinct same-tenant principal scopes required")
        bounded_tuple(self.modes, str, limit=2, nonempty=True)
        if len(set(self.modes)) != len(self.modes) or not set(self.modes) <= MODES:
            raise ContractError("Known principal permissions required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.issued_at >= self.valid_until:
            raise ContractError("Positive principal lifetime required")

    def require(self, scope, mode, now):
        if not (self.issued_at <= utc(now) < self.valid_until and scope in self.scopes and mode in self.modes):
            raise ContractError("Review access denied")


def validate_review(review, registration):
    if type(review) is not ProgramReview or (
        review.program_digest != registration.program.fingerprint
        or review.subject_digest != registration.program.subject_digest
        or review.phase != registration.phase
    ):
        raise ContractError("Review differs from registered program")
    expected = {c.check_id: c for c in checks_for(registration.program.kind) if c.phase == registration.phase}
    if len(review.results) != len(expected) or {r.check_id for r in review.results} != set(expected):
        raise ContractError("Review does not cover the registered minimum checks")
    for row in review.results:
        if row.references != expected[row.check_id].references or type(row.result) is not VerificationResult:
            raise ContractError("Review control semantics changed")
        if row.result == VerificationResult.NOT_APPLICABLE:
            raise ContractError("Remote minimum checks cannot be waived")
        identifier(row.reason)
        if row.evidence_id is not None:
            identifier(row.evidence_id)
        elif row.result == VerificationResult.PASS:
            raise ContractError("Remote PASS requires evidence identity")
    if not registration.issued_at <= utc(review.reviewed_at) < utc(review.valid_until) <= registration.program.valid_until:
        raise ContractError("Invalid remote review interval")


@dataclass(frozen=True, slots=True)
class RemoteProgramReview(Document):
    context_digest: str
    request_id: str
    subject_id: str
    principal_digest: str
    scope: ResourceScope
    mode: str
    review: ProgramReview
    issued_at: datetime
    valid_until: datetime
    execution_authorized: bool = False

    def __post_init__(self):
        for value in (self.context_digest, self.request_id, self.principal_digest):
            digest(value)
        identifier(self.subject_id)
        if type(self.scope) is not ResourceScope or self.mode not in MODES or type(self.review) is not ProgramReview:
            raise ContractError("Typed review response required")
        start, end = utc(self.issued_at), utc(self.valid_until)
        if not utc(self.review.reviewed_at) <= start < end <= min(self.review.valid_until, start + MAX_REVIEW_LIFETIME):
            raise ContractError("Invalid short-lived review response")
        object.__setattr__(self, "issued_at", start)
        object.__setattr__(self, "valid_until", end)
        if self.execution_authorized is not False:
            raise ContractError("Security reviews never authorize execution")

    def require_for(self, request, registration, *, subject_id, now):
        if (type(request) is not ReviewRequest or type(registration) is not ReviewRegistration
                or self.context_digest != request.context_digest or self.context_digest != registration.fingerprint
                or self.request_id != request.request_id or self.scope != request.scope
                or self.scope != registration.scope or self.mode != request.mode or self.subject_id != subject_id):
            raise ContractError("Remote response binding mismatch")
        registration.require_current(now)
        if self.valid_until > registration.valid_until:
            raise ContractError("Remote response exceeds local registration lifetime")
        if not self.issued_at <= utc(now) < min(self.valid_until, registration.valid_until):
            raise ContractError("Remote review expired or is from the future")
        validate_review(self.review, registration)
