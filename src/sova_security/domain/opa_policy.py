"""Operator-registered OPA policy and content-bound decisions, never permits."""

from dataclasses import dataclass
from datetime import datetime
import hashlib

from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    digest,
    identifier,
    utc,
)
from sova_security.contracts.evidence import Gate, VerificationObligation
from sova_security.domain.assessment import Document, bounded_tuple
from sova_security.contracts.plans import PlanPurpose

OPA_VERIFIER_VERSION = "sova.security.opa.v1"
OPA_QUERY = "data.sova.security.decision"


def validate_verdict(allowed, reasons):
    import re

    if type(allowed) is not bool:
        raise ContractError("Explicit OPA boolean verdict required")
    bounded_tuple(reasons, str, limit=64)
    if (
        len(set(reasons)) != len(reasons)
        or any(re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", r) is None for r in reasons)
        or allowed != (not reasons)
    ):
        raise ContractError("OPA verdict requires bounded unique machine reasons")


@dataclass(frozen=True, slots=True)
class OPAPolicy(Document):
    scope: ResourceScope
    policy_id: str
    revision: int
    source: str
    engine_digest: str
    capabilities_digest: str
    allowed_scopes: tuple[ResourceScope, ...]
    required: tuple[VerificationObligation, ...]
    issued_at: datetime
    valid_until: datetime
    purposes: tuple[PlanPurpose, ...] = (PlanPurpose.CHANGE,)

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed OPA scope required")
        identifier(self.policy_id)
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive OPA policy revision required")
        if type(self.source) is not str:
            raise ContractError("Registered Rego source required")
        try:
            source = self.source.encode("utf-8")
        except UnicodeError as exc:
            raise ContractError("UTF-8 Rego source required") from exc
        if not 1 <= len(source) <= 65536:
            raise ContractError("Bounded Rego policy required")
        digest(self.engine_digest)
        digest(self.capabilities_digest)
        bounded_tuple(self.purposes, PlanPurpose, limit=2, nonempty=True)
        if len(set(self.purposes)) != len(self.purposes) or not set(self.purposes) <= {
            PlanPurpose.CHANGE,
            PlanPurpose.MIGRATION_PHASE,
        }:
            raise ContractError(
                "This OPA profile supports ordinary change/migration phases only"
            )
        bounded_tuple(self.allowed_scopes, ResourceScope, limit=16, nonempty=True)
        bounded_tuple(self.required, VerificationObligation, limit=64, nonempty=True)
        if (
            self.scope not in self.allowed_scopes
            or len(set(self.allowed_scopes)) != len(self.allowed_scopes)
            or any(
                (s.tenant_id, s.application_id)
                != (self.scope.tenant_id, self.scope.application_id)
                for s in self.allowed_scopes
            )
            or len({o.obligation_id for o in self.required}) != len(self.required)
            or any(
                not o.required
                or o.due_gate > Gate.PREFLIGHT
                or o.scope not in self.allowed_scopes
                or o.verifier_version == OPA_VERIFIER_VERSION
                for o in self.required
            )
        ):
            raise ContractError("Explicit independent OPA control coverage required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.issued_at >= self.valid_until:
            raise ContractError("Positive OPA policy validity required")

    @property
    def source_digest(self):
        return hashlib.sha256(self.source.encode()).hexdigest()

    @property
    def obligation(self):
        return VerificationObligation(
            "opa-policy:" + self.fingerprint,
            self.scope,
            Gate.PREFLIGHT,
            OPA_VERIFIER_VERSION,
            True,
        )


@dataclass(frozen=True, slots=True)
class OPADecision(Document):
    scope: ResourceScope
    subject_digest: str
    policy_digest: str
    input_digest: str
    allowed: bool
    reasons: tuple[str, ...]
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or type(self.allowed) is not bool:
            raise ContractError("Typed OPA scope/verdict required")
        for name in ("subject_digest", "policy_digest", "input_digest"):
            digest(getattr(self, name))
        validate_verdict(self.allowed, self.reasons)
        object.__setattr__(self, "evaluated_at", utc(self.evaluated_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.evaluated_at >= self.valid_until:
            raise ContractError("Current OPA decision required")
