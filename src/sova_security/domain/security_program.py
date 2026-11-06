"""The two architecture proposals as evidence obligations, not a new executor.

The catalog is a versioned minimum. A host binds each check to its existing
verifier contract. Product names, installed tools and model text are not proofs.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sova_security.contracts.commands import ContractError, ResourceScope, digest, utc
from sova_security.contracts.evidence import (
    EvidenceRecord,
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult,
    evaluate_gate,
)
from sova_security.domain.assessment import Document, bounded_tuple


class ProgramKind(StrEnum):
    PATCH = "patch"
    MIGRATION = "migration"


class ProgramPhase(StrEnum):
    PREFLIGHT = "preflight"
    POSTFLIGHT = "postflight"


@dataclass(frozen=True, slots=True)
class ProgramCheck:
    check_id: str
    references: tuple[str, ...]
    phase: ProgramPhase
    role: str
    migration_only: bool = False


# References preserve the pasted documents' IDs. They do not rename the existing
# CC catalog, team T5 tests, or Sova Gate enum (whose numbers have other meanings).
P, Q = ProgramPhase.PREFLIGHT, ProgramPhase.POSTFLIGHT
CHECKS = (
    ProgramCheck(
        "risk-assessment", ("SEC-PATCH-01", "SEC-PATCH-02", "SG-2"), P, "source"
    ),
    ProgramCheck(
        "proposal-scope",
        ("SEC-PATCH-03", "CTRL-08", "CTRL-09", "POL-02", "POL-12"),
        P,
        "target",
    ),
    ProgramCheck(
        "sandbox-isolation", ("SEC-PATCH-04", "CTRL-03", "POL-04"), P, "target"
    ),
    ProgramCheck("rehearsal", ("SEC-PATCH-04", "POL-08"), P, "target"),
    ProgramCheck("source-compatibility", ("SEC-PATCH-04",), P, "source"),
    ProgramCheck("target-compatibility", ("SEC-PATCH-04",), P, "target"),
    ProgramCheck(
        "identity-boundary",
        ("CTRL-01", "CTRL-02", "CTRL-04", "POL-01", "SG-1"),
        P,
        "target",
    ),
    ProgramCheck("web-session", ("CTRL-05",), P, "target"),
    ProgramCheck("resource-budget", ("CTRL-07",), P, "target"),
    ProgramCheck("network-tls", ("POL-03", "SG-1"), P, "target"),
    ProgramCheck("artifact-provenance", ("CTRL-03", "POL-05"), P, "target"),
    ProgramCheck("approval-binding", ("SEC-PATCH-05", "POL-11", "SG-2"), P, "target"),
    ProgramCheck("effect-reconciliation", ("POL-09", "SG-2"), P, "target"),
    ProgramCheck("recovery-assets", ("CTRL-06", "POL-10", "SG-3"), P, "target"),
    ProgramCheck("protection-parity", ("SEC-PATCH-08", "POL-06"), P, "target", True),
    ProgramCheck("data-cutover", ("POL-07", "SG-3"), P, "target", True),
    ProgramCheck("runtime-verification", ("SEC-PATCH-06", "SG-2"), Q, "target"),
    ProgramCheck("patch-reassessment", ("SEC-PATCH-07",), Q, "target"),
    ProgramCheck(
        "recovery-verification", ("SEC-PATCH-06", "CTRL-06", "SG-3"), Q, "target"
    ),
    ProgramCheck("continuous-revalidation", ("SEC-PATCH-09",), Q, "target"),
    ProgramCheck("audit-trail", ("SEC-PATCH-10", "POL-10", "SG-2"), Q, "target"),
    ProgramCheck("runtime-parity", ("SEC-PATCH-08", "SG-3"), Q, "target", True),
)


def checks_for(kind):
    if not isinstance(kind, ProgramKind):
        raise ContractError("Typed security program kind required")
    return tuple(
        c for c in CHECKS if not c.migration_only or kind == ProgramKind.MIGRATION
    )


def obligation_id(subject_digest, check_id):
    digest(subject_digest)
    if check_id not in {c.check_id for c in CHECKS}:
        raise ContractError("Unknown security program check")
    return "security-program:" + subject_digest + ":" + check_id


@dataclass(frozen=True, slots=True)
class ProgramBinding(Document):
    check_id: str
    obligation: VerificationObligation
    revisions: RevisionSet

    def __post_init__(self):
        if (
            self.check_id not in {c.check_id for c in CHECKS}
            or not isinstance(self.obligation, VerificationObligation)
            or not self.obligation.required
            or not isinstance(self.revisions, RevisionSet)
        ):
            raise ContractError("Known mandatory program check and revisions required")


@dataclass(frozen=True, slots=True)
class SecurityProgram(Document):
    """Host registration for one exact change, including per-environment revisions.

    subject_digest is the existing plan/request digest, not a model-provided ID.
    The host authenticates this registration and re-resolves it on every use.
    """

    kind: ProgramKind
    subject_digest: str
    source: ResourceScope
    target: ResourceScope
    bindings: tuple[ProgramBinding, ...]
    issued_at: datetime
    valid_until: datetime
    catalog_version: str = "security-modernization.v1"

    def __post_init__(self):
        expected = checks_for(self.kind)
        digest(self.subject_digest)
        if (
            self.catalog_version != "security-modernization.v1"
            or not isinstance(self.source, ResourceScope)
            or not isinstance(self.target, ResourceScope)
            or (self.source.tenant_id, self.source.application_id)
            != (self.target.tenant_id, self.target.application_id)
            or (
                self.kind == ProgramKind.MIGRATION
                and self.source.environment_id == self.target.environment_id
            )
        ):
            raise ContractError("Registered same-application security program required")
        bounded_tuple(self.bindings, ProgramBinding, limit=64, nonempty=True)
        by_id = {b.check_id: b for b in self.bindings}
        if len(by_id) != len(self.bindings) or set(by_id) != {
            c.check_id for c in expected
        }:
            raise ContractError("Program omitted, duplicated or added a catalog check")
        # One bound proof cannot masquerade as several independent checks.
        if len({b.obligation.obligation_id for b in self.bindings}) != len(
            self.bindings
        ):
            raise ContractError("Distinct program obligation identities required")
        for check in expected:
            obligation = by_id[check.check_id].obligation
            scope = self.source if check.role == "source" else self.target
            gate = Gate.PREFLIGHT if check.phase == P else Gate.POSTFLIGHT
            if (
                obligation.scope != scope
                or obligation.due_gate != gate
                or obligation.obligation_id
                != obligation_id(self.subject_digest, check.check_id)
            ):
                raise ContractError("Program check scope or phase differs from catalog")
        object.__setattr__(
            self, "bindings", tuple(sorted(self.bindings, key=lambda b: b.check_id))
        )
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.issued_at >= self.valid_until:
            raise ContractError("Positive security program validity required")


@dataclass(frozen=True, slots=True)
class ProgramInput(Document):
    """Portable diagnostic input. Decoding never authenticates either member."""

    program: SecurityProgram
    evidence: tuple[EvidenceRecord, ...]

    def __post_init__(self):
        if not isinstance(self.program, SecurityProgram):
            raise ContractError("Typed security program required")
        bounded_tuple(self.evidence, EvidenceRecord)


@dataclass(frozen=True, slots=True)
class ProgramResult(Document):
    check_id: str
    references: tuple[str, ...]
    result: VerificationResult
    evidence_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ProgramReview(Document):
    program_digest: str
    subject_digest: str
    phase: ProgramPhase
    results: tuple[ProgramResult, ...]
    reviewed_at: datetime
    valid_until: datetime

    @property
    def passed(self):
        return bool(self.results) and all(
            r.result == VerificationResult.PASS for r in self.results
        )


def review_program(program, phase, evidence, *, now, not_before=None):
    """Pure diagnostic. Authentication and execution authority are outside here."""
    if not isinstance(program, SecurityProgram) or not isinstance(phase, ProgramPhase):
        raise ContractError("Typed program and phase required")
    bounded_tuple(evidence, EvidenceRecord)
    if len({r.evidence_id for r in evidence}) != len(evidence):
        raise ContractError("Duplicate program evidence identity")
    now = utc(now)
    if not_before is not None:
        not_before = utc(not_before)
        if phase != ProgramPhase.POSTFLIGHT or not_before > now:
            raise ContractError("Postflight observation boundary must precede review")
    if not program.issued_at <= now < program.valid_until:
        raise ContractError("Security program expired or not yet valid")
    by_id = {b.check_id: b for b in program.bindings}
    results, deadlines = [], [program.valid_until]
    for check in checks_for(program.kind):
        if check.phase != phase:
            continue
        binding = by_id[check.check_id]
        gate = evaluate_gate(
            binding.obligation.due_gate,
            (binding.obligation,),
            evidence,
            binding.revisions,
            now=now,
        )
        row = gate.decisions[0]
        result, reason = row.result, row.reason
        # Minimum controls cannot be waived by uploading N/A and an approver name.
        if result == VerificationResult.NOT_APPLICABLE:
            result, reason = (
                VerificationResult.UNKNOWN,
                "minimum_control_cannot_be_waived",
            )
        if row.evidence_id:
            chosen = next(r for r in evidence if r.evidence_id == row.evidence_id)
            if not_before is not None and chosen.observed_at < not_before:
                result, reason = (
                    VerificationResult.UNKNOWN,
                    "observation_precedes_operation",
                )
            if chosen.valid_until > now:
                deadlines.append(chosen.valid_until)
        results.append(
            ProgramResult(
                check.check_id, check.references, result, row.evidence_id, reason
            )
        )
    return ProgramReview(
        program.fingerprint,
        program.subject_digest,
        phase,
        tuple(results),
        now,
        min(deadlines),
    )
