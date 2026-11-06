"""Explicit registration for the team's control-run interoperability profile."""

from dataclasses import dataclass
from datetime import datetime
import re

from sova_security.contracts.commands import ContractError, ResourceScope, identifier
from sova_security.contracts.evidence import RevisionSet, EvidenceRecord
from sova_security.domain.assessment import Document, bounded_tuple, window

CONTROL_TEST = r"(SEC-01|ENC-01|ENC-02|AUD-01|NET-01|IAM-01|ISO-01|DR-01)\.[0-9]+"
OUTCOMES = {
    "deny",
    "allow",
    "present",
    "absent",
    "enabled",
    "disabled",
    "success",
    "failure",
}

CURRENT_SCHEMA_DIGEST = "f1273e751b31288c6d2ed927d888032474ce05f132dde7545bc12e2d9b38b654"
LEGACY_SCHEMA_DIGEST = "7c9728028af9c9d8bc45f5e8a8ba2b3ba0e38c96b7373b7338b49c8f37adfeb9"


@dataclass(frozen=True, slots=True)
class TeamControlBinding(Document):
    test_id: str
    method_version: str
    expected: str
    positive_control_required: bool

    def __post_init__(self):
        if (
            type(self.test_id) is not str
            or re.fullmatch(CONTROL_TEST, self.test_id) is None
        ):
            raise ContractError("Registered team control test ID required")
        if (
            type(self.method_version) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", self.method_version)
            is None
        ):
            raise ContractError("Registered team test method version required")
        if (
            self.expected not in OUTCOMES
            or type(self.positive_control_required) is not bool
        ):
            raise ContractError(
                "Explicit test outcome and positive-control requirement required"
            )
        if self.expected == "deny" and not self.positive_control_required:
            raise ContractError("Denial tests require a passing positive control")

    @property
    def verifier_version(self):
        return "team-bravo.control:" + self.test_id + ":" + self.method_version


@dataclass(frozen=True, slots=True)
class TeamControlRegistration(Document):
    scope: ResourceScope
    revisions: RevisionSet
    environment_ref: str
    role: str
    tests: tuple[TeamControlBinding, ...]
    maximum_evidence_age_seconds: int
    observed_at: datetime
    valid_until: datetime
    schema_digest: str = (
        "7c9728028af9c9d8bc45f5e8a8ba2b3ba0e38c96b7373b7338b49c8f37adfeb9"
    )

    def __post_init__(self):
        if self.schema_digest not in {LEGACY_SCHEMA_DIGEST, CURRENT_SCHEMA_DIGEST}:
            raise ContractError("Pinned team control schema required")
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed team scope/revision registration required")
        identifier(self.environment_ref)
        if self.role not in {"source", "target", "rehearsal"}:
            raise ContractError("Explicit team environment role required")
        bounded_tuple(self.tests, TeamControlBinding, limit=128, nonempty=True)
        if len({t.test_id for t in self.tests}) != len(self.tests):
            raise ContractError("Unique team test registration required")
        if (
            type(self.maximum_evidence_age_seconds) is not int
            or not 1 <= self.maximum_evidence_age_seconds <= 86400
        ):
            raise ContractError("Bounded team evidence freshness policy required")
        window(self)


@dataclass(frozen=True, slots=True)
class ImportedControlRun(Document):
    registration: TeamControlRegistration
    run_id: str
    report_digest: str
    evidence: tuple[EvidenceRecord, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        from sova_security.contracts.commands import digest

        if not isinstance(self.registration, TeamControlRegistration):
            raise ContractError("Registered team control import required")
        identifier(self.run_id)
        digest(self.report_digest)
        bounded_tuple(self.evidence, EvidenceRecord, limit=128, nonempty=True)
        expected = self.registration.tests
        if len(self.evidence) != len(expected) or any(
            record.scope != self.registration.scope
            or record.revisions != self.registration.revisions
            or record.obligation_id != "team-control:" + test.test_id
            or record.verifier_version != test.verifier_version
            or record.artifact_digest != self.report_digest
            for record, test in zip(self.evidence, expected, strict=True)
        ):
            raise ContractError("Imported records differ from registered team tests")
        window(self)
        if (
            not self.registration.observed_at
            <= self.observed_at
            < self.valid_until
            <= self.registration.valid_until
        ):
            raise ContractError("Imported control run exceeds registration window")
        if any(
            not record.observed_at
            <= self.observed_at
            < self.valid_until
            <= record.valid_until
            for record in self.evidence
        ):
            raise ContractError("Imported control run extends its underlying evidence")

    @property
    def scope(self):
        return self.registration.scope
