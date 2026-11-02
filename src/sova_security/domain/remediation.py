"""Content-bound remediation and sandbox verification contracts.

No shell commands or production authority. The host authenticates collectors,
Harbor admission and an independent verifier; structural hashes are not signatures.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
import re

from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    digest,
    identifier,
    utc,
)
from sova_security.contracts.evidence import VerificationResult
from sova_security.domain.assessment import Document, bounded_tuple


class Applicability(StrEnum):
    SOURCE_ONLY = "source_only"
    TARGET_ONLY = "target_only"
    BOTH = "both"


class TargetRole(StrEnum):
    SOURCE = "source"
    TARGET = "target"


class ChangeKind(StrEnum):
    PATCH = "patch"
    REBUILD = "rebuild"
    CONTAIN = "contain"
    ROTATE = "rotate"
    MIGRATE = "migrate"


PROTECTED_ROOTS = frozenset(
    {
        ".git",
        ".github",
        ".aws",
        ".ssh",
        "policies",
        "tests",
        "verifier",
        "verification",
        "audit",
        "secrets",
    }
)
PROTECTED_FILES = frozenset(
    {".env", ".gitleaks.toml", ".trivyignore", "pyproject.toml"}
)


def patch_path(path):
    identifier(path, "patch_path", limit=512)
    if re.fullmatch(r"[A-Za-z0-9_./@+\-]+", path) is None:
        raise ContractError("This patch profile supports ASCII portable paths only")
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or "\\" in path
        or ":" in path
        or path != candidate.as_posix()
        or any(p in {".", ".."} for p in candidate.parts)
        or not candidate.parts
    ):
        raise ContractError("Canonical relative patch path required")
    # Case-insensitive filesystems must not allow a differently-cased policy path.
    lowered = [p.casefold() for p in candidate.parts]
    if (
        any(p in PROTECTED_ROOTS for p in lowered)
        or candidate.name.casefold() in PROTECTED_FILES
        or candidate.name.casefold().startswith(".env.")
        or candidate.suffix.casefold() in {".pem", ".key", ".p12", ".pfx"}
    ):
        raise ContractError("Protected verification, policy or credential path")
    return path


def fix_test_id(finding_digest):
    digest(finding_digest)
    return "security-fix:" + finding_digest


@dataclass(frozen=True, slots=True)
class FileChange(Document):
    path: str
    before_digest: str | None
    after_digest: str | None

    def __post_init__(self):
        patch_path(self.path)
        if self.before_digest is None and self.after_digest is None:
            raise ContractError(
                "A file change must add, remove or replace a regular file"
            )
        for value in (self.before_digest, self.after_digest):
            if value is not None:
                digest(value)
        if self.before_digest == self.after_digest:
            raise ContractError("Unchanged files are not patch effects")


@dataclass(frozen=True, slots=True)
class RemediationProposal(Document):
    scope: ResourceScope
    assessment_digest: str
    inventory_digest: str
    policy_digest: str
    base_source_digest: str
    base_image_digest: str
    base_configuration_digest: str
    patch_artifact_digest: str
    kind: ChangeKind
    applicability: Applicability
    findings: tuple[str, ...]
    changes: tuple[FileChange, ...]
    created_by: str
    created_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if (
            not isinstance(self.scope, ResourceScope)
            or not isinstance(self.kind, ChangeKind)
            or not isinstance(self.applicability, Applicability)
        ):
            raise ContractError("Typed proposal scope/kind/applicability required")
        for name in (
            "assessment_digest",
            "inventory_digest",
            "policy_digest",
            "base_source_digest",
            "base_image_digest",
            "base_configuration_digest",
            "patch_artifact_digest",
        ):
            digest(getattr(self, name))
        identifier(self.created_by)
        bounded_tuple(self.findings, str, limit=16, nonempty=True)
        for finding in self.findings:
            digest(finding)
        bounded_tuple(
            self.changes, FileChange, limit=64, nonempty=self.kind == ChangeKind.PATCH
        )
        if len(set(self.findings)) != len(self.findings) or len(
            {c.path.casefold() for c in self.changes}
        ) != len(self.changes):
            raise ContractError(
                "Unique finding IDs and filesystem-safe patch paths required"
            )
        changed_paths = {c.path.casefold() for c in self.changes}
        if any(
            str(parent).casefold() in changed_paths
            for change in self.changes
            for parent in PurePosixPath(change.path).parents
            if str(parent) != "."
        ):
            raise ContractError(
                "Patch file paths cannot alias another changed file's directory"
            )
        object.__setattr__(self, "findings", tuple(sorted(self.findings)))
        object.__setattr__(
            self, "changes", tuple(sorted(self.changes, key=lambda c: c.path))
        )
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.created_at >= self.valid_until:
            raise ContractError("Positive proposal validity required")


@dataclass(frozen=True, slots=True)
class RehearsalTarget(Document):
    scope: ResourceScope
    role: TargetRole
    snapshot_digest: str
    base_image_digest: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.role, TargetRole
        ):
            raise ContractError("Typed registered rehearsal target required")
        digest(self.snapshot_digest)
        digest(self.base_image_digest)


@dataclass(frozen=True, slots=True)
class VerificationRequirement(Document):
    scope: ResourceScope
    test_id: str
    baseline_expected: VerificationResult | None

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed test target required")
        identifier(self.test_id)
        if self.baseline_expected is not None and self.baseline_expected not in {
            VerificationResult.PASS,
            VerificationResult.FAIL,
        }:
            raise ContractError("Explicit pass/fail baseline or no baseline required")
        if self.baseline_expected is not None and not isinstance(
            self.baseline_expected, VerificationResult
        ):
            raise ContractError("Typed baseline result required")


@dataclass(frozen=True, slots=True)
class SandboxProfile(Document):
    profile_id: str
    runner_image_digest: str
    egress_policy_digest: str
    verifier_image_digest: str
    test_bundle_digest: str
    max_seconds: int
    max_memory_mib: int
    allowed_files: tuple[str, ...]
    production_credentials_allowed: bool = False

    def __post_init__(self):
        identifier(self.profile_id)
        for name in (
            "runner_image_digest",
            "egress_policy_digest",
            "verifier_image_digest",
            "test_bundle_digest",
        ):
            digest(getattr(self, name))
        if self.production_credentials_allowed is not False:
            raise ContractError("Production credentials cannot enter rehearsal")
        if (
            type(self.max_seconds) is not int
            or not 1 <= self.max_seconds <= 3600
            or type(self.max_memory_mib) is not int
            or not 64 <= self.max_memory_mib <= 16384
        ):
            raise ContractError("Bounded sandbox time and memory required")
        bounded_tuple(self.allowed_files, str, limit=64, nonempty=True)
        for path in self.allowed_files:
            patch_path(path)
        if len({p.casefold() for p in self.allowed_files}) != len(self.allowed_files):
            raise ContractError("Unique allowed file paths required")
        object.__setattr__(self, "allowed_files", tuple(sorted(self.allowed_files)))


@dataclass(frozen=True, slots=True)
class RehearsalRequest(Document):
    request_id: str
    proposal: RemediationProposal
    profile: SandboxProfile
    targets: tuple[RehearsalTarget, ...]
    requirements: tuple[VerificationRequirement, ...]
    verifier_issuer: str
    created_at: datetime
    valid_until: datetime

    def __post_init__(self):
        identifier(self.request_id)
        identifier(self.verifier_issuer)
        if (
            isinstance(self.proposal, RemediationProposal)
            and self.verifier_issuer == self.proposal.created_by
        ):
            raise ContractError("Independent rehearsal verifier identity required")
        if not isinstance(self.proposal, RemediationProposal) or not isinstance(
            self.profile, SandboxProfile
        ):
            raise ContractError("Typed proposal and sandbox profile required")
        bounded_tuple(self.targets, RehearsalTarget, limit=2, nonempty=True)
        bounded_tuple(
            self.requirements, VerificationRequirement, limit=64, nonempty=True
        )
        if self.proposal.kind != ChangeKind.PATCH:
            raise ContractError(
                "This rehearsal profile supports regular-file patches only"
            )
        expected_roles = {
            Applicability.SOURCE_ONLY: {TargetRole.SOURCE},
            Applicability.TARGET_ONLY: {TargetRole.TARGET},
            Applicability.BOTH: {TargetRole.SOURCE, TargetRole.TARGET},
        }[self.proposal.applicability]
        if (
            {t.role for t in self.targets} != expected_roles
            or len({t.role for t in self.targets}) != len(self.targets)
            or len({t.scope for t in self.targets}) != len(self.targets)
        ):
            raise ContractError("Rehearsal target coverage differs from applicability")
        if any(
            (t.scope.tenant_id, t.scope.application_id)
            != (self.proposal.scope.tenant_id, self.proposal.scope.application_id)
            for t in self.targets
        ):
            raise ContractError("Rehearsal cannot cross tenant/application")
        if any(
            t.role == TargetRole.TARGET and t.scope == self.proposal.scope
            for t in self.targets
        ):
            raise ContractError(
                "Target-only verification cannot stand in for source coverage"
            )
        source = next((t for t in self.targets if t.role == TargetRole.SOURCE), None)
        if source is not None and (
            source.scope != self.proposal.scope
            or source.base_image_digest != self.proposal.base_image_digest
            or source.snapshot_digest != self.proposal.inventory_digest
        ):
            raise ContractError("Source rehearsal differs from the proposed inventory")
        if not {c.path for c in self.proposal.changes}.issubset(
            self.profile.allowed_files
        ):
            raise ContractError("Patch exceeds registered sandbox file scope")
        if len({(r.scope, r.test_id) for r in self.requirements}) != len(
            self.requirements
        ) or {r.scope for r in self.requirements} != {t.scope for t in self.targets}:
            raise ContractError(
                "Unique verification obligations for every target required"
            )
        for target in self.targets:
            # Security reproduction and functional/compatibility checks are not interchangeable.
            tests = {r.test_id: r for r in self.requirements if r.scope == target.scope}
            security_tests = {fix_test_id(f) for f in self.proposal.findings}
            if (
                not (
                    security_tests
                    | {"functional", "compatibility", "data-safety", "protection"}
                ).issubset(tests)
                or any(
                    tests[name].baseline_expected != VerificationResult.FAIL
                    for name in security_tests
                )
                or tests["functional"].baseline_expected != VerificationResult.PASS
                or tests["data-safety"].baseline_expected != VerificationResult.PASS
                or tests["protection"].baseline_expected != VerificationResult.PASS
            ):
                raise ContractError(
                    "Security, functional/compatibility, data-safety and protection obligations required"
                )
        object.__setattr__(
            self, "targets", tuple(sorted(self.targets, key=lambda t: str(t.role)))
        )
        object.__setattr__(
            self,
            "requirements",
            tuple(
                sorted(
                    self.requirements,
                    key=lambda r: (
                        r.scope.environment_id,
                        r.scope.resource_id,
                        r.test_id,
                    ),
                )
            ),
        )
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if (
            not self.proposal.created_at
            <= self.created_at
            < self.valid_until
            <= self.proposal.valid_until
        ):
            raise ContractError("Rehearsal exceeds proposal authorization window")


@dataclass(frozen=True, slots=True)
class TestedArtifact(Document):
    scope: ResourceScope
    image_digest: str
    source_digest: str
    configuration_digest: str
    provenance_digest: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed tested artifact scope required")
        for name in (
            "image_digest",
            "source_digest",
            "configuration_digest",
            "provenance_digest",
        ):
            digest(getattr(self, name))


@dataclass(frozen=True, slots=True)
class TestProof(Document):
    scope: ResourceScope
    test_id: str
    phase: str
    result: VerificationResult
    image_digest: str
    evidence_digest: str
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if (
            not isinstance(self.scope, ResourceScope)
            or not isinstance(self.result, VerificationResult)
            or self.phase not in {"before", "after"}
        ):
            raise ContractError("Typed scoped test result/phase required")
        identifier(self.test_id)
        digest(self.image_digest)
        digest(self.evidence_digest)
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.observed_at >= self.valid_until:
            raise ContractError("Positive test proof window required")


@dataclass(frozen=True, slots=True)
class RehearsalReceipt(Document):
    request_digest: str
    proposal_digest: str
    issuer_id: str
    runner_image_digest: str
    verifier_image_digest: str
    test_bundle_digest: str
    egress_policy_digest: str
    no_production_credentials: bool
    elapsed_seconds: int
    peak_memory_mib: int
    metadata_denied: VerificationResult
    egress_denied: VerificationResult
    changed_files: tuple[FileChange, ...]
    artifacts: tuple[TestedArtifact, ...]
    proofs: tuple[TestProof, ...]
    issued_at: datetime
    valid_until: datetime

    def __post_init__(self):
        for name in (
            "request_digest",
            "proposal_digest",
            "runner_image_digest",
            "verifier_image_digest",
            "test_bundle_digest",
            "egress_policy_digest",
        ):
            digest(getattr(self, name))
        identifier(self.issuer_id)
        if (
            type(self.no_production_credentials) is not bool
            or not isinstance(self.metadata_denied, VerificationResult)
            or not isinstance(self.egress_denied, VerificationResult)
        ):
            raise ContractError("Typed sandbox protection results required")
        if (
            type(self.elapsed_seconds) is not int
            or self.elapsed_seconds < 0
            or type(self.peak_memory_mib) is not int
            or self.peak_memory_mib < 0
        ):
            raise ContractError("Observed nonnegative sandbox resource usage required")
        bounded_tuple(self.changed_files, FileChange, limit=64)
        bounded_tuple(self.artifacts, TestedArtifact, limit=2, nonempty=True)
        bounded_tuple(self.proofs, TestProof, limit=128, nonempty=True)
        if (
            len({c.path.casefold() for c in self.changed_files})
            != len(self.changed_files)
            or len({a.scope for a in self.artifacts}) != len(self.artifacts)
            or len({(p.scope, p.test_id, p.phase) for p in self.proofs})
            != len(self.proofs)
        ):
            raise ContractError("Duplicate changed file, artifact or proof")
        object.__setattr__(
            self,
            "changed_files",
            tuple(sorted(self.changed_files, key=lambda c: c.path)),
        )
        object.__setattr__(
            self,
            "artifacts",
            tuple(
                sorted(
                    self.artifacts,
                    key=lambda a: (a.scope.environment_id, a.scope.resource_id),
                )
            ),
        )
        object.__setattr__(
            self,
            "proofs",
            tuple(
                sorted(
                    self.proofs,
                    key=lambda p: (
                        p.scope.environment_id,
                        p.scope.resource_id,
                        p.test_id,
                        p.phase,
                    ),
                )
            ),
        )
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.issued_at >= self.valid_until or any(
            not p.observed_at <= self.issued_at < p.valid_until for p in self.proofs
        ):
            raise ContractError(
                "Receipt must follow valid independent test observations"
            )


@dataclass(frozen=True, slots=True)
class RehearsalDecision(Document):
    request_digest: str
    receipt_digest: str
    allowed: bool
    reasons: tuple[str, ...]
    valid_until: datetime

    def __post_init__(self):
        digest(self.request_digest)
        digest(self.receipt_digest)
        if type(self.allowed) is not bool:
            raise ContractError("Explicit rehearsal decision required")
        bounded_tuple(self.reasons, str, limit=256)
        for reason in self.reasons:
            identifier(reason, limit=512)
        if self.allowed != (not self.reasons):
            raise ContractError("Rehearsal decision conflicts with unmet obligations")
        object.__setattr__(self, "valid_until", utc(self.valid_until))


def evaluate_rehearsal(request, receipt, *, now):
    if not isinstance(request, RehearsalRequest) or not isinstance(
        receipt, RehearsalReceipt
    ):
        raise ContractError("Typed rehearsal request and receipt required")
    now = utc(now)
    reasons = []
    if (
        not request.created_at <= now < request.valid_until
        or not receipt.issued_at <= now < receipt.valid_until
    ):
        reasons.append("expired-or-future")
    if (
        receipt.request_digest != request.fingerprint
        or receipt.proposal_digest != request.proposal.fingerprint
    ):
        reasons.append("request-binding-mismatch")
    profile = request.profile
    for name in (
        "runner_image_digest",
        "verifier_image_digest",
        "test_bundle_digest",
        "egress_policy_digest",
    ):
        if getattr(receipt, name) != getattr(profile, name):
            reasons.append("sandbox-binding:" + name)
    if (
        receipt.elapsed_seconds > profile.max_seconds
        or receipt.peak_memory_mib > profile.max_memory_mib
    ):
        reasons.append("sandbox-resource-limit-exceeded")
    if receipt.issuer_id != request.verifier_issuer:
        reasons.append("verifier-issuer-mismatch")
    if (
        not receipt.no_production_credentials
        or receipt.metadata_denied != VerificationResult.PASS
        or receipt.egress_denied != VerificationResult.PASS
    ):
        reasons.append("sandbox-protection-unverified")
    if receipt.changed_files != request.proposal.changes:
        reasons.append("unapproved-file-change")
    artifacts = {a.scope: a.image_digest for a in receipt.artifacts}
    targets = {t.scope: t for t in request.targets}
    if any(
        a.image_digest == targets[a.scope].base_image_digest
        or (
            a.scope == request.proposal.scope
            and a.source_digest == request.proposal.base_source_digest
        )
        for a in receipt.artifacts
        if a.scope in targets
    ):
        reasons.append("patch-artifact-did-not-change")
    if set(artifacts) != set(targets):
        reasons.append("artifact-target-coverage")
    proofs = {(p.scope, p.test_id, p.phase): p for p in receipt.proofs}
    expected = set()
    for req in request.requirements:
        for phase, expected_result in (
            ("before", req.baseline_expected),
            ("after", VerificationResult.PASS),
        ):
            if expected_result is None:
                continue
            key = (req.scope, req.test_id, phase)
            expected.add(key)
            proof = proofs.get(key)
            image = (
                targets[req.scope].base_image_digest
                if phase == "before"
                else artifacts.get(req.scope)
            )
            if (
                proof is None
                or proof.result != expected_result
                or proof.image_digest != image
                or not request.created_at
                <= proof.observed_at
                <= now
                < proof.valid_until
            ):
                reasons.append("missing-or-failed-proof:" + req.test_id + ":" + phase)
    if set(proofs) != expected:
        reasons.append("unexpected-proof-scope")
    deadline = min(
        request.valid_until,
        receipt.valid_until,
        *(p.valid_until for p in receipt.proofs),
    )
    return RehearsalDecision(
        request.fingerprint, receipt.fingerprint, not reasons, tuple(reasons), deadline
    )
