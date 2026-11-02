"""Compare current security with a registered accepted deployment baseline.

Baseline is historical deployment identity, not an extension of old evidence or
an execution permit. A separate authenticated registration bounds monitoring.
"""

from dataclasses import dataclass
from datetime import datetime

from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    digest,
    identifier,
    utc,
)
from sova_security.domain.assessment import (
    Assessment,
    AssetInventory,
    Document,
    bounded_tuple,
)
from sova_security.domain.remediation import TestedArtifact


@dataclass(frozen=True, slots=True)
class RuntimeSecurityBaseline(Document):
    scope: ResourceScope
    deployment_receipt_digest: str
    artifact: TestedArtifact
    resource_revision: str
    assessment: Assessment
    accepted_at: datetime
    monitor_until: datetime

    def __post_init__(self):
        if (
            not isinstance(self.scope, ResourceScope)
            or not isinstance(self.artifact, TestedArtifact)
            or not isinstance(self.assessment, Assessment)
            or self.artifact.scope != self.scope
            or self.assessment.scope != self.scope
            or not self.assessment.complete
        ):
            raise ContractError(
                "Accepted typed runtime baseline with complete assessment required"
            )
        digest(self.deployment_receipt_digest)
        identifier(self.resource_revision)
        object.__setattr__(self, "accepted_at", utc(self.accepted_at))
        object.__setattr__(self, "monitor_until", utc(self.monitor_until))
        if not (
            self.assessment.assessed_at
            <= self.accepted_at
            < self.assessment.valid_until
            and self.accepted_at < self.monitor_until
        ):
            raise ContractError(
                "Historical assessment must precede bounded baseline registration"
            )


@dataclass(frozen=True, slots=True)
class ContinuousSecurityReview(Document):
    scope: ResourceScope
    baseline_digest: str
    inventory_digest: str
    assessment_digest: str
    triggers: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed review scope required")
        for name in ("baseline_digest", "inventory_digest", "assessment_digest"):
            digest(getattr(self, name))
        bounded_tuple(self.triggers, str, limit=8)
        allowed = {
            "artifact-drift",
            "resource-revision-drift",
            "new-or-changed-risk",
            "unverified-current-security",
        }
        if (
            len(set(self.triggers)) != len(self.triggers)
            or not set(self.triggers) <= allowed
        ):
            raise ContractError("Known unique continuous-security triggers required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.observed_at >= self.valid_until:
            raise ContractError("Current review evidence required")


def review_runtime_security(baseline, inventory, assessment, *, now):
    if (
        not isinstance(baseline, RuntimeSecurityBaseline)
        or not isinstance(inventory, AssetInventory)
        or not isinstance(assessment, Assessment)
    ):
        raise ContractError(
            "Typed runtime baseline and current assessed inventory required"
        )
    now = utc(now)
    if (
        not baseline.accepted_at <= now < baseline.monitor_until
        or not inventory.observed_at <= now < inventory.valid_until
        or not assessment.assessed_at <= now < assessment.valid_until
    ):
        raise ContractError("Monitoring registration/evidence expired")
    if (
        baseline.scope != inventory.scope
        or baseline.scope != assessment.scope
        or assessment.inventory_digest != inventory.fingerprint
    ):
        raise ContractError("Continuous review crosses scope or inventory")
    triggers = []
    expected = baseline.artifact
    if (
        inventory.image_digest,
        inventory.source_digest,
        inventory.configuration_digest,
    ) != (expected.image_digest, expected.source_digest, expected.configuration_digest):
        triggers.append("artifact-drift")
    if inventory.resource_revision != baseline.resource_revision:
        triggers.append("resource-revision-drift")
    original = {d.fingerprint for d in baseline.assessment.decisions}
    if {d.fingerprint for d in assessment.decisions} - original:
        triggers.append("new-or-changed-risk")
    if not assessment.complete:
        triggers.append("unverified-current-security")
    return ContinuousSecurityReview(
        baseline.scope,
        baseline.fingerprint,
        inventory.fingerprint,
        assessment.fingerprint,
        tuple(triggers),
        now,
        min(baseline.monitor_until, inventory.valid_until, assessment.valid_until),
    )
