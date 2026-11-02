"""Independent post-patch scan comparison, separate from HTTP health.

Authenticate both snapshots and scanner invocations first. Passing this function
does not authorize deployment and does not prove scanner completeness on its own.
"""

from dataclasses import dataclass
from datetime import datetime

from sova_security.contracts.commands import ContractError, ResourceScope, digest, utc
from sova_security.domain.assessment import (
    Assessment,
    Document,
    Severity,
    assess_risk,
    bounded_tuple,
)
from sova_security.domain.remediation import RemediationProposal, TestedArtifact


@dataclass(frozen=True, slots=True)
class PatchReassessment(Document):
    scope: ResourceScope
    proposal_digest: str
    artifact_digest: str
    baseline_digest: str
    assessment_digest: str
    allowed: bool
    reasons: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or type(self.allowed) is not bool:
            raise ContractError("Typed patch reassessment scope and verdict required")
        for field in (
            "proposal_digest",
            "artifact_digest",
            "baseline_digest",
            "assessment_digest",
        ):
            digest(getattr(self, field))
        bounded_tuple(self.reasons, str, limit=16)
        if self.allowed != (not self.reasons):
            raise ContractError("Reassessment verdict differs from unresolved evidence")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.observed_at >= self.valid_until:
            raise ContractError("Positive reassessment validity required")


def reassess_patch(
    proposal,
    artifact,
    baseline,
    *,
    before_inputs,
    after_inputs,
    expected_policy_digest,
    not_before,
    now,
):
    """Strict initial profile: selected findings gone, no new/increased findings.

    Policy exceptions require a future explicit profile. Do not suppress findings
    to get a pass. Target policy hash comes from the trusted execution registry;
    it need not equal the source policy when environments differ.
    """
    if (
        not isinstance(proposal, RemediationProposal)
        or not isinstance(artifact, TestedArtifact)
        or not isinstance(baseline, Assessment)
        or type(before_inputs) is not tuple
        or type(after_inputs) is not tuple
        or len(before_inputs) != 4
        or len(after_inputs) != 4
    ):
        raise ContractError("Typed baseline and exact assessment input tuples required")
    digest(expected_policy_digest)
    now, not_before = utc(now), utc(not_before)
    reconstructed = assess_risk(*before_inputs, now=baseline.assessed_at)
    if (
        reconstructed != baseline
        or not baseline.complete
        or baseline.fingerprint != proposal.assessment_digest
        or before_inputs[0].fingerprint != proposal.inventory_digest
        or before_inputs[0].source_digest != proposal.base_source_digest
        or before_inputs[0].image_digest != proposal.base_image_digest
        or before_inputs[0].configuration_digest != proposal.base_configuration_digest
        or before_inputs[3].fingerprint != proposal.policy_digest
    ):
        raise ContractError("Patch baseline differs from assessed proposal")
    before_inventory, before_scan, _, _ = before_inputs
    after_inventory, after_scan, after_exposure, after_policy = after_inputs
    after = assess_risk(*after_inputs, now=now)
    if (
        after.scope != artifact.scope
        or (after.scope.tenant_id, after.scope.application_id)
        != (proposal.scope.tenant_id, proposal.scope.application_id)
        or after_inventory.image_digest != artifact.image_digest
        or after_inventory.source_digest != artifact.source_digest
        or after_inventory.configuration_digest != artifact.configuration_digest
        or after_policy.fingerprint != expected_policy_digest
    ):
        raise ContractError(
            "Post-patch inventory/policy differs from registered artifact"
        )
    if not proposal.created_at <= not_before <= now < proposal.valid_until or any(
        value.observed_at < not_before
        for value in (after_inventory, after_scan, after_exposure)
    ):
        raise ContractError("Patch reassessment predates execution or proposal expired")
    selected = {
        d.fingerprint: d
        for d in baseline.decisions
        if d.fingerprint in proposal.findings
    }
    if len(selected) != len(proposal.findings):
        raise ContractError("Patch finding is not part of baseline")
    old_components = {c.component_id: c for c in before_inventory.components}
    new_components = {c.component_id: c for c in after_inventory.components}

    def identity(advisory, component_id, components):
        component = components.get(component_id)
        if component is None:
            raise ContractError("Finding component is absent from inventory")
        return advisory, component.name, component.ecosystem

    selected_keys = {
        identity(d.advisory_id, d.component_id, old_components)
        for d in selected.values()
    }
    levels = {
        Severity.UNKNOWN: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def findings(scan, components):
        result = {}
        for f in scan.findings:
            key = identity(f.advisory_id, f.component_id, components)
            result[key] = max(result.get(key, 0), levels[f.severity])
        return result

    old, new = (
        findings(before_scan, old_components),
        findings(after_scan, new_components),
    )
    reasons = []
    if not after.complete:
        reasons.append("post-patch-assessment-incomplete")
    if selected_keys.intersection(new):
        reasons.append("selected-finding-still-present")
    if set(new) - set(old):
        reasons.append("new-advisory-introduced")
    if any(new[k] > old[k] for k in set(new).intersection(old)):
        reasons.append("advisory-severity-increased")
    result = PatchReassessment(
        artifact.scope,
        proposal.fingerprint,
        artifact.fingerprint,
        baseline.fingerprint,
        after.fingerprint,
        not reasons,
        tuple(reasons),
        now,
        min(after.valid_until, proposal.valid_until),
    )
    return result, after
