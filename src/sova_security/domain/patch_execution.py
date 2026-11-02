"""Compile verified patch artifacts to the existing lifecycle/effect contracts.

No replacement approval service or executor. An authenticated host must install
the guard on every dispatch and use its durable effect journal for readback.
"""

from dataclasses import dataclass
from datetime import datetime

from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova_security.contracts.evidence import (
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult,
)
from sova_security.contracts.plans import LifecyclePlan, PlanPurpose, PlanStep
from sova_security.domain.assessment import Document, bounded_tuple
from sova_security.domain.remediation import (
    RehearsalDecision,
    RehearsalRequest,
    RehearsalReceipt,
    TestedArtifact,
    evaluate_rehearsal,
)

VERIFIER_VERSION = "sova.security.patch-rehearsal.v1"
ACTION = "apply-verified-patch"


@dataclass(frozen=True, slots=True)
class PatchExecutionBinding(Document):
    scope: ResourceScope
    plan_digest: str
    request_digest: str
    receipt_digest: str
    decision_digest: str
    proposal_digest: str
    artifacts: tuple[TestedArtifact, ...]
    created_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed patch scope required")
        for field in (
            "plan_digest",
            "request_digest",
            "receipt_digest",
            "decision_digest",
            "proposal_digest",
        ):
            digest(getattr(self, field))
        bounded_tuple(self.artifacts, TestedArtifact, limit=2, nonempty=True)
        if len({a.scope for a in self.artifacts}) != len(self.artifacts) or any(
            (a.scope.tenant_id, a.scope.application_id)
            != (self.scope.tenant_id, self.scope.application_id)
            for a in self.artifacts
        ):
            raise ContractError("Unique patch targets within one application required")
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.created_at >= self.valid_until:
            raise ContractError("Positive patch binding validity required")


def compile_patch(
    request,
    receipt,
    decision,
    *,
    inventories,
    adapters,
    plan_id,
    created_by,
    now,
    execution_scope=None,
):
    """Inputs and adapter IDs must come from authenticated host registries.

    Returns an unapproved plan. Structural evaluation alone gives no authority.
    No parameters can carry a shell command, tag or caller-selected destination.
    """
    if not isinstance(request, RehearsalRequest) or not isinstance(
        receipt, RehearsalReceipt
    ):
        raise ContractError("Typed registered rehearsal required")
    if not isinstance(decision, RehearsalDecision):
        raise ContractError("Authenticated rehearsal decision required")
    now = utc(now)
    checked = evaluate_rehearsal(request, receipt, now=now)
    if (
        not decision.allowed
        or not checked.allowed
        or decision.request_digest != checked.request_digest
        or decision.receipt_digest != checked.receipt_digest
        or decision.valid_until > checked.valid_until
        or now >= decision.valid_until
    ):
        raise ContractError("Patch rehearsal is not currently admitted")
    from sova_security.domain.assessment import AssetInventory, current

    if type(inventories) is not tuple or any(
        not isinstance(i, AssetInventory) for i in inventories
    ):
        raise ContractError("Registered typed target inventories required")
    registered = {i.scope: i for i in inventories}
    targets = {t.scope: t for t in request.targets}
    if execution_scope is None:
        if len(targets) != 1:
            raise ContractError(
                "Cross-environment rehearsal requires one explicit execution scope per plan"
            )
        execution_scope = next(iter(targets))
    if not isinstance(execution_scope, ResourceScope) or execution_scope not in targets:
        raise ContractError("Execution scope was not independently rehearsed")
    if len(registered) != len(inventories) or set(registered) != set(targets):
        raise ContractError("Exact target inventory coverage required")
    if type(adapters) is not dict or set(adapters) != set(targets):
        raise ContractError("Exact registered adapter coverage required")
    for scope, target in targets.items():
        inventory = registered[scope]
        if (
            inventory.fingerprint != target.snapshot_digest
            or inventory.image_digest != target.base_image_digest
            or not current(inventory, now)
        ):
            raise ContractError("Patch target changed or expired")
        identifier(adapters[scope])
    deadline = min(decision.valid_until, *(i.valid_until for i in inventories))
    proposal = request.proposal
    revisions = RevisionSet(
        proposal.base_source_digest,
        proposal.base_configuration_digest,
        proposal.policy_digest,
        request.fingerprint,
    )
    artifacts = {a.scope: a for a in receipt.artifacts}
    steps, obligations = [], []
    for index, target in enumerate(request.targets):
        artifact = artifacts[target.scope]
        if target.scope == execution_scope:
            steps.append(
                PlanStep(
                    "patch-1",
                    target.scope,
                    adapters[target.scope],
                    ACTION,
                    canonical_json(
                        {
                            "request_digest": request.fingerprint,
                            "receipt_digest": receipt.fingerprint,
                            "proposal_digest": proposal.fingerprint,
                            "artifact": artifact.document,
                        }
                    ),
                    registered[target.scope].resource_revision,
                    (),
                )
            )
        obligations.append(
            VerificationObligation(
                "patch-rehearsal-" + str(index + 1),
                target.scope,
                Gate.PREFLIGHT,
                VERIFIER_VERSION,
                True,
            )
        )
    plan = LifecyclePlan(
        plan_id,
        proposal.scope.tenant_id,
        proposal.scope.application_id,
        created_by,
        PlanPurpose.CHANGE,
        revisions,
        deadline,
        tuple(steps),
        tuple(obligations),
    )
    binding = PatchExecutionBinding(
        proposal.scope,
        plan.fingerprint,
        request.fingerprint,
        receipt.fingerprint,
        decision.fingerprint,
        proposal.fingerprint,
        receipt.artifacts,
        now,
        deadline,
    )
    return plan, binding


@dataclass(frozen=True, slots=True)
class PatchRuntimeObservation(Document):
    """Independent readback, not an adapter's apply-success response."""

    scope: ResourceScope
    plan_digest: str
    command_digest: str
    artifact: TestedArtifact
    resource_revision: str
    verifier_id: str
    evidence_digest: str
    functional: VerificationResult
    security_fix: VerificationResult
    protection: VerificationResult
    observed_at: datetime
    valid_until: datetime
    reassessment_digest: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.artifact, TestedArtifact
        ):
            raise ContractError("Typed runtime artifact and scope required")
        if self.scope != self.artifact.scope:
            raise ContractError("Runtime artifact scope mismatch")
        for field in (
            "plan_digest",
            "command_digest",
            "evidence_digest",
            "reassessment_digest",
        ):
            digest(getattr(self, field))
        identifier(self.resource_revision)
        identifier(self.verifier_id)
        if any(
            not isinstance(getattr(self, k), VerificationResult)
            for k in ("functional", "security_fix", "protection")
        ):
            raise ContractError("Typed independent runtime test results required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.observed_at >= self.valid_until:
            raise ContractError("Positive runtime proof validity required")


def require_postflight(binding, observation, *, command, not_before, now, reassessment):
    """Host authenticates observation and journal before calling this function.

    A failure/unknown must create a hold/reconciliation outcome, never an implicit
    rollback: later writes or schema changes may make reversal destructive.
    """
    from sova_security.contracts.commands import EffectCommand
    from sova_security.domain.patch_reassessment import PatchReassessment

    if (
        not isinstance(binding, PatchExecutionBinding)
        or not isinstance(observation, PatchRuntimeObservation)
        or not isinstance(command, EffectCommand)
        or not isinstance(reassessment, PatchReassessment)
    ):
        raise ContractError(
            "Typed postflight binding, observation and command required"
        )
    now, not_before = utc(now), utc(not_before)
    expected = next((a for a in binding.artifacts if a.scope == command.scope), None)
    if (
        command.plan_digest != binding.plan_digest
        or command.action != ACTION
        or observation.scope != command.scope
        or observation.plan_digest != binding.plan_digest
        or observation.command_digest != command.fingerprint
        or observation.artifact != expected
    ):
        raise ContractError(
            "Runtime readback differs from approved patch command/artifact"
        )
    if (
        not binding.created_at
        <= not_before
        <= observation.observed_at
        <= now
        < min(binding.valid_until, observation.valid_until)
    ):
        raise ContractError("Postflight proof is stale, expired or predates execution")
    if (
        reassessment.fingerprint != observation.reassessment_digest
        or reassessment.scope != command.scope
        or reassessment.proposal_digest != binding.proposal_digest
        or reassessment.artifact_digest != observation.artifact.fingerprint
        or not reassessment.allowed
        or not not_before
        <= reassessment.observed_at
        <= observation.observed_at
        <= now
        < reassessment.valid_until
    ):
        raise ContractError("Current approved patch rescan has not passed")
    if any(
        getattr(observation, k) != VerificationResult.PASS
        for k in ("functional", "security_fix", "protection")
    ):
        raise ContractError(
            "Postflight failed or remains unverified; hold for reconciliation"
        )
    return min(binding.valid_until, observation.valid_until, reassessment.valid_until)
