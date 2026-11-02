"""Bridge to Harbor and independent verification; never implements Harbor itself."""

from sova_security.application.boundary import require_accept
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.assessment import (
    assess_risk,
    Assessment,
    AssetInventory,
    current,
)
from sova_security.domain.remediation import (
    ChangeKind,
    evaluate_rehearsal,
    RemediationProposal,
    RehearsalRequest,
    RehearsalReceipt,
)


def require_proposal_binding(proposal, inventory, assessment, *, now):
    now = utc(now)
    if (
        not isinstance(proposal, RemediationProposal)
        or not isinstance(inventory, AssetInventory)
        or not isinstance(assessment, Assessment)
    ):
        raise ContractError("Typed proposal, inventory and assessment required")
    if (
        proposal.scope != inventory.scope
        or proposal.scope != assessment.scope
        or proposal.inventory_digest != inventory.fingerprint
        or proposal.assessment_digest != assessment.fingerprint
        or proposal.policy_digest != assessment.policy_digest
        or proposal.base_source_digest != inventory.source_digest
        or proposal.base_image_digest != inventory.image_digest
        or proposal.base_configuration_digest != inventory.configuration_digest
    ):
        raise ContractError("Proposal differs from assessed source, policy or artifact")
    if (
        not inventory.observed_at <= now < inventory.valid_until
        or not assessment.assessed_at <= now < assessment.valid_until
        or not proposal.created_at <= now < proposal.valid_until
        or proposal.valid_until > assessment.valid_until
    ):
        raise ContractError("Proposal evidence expired or validity was extended")
    if proposal.kind == ChangeKind.PATCH and (
        not assessment.complete
        or any(
            d.response != "propose-patch"
            for d in assessment.decisions
            if d.fingerprint in proposal.findings
        )
    ):
        raise ContractError(
            "Ordinary patch cannot bypass incomplete assessment or incident handling"
        )
    if not set(proposal.findings).issubset(
        {d.fingerprint for d in assessment.decisions}
    ):
        raise ContractError("Proposal includes an unassessed finding")


class RehearsalAdmissionService:
    def __init__(
        self,
        *,
        authorize,
        authenticate_input,
        authenticate_receipt,
        current_inputs,
        current_request,
        current_assessment,
        target_inventory,
        clock,
    ):
        self.authorize = authorize
        self.authenticate_input = authenticate_input
        self.authenticate_receipt = authenticate_receipt
        self.current_inputs = current_inputs
        self.current_request = current_request
        self.current_assessment = current_assessment
        self.target_inventory = target_inventory
        self.clock = clock

    def verify(self, actor, *, request, receipt):
        if not isinstance(request, RehearsalRequest) or not isinstance(
            receipt, RehearsalReceipt
        ):
            raise ContractError("Typed rehearsal request and receipt required")
        scope = request.proposal.scope
        require_accept(self.authorize, actor, scope, "security:verify-rehearsal")
        if self.current_request(scope, request.request_id) != request:
            raise ContractError("Rehearsal request changed or was revoked")
        inputs = self.current_inputs(scope)
        if type(inputs) is not tuple or len(inputs) != 4:
            raise ContractError("Current authenticated assessment inputs required")
        for value in (*inputs, request):
            require_accept(self.authenticate_input, actor, scope, value)
        targets = {}
        for target in request.targets:
            require_accept(
                self.authorize, actor, target.scope, "security:verify-rehearsal-target"
            )
            inventory = self.target_inventory(target.scope)
            if (
                not isinstance(inventory, AssetInventory)
                or inventory.scope != target.scope
                or inventory.fingerprint != target.snapshot_digest
                or inventory.image_digest != target.base_image_digest
            ):
                raise ContractError("Rehearsal target inventory changed")
            require_accept(self.authenticate_input, actor, target.scope, inventory)
            targets[target.scope] = inventory
        at = utc(self.clock())
        if any(not current(t, at) for t in targets.values()):
            raise ContractError("Rehearsal target inventory expired")
        assessment = assess_risk(*inputs, now=at)
        # Assessment time is part of its digest. Use the persisted assessment bound to the proposal,
        # not a regenerated object with another timestamp: the host authenticates that object below.
        bound = self.current_assessment(scope, request.proposal.assessment_digest)
        if (
            not isinstance(bound, Assessment)
            or bound.inventory_digest != assessment.inventory_digest
            or bound.scan_digest != assessment.scan_digest
            or bound.exposure_digest != assessment.exposure_digest
            or bound.policy_digest != assessment.policy_digest
            or bound.decisions != assessment.decisions
            or bound.reasons != assessment.reasons
            or bound.complete != assessment.complete
            or bound.valid_until != assessment.valid_until
        ):
            raise ContractError("Proposal assessment inputs are no longer current")
        require_accept(self.authenticate_input, actor, scope, bound)
        require_proposal_binding(request.proposal, inputs[0], bound, now=at)
        require_accept(self.authenticate_receipt, actor, request, receipt)
        decision = evaluate_rehearsal(request, receipt, now=utc(self.clock()))
        require_accept(self.authorize, actor, scope, "security:verify-rehearsal")
        if (
            self.current_inputs(scope) != inputs
            or self.current_request(scope, request.request_id) != request
            or self.current_assessment(scope, request.proposal.assessment_digest)
            != bound
        ):
            raise ContractError("Authority changed during rehearsal admission")
        require_accept(self.authenticate_receipt, actor, request, receipt)
        require_accept(self.authorize, actor, scope, "security:verify-rehearsal")
        if (
            self.current_inputs(scope) != inputs
            or self.current_request(scope, request.request_id) != request
            or self.current_assessment(scope, request.proposal.assessment_digest)
            != bound
        ):
            raise ContractError("Authority changed before final rehearsal return")
        for target_scope, inventory in targets.items():
            require_accept(
                self.authorize, actor, target_scope, "security:verify-rehearsal-target"
            )
            if self.target_inventory(target_scope) != inventory:
                raise ContractError("Target changed before final rehearsal return")
        from dataclasses import replace

        decision = replace(
            decision,
            valid_until=min(
                decision.valid_until, *(t.valid_until for t in targets.values())
            ),
        )
        final = utc(self.clock())
        if final < at or final >= min(decision.valid_until, bound.valid_until):
            raise ContractError("Rehearsal authority expired during admission")
        return decision
