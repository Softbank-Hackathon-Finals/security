"""Independent security gate and privileged release. No implicit risk exceptions."""

from sova_security.application.boundary import require_accept, require_authentication

from datetime import UTC, datetime

from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.governance import (
    assess_governance,
    SecurityHold,
    StoredHold,
    HoldRelease,
)


class GovernanceGuard:
    def __init__(
        self,
        holds,
        *,
        policy_provider,
        evidence_provider,
        authenticate_policy,
        authenticate_evidence,
        clock=lambda: datetime.now(UTC),
    ):
        self.holds = holds
        self.policy_provider = policy_provider
        self.evidence_provider = evidence_provider
        self.authenticate_policy = authenticate_policy
        self.authenticate_evidence = authenticate_evidence
        self.clock = clock

    def assess(self, plan, now):
        if self.holds.tenant_id != plan.tenant_id:
            raise ContractError("Governance tenant mismatch")
        policy = self.policy_provider(plan)
        require_authentication(self.authenticate_policy, policy)
        if (policy.tenant_id, policy.application_id) != (
            plan.tenant_id,
            plan.application_id,
        ):
            raise ContractError("Security policy scope mismatch")
        required = {c.obligation for c in policy.controls}
        if not required <= set(plan.obligations):
            raise ContractError("Plan omitted or weakened security controls")
        controlled = {o.scope for o in required}
        if any(step.scope not in controlled for step in plan.steps):
            raise ContractError("Plan resource lacks security controls")
        evidence = self.evidence_provider(plan)
        if type(evidence) is not tuple:
            raise ContractError("Immutable security evidence required")
        for record in evidence:
            require_authentication(self.authenticate_evidence, record)
        holds = self.holds.active_holds(plan.application_id)
        if type(holds) is not tuple:
            raise ContractError("Immutable hold snapshot required")
        for stored in holds:
            if not stored.active or (
                stored.hold.scope.tenant_id,
                stored.hold.scope.application_id,
            ) != (plan.tenant_id, plan.application_id):
                raise ContractError("Invalid scoped security hold snapshot")
        # Policy/evidence/hold lookups are external boundaries. An earlier
        # authenticated snapshot is not a lasting authorization lease.
        require_authentication(self.authenticate_policy, policy)
        for record in evidence:
            require_authentication(self.authenticate_evidence, record)
        if (
            self.policy_provider(plan) != policy
            or self.evidence_provider(plan) != evidence
            or self.holds.active_holds(plan.application_id) != holds
        ):
            raise ContractError(
                "Security authority changed during governance assessment"
            )
        checked_at = self.clock()
        if checked_at < now:
            raise ContractError("Governance clock moved backwards")
        result = assess_governance(policy, evidence, plan.revisions, now=checked_at)
        result["active_holds"] = [h.hold.hold_id for h in holds]
        result["accepted"] = result["accepted"] and not holds
        return result

    def __call__(self, plan, now):
        result = self.assess(plan, now)
        if not result["accepted"]:
            raise ContractError("Security governance blocks execution")
        return datetime.fromisoformat(result["valid_until"])


class SecurityHoldService:
    def __init__(
        self,
        repository,
        *,
        authorize,
        authenticate_release,
        authenticate_evidence,
        current_revisions,
        clock,
    ):
        self.repository = repository
        self.authorize = authorize
        self.authenticate_release = authenticate_release
        self.authenticate_evidence = authenticate_evidence
        self.current_revisions = current_revisions
        self.clock = clock

    def open(self, actor, hold):
        if not isinstance(hold, SecurityHold):
            raise ContractError("Typed security hold required")
        if actor != hold.raised_by or hold.scope.tenant_id != self.repository.tenant_id:
            raise ContractError("Security hold actor/scope mismatch")
        require_accept(self.authorize, actor, hold.scope, "security:hold")
        if hold.raised_at > self.clock():
            raise ContractError("Future hold timestamp")
        result = self.repository.open_hold(hold)
        if (
            not isinstance(result, StoredHold)
            or result != StoredHold(hold, 1)
            or self.repository.get_hold(hold.scope.application_id, hold.hold_id)
            != result
        ):
            raise ContractError("Security hold persistence was not confirmed")
        return result

    def release(self, actor, application_id, request, evidence):
        if not isinstance(request, HoldRelease) or not isinstance(
            evidence, EvidenceRecord
        ):
            raise ContractError("Typed security release and revalidation required")
        stored = self.repository.get_hold(application_id, request.hold_id)
        if not isinstance(stored, StoredHold) or not stored.active:
            raise ContractError("Security hold already released")
        scope = stored.hold.scope
        if (
            scope.tenant_id != self.repository.tenant_id
            or scope.application_id != application_id
            or actor != request.requested_by
            or request.scope != scope
            or request.revisions != self.current_revisions(scope)
        ):
            raise ContractError("Hold release requester/scope/revisions mismatch")
        require_accept(self.authorize, actor, scope, "security:release-request")
        require_authentication(self.authenticate_release, request)
        require_accept(
            self.authorize, request.approved_by, scope, "security:release-approve"
        )
        require_authentication(self.authenticate_evidence, evidence)
        now = self.clock()
        request.require_valid(stored.hold, stored.revision, now)
        if (
            evidence.obligation_id != "security-release:" + stored.hold.hold_id
            or evidence.scope != scope
            or evidence.revisions != request.revisions
            or request.revisions != self.current_revisions(scope)
            or evidence.verifier_version != "security-revalidation-v1"
            or evidence.result != VerificationResult.PASS
            or not stored.hold.raised_at
            <= evidence.observed_at
            <= now
            < evidence.valid_until
            or evidence.evidence_id != request.evidence_id
            or evidence.artifact_digest != request.evidence_digest
            or request.valid_until > evidence.valid_until
        ):
            raise ContractError(
                "Hold release lacks current bound security revalidation"
            )
        # A release removes containment. Recheck live identities and verifier
        # trust after lookups, even if the signed request bytes are unchanged.
        require_accept(self.authorize, actor, scope, "security:release-request")
        require_accept(
            self.authorize, request.approved_by, scope, "security:release-approve"
        )
        require_authentication(self.authenticate_release, request)
        require_authentication(self.authenticate_evidence, evidence)
        if (
            self.current_revisions(scope) != request.revisions
            or self.repository.get_hold(application_id, request.hold_id) != stored
        ):
            raise ContractError("Security release authority changed before commit")
        final = self.clock()
        request.require_valid(stored.hold, stored.revision, final)
        if final < now or final >= evidence.valid_until:
            raise ContractError("Security release evidence expired before commit")
        result = self.repository.release_hold(application_id, request)
        if (
            not isinstance(result, StoredHold)
            or result != StoredHold(stored.hold, stored.revision + 1, request)
            or self.repository.get_hold(application_id, request.hold_id) != result
        ):
            # A write may already have happened. Report uncertainty; do not
            # invent a replacement hold or retry a release behind the caller.
            raise ContractError("Security release persistence was not confirmed")
        return result
