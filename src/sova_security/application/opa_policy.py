"""Additional OPA gate intersected with the existing mandatory Python checks."""

from datetime import timedelta
from dataclasses import asdict
import hashlib

from sova_security.application.boundary import require_accept, require_authentication
from sova_security.contracts.commands import ContractError, canonical_json, utc
from sova_security.contracts.evidence import Gate, VerificationResult, evaluate_gate
from sova_security.domain.opa_policy import OPAPolicy, OPADecision, validate_verdict
from sova_security.domain.governance import StoredHold


class OPAPlanPolicy:
    def __init__(
        self,
        *,
        policy_provider,
        evidence_provider,
        authenticate_policy,
        authenticate_evidence,
        authorize,
        evaluator,
        holds,
        clock,
    ):
        self.policy_provider = policy_provider
        self.evidence_provider = evidence_provider
        self.authenticate_policy = authenticate_policy
        self.authenticate_evidence = authenticate_evidence
        self.authorize = authorize
        self.evaluator = evaluator
        self.holds = holds
        self.clock = clock

    def evaluate(self, actor, plan, *, now=None):
        started = utc(self.clock() if now is None else now)
        for step in plan.steps:
            require_accept(
                self.authorize, actor, step.scope, "security:evaluate-policy"
            )
        policy = self.policy_provider(plan)
        if not isinstance(policy, OPAPolicy) or (
            policy.scope.tenant_id,
            policy.scope.application_id,
        ) != (plan.tenant_id, plan.application_id):
            raise ContractError("Registered app-scoped OPA policy required")
        if self.holds.tenant_id != plan.tenant_id:
            raise ContractError("OPA hold authority tenant mismatch")
        active = self.holds.active_holds(plan.application_id)
        if type(active) is not tuple or any(
            not isinstance(h, StoredHold)
            or not h.active
            or (h.hold.scope.tenant_id, h.hold.scope.application_id)
            != (plan.tenant_id, plan.application_id)
            for h in active
        ):
            raise ContractError("Scoped active OPA security hold snapshot required")
        require_authentication(self.authenticate_policy, policy)
        if not policy.issued_at <= started < min(policy.valid_until, plan.valid_until):
            raise ContractError("OPA policy/plan expired")
        for scope in policy.allowed_scopes:
            require_accept(self.authorize, actor, scope, "security:evaluate-policy")
        evidence = self.evidence_provider(plan)
        if type(evidence) is not tuple:
            raise ContractError("Immutable authenticated OPA facts required")
        for record in evidence:
            require_authentication(self.authenticate_evidence, record)
        facts = evaluate_gate(
            Gate.PREFLIGHT, policy.required, evidence, plan.revisions, now=started
        )
        mandatory_pass = all(
            d.result == VerificationResult.PASS for d in facts.decisions
        )
        scope_covered = all(step.scope in policy.allowed_scopes for step in plan.steps)
        policy_bound = policy.obligation in plan.obligations
        purpose_covered = plan.purpose in policy.purposes
        body = {
            "schema_version": 1,
            "scope": asdict(policy.scope),
            "subject_digest": plan.fingerprint,
            "policy_digest": policy.fingerprint,
            "scope_covered": scope_covered,
            "policy_bound": policy_bound,
            "hold_active": bool(active),
            "purpose_covered": purpose_covered,
            "checks": [
                {
                    "control_id": d.obligation.obligation_id,
                    "result": str(d.result),
                    "evidence_id": d.evidence_id,
                }
                for d in facts.decisions
            ],
        }
        if active:
            allowed, reasons = False, ("security-hold-active",)
        else:
            allowed, reasons = self.evaluator.evaluate(policy, body)
        validate_verdict(allowed, reasons)
        reasons = set(reasons)
        if not mandatory_pass:
            reasons.add("mandatory-control-unverified")
        if not scope_covered:
            reasons.add("scope-not-covered")
        if not policy_bound:
            reasons.add("policy-not-bound")
        if not purpose_covered:
            reasons.add("plan-purpose-not-covered")
        require_authentication(self.authenticate_policy, policy)
        for record in evidence:
            require_authentication(self.authenticate_evidence, record)
        for scope in policy.allowed_scopes:
            require_accept(self.authorize, actor, scope, "security:evaluate-policy")
        if (
            self.policy_provider(plan) != policy
            or self.evidence_provider(plan) != evidence
            or self.holds.active_holds(plan.application_id) != active
        ):
            raise ContractError("OPA policy/facts changed during evaluation")
        final = utc(self.clock())
        if final < started:
            raise ContractError("OPA evaluation clock moved backwards")
        used = {d.evidence_id for d in facts.decisions}
        deadline = min(
            policy.valid_until,
            plan.valid_until,
            started + timedelta(seconds=30),
            *(record.valid_until for record in evidence if record.evidence_id in used),
        )
        if final >= deadline:
            raise ContractError("OPA facts expired before decision")
        return OPADecision(
            policy.scope,
            plan.fingerprint,
            policy.fingerprint,
            hashlib.sha256(canonical_json(body, limit=262144).encode()).hexdigest(),
            not reasons,
            tuple(sorted(reasons)),
            final,
            deadline,
        )

    def for_actor(self, actor):
        def guard(plan, now):
            decision = self.evaluate(actor, plan, now=now)
            if not decision.allowed:
                raise ContractError("OPA policy blocks execution")
            return decision.valid_until

        return guard
