"""Unsigned OPA record for a registered independent policy verifier to sign."""

from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.opa_policy import OPADecision, OPAPolicy, OPA_VERIFIER_VERSION


def opa_evidence(plan, policy, decision, *, evidence_id):
    if (
        not isinstance(policy, OPAPolicy)
        or not isinstance(decision, OPADecision)
        or decision.subject_digest != plan.fingerprint
        or decision.policy_digest != policy.fingerprint
        or decision.scope != policy.scope
        or policy.obligation not in plan.obligations
        or decision.valid_until > min(plan.valid_until, policy.valid_until)
    ):
        raise ContractError("OPA decision is not bound to approved plan/policy")
    return EvidenceRecord(
        evidence_id,
        policy.obligation.obligation_id,
        policy.scope,
        plan.revisions,
        OPA_VERIFIER_VERSION,
        decision.evaluated_at,
        decision.valid_until,
        VerificationResult.PASS if decision.allowed else VerificationResult.FAIL,
        "opa-decision:" + policy.fingerprint,
        decision.fingerprint,
    )
