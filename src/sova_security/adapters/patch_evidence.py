"""Independent verifier projections to the existing lifecycle evidence format.

Records are unsigned. A trusted verifier must issue/authenticate them; generating
this object is never sufficient to authorize an execution.
"""

from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.patch_execution import (
    VERIFIER_VERSION,
    PatchExecutionBinding,
)
from sova_security.domain.remediation import evaluate_rehearsal


def patch_rehearsal_records(plan, binding, request, receipt, *, evidence_prefix):
    from sova_security.contracts.commands import identifier

    identifier(evidence_prefix, limit=128)
    if not isinstance(binding, PatchExecutionBinding) or (
        binding.plan_digest != plan.fingerprint
        or binding.request_digest != request.fingerprint
        or binding.receipt_digest != receipt.fingerprint
        or binding.artifacts != receipt.artifacts
    ):
        raise ContractError("Patch evidence differs from its registered binding")
    decision = evaluate_rehearsal(request, receipt, now=binding.created_at)
    if (
        not decision.allowed
        or binding.valid_until > decision.valid_until
        or plan.valid_until != binding.valid_until
    ):
        raise ContractError("Patch evidence requires a valid admitted rehearsal")
    scopes = {t.scope for t in request.targets}
    if (
        {o.scope for o in plan.obligations} != scopes
        or len(plan.obligations) != len(scopes)
        or any(
            o.verifier_version != VERIFIER_VERSION or not o.required
            for o in plan.obligations
        )
    ):
        raise ContractError("Exact patch rehearsal obligations required")
    return tuple(
        EvidenceRecord(
            evidence_prefix + "-" + str(index + 1),
            obligation.obligation_id,
            obligation.scope,
            plan.revisions,
            VERIFIER_VERSION,
            binding.created_at,
            binding.valid_until,
            VerificationResult.PASS,
            "patch-rehearsal:" + binding.fingerprint,
            binding.fingerprint,
        )
        for index, obligation in enumerate(plan.obligations)
    )
