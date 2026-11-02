"""Independent verifier projections to the existing lifecycle evidence format.

Records are unsigned. A trusted verifier must issue/authenticate them; generating
this object is never sufficient to authorize an execution.
"""

from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.patch_execution import (
    VERIFIER_VERSION,
    PatchExecutionBinding,
    PatchRuntimeObservation,
)
from sova_security.domain.remediation import evaluate_rehearsal

RUNTIME_VERIFIER_VERSION = "sova.security.patch-runtime.v1"


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


def patch_runtime_record(plan, binding, command, proof, *, evidence_id):
    if (
        not isinstance(binding, PatchExecutionBinding)
        or not isinstance(proof, PatchRuntimeObservation)
        or plan.fingerprint != binding.plan_digest
        or command.plan_digest != plan.fingerprint
        or proof.plan_digest != plan.fingerprint
        or proof.command_digest != command.fingerprint
        or proof.scope != command.scope
    ):
        raise ContractError("Runtime evidence differs from registered patch intent")
    expected = plan.command(
        command.step_id, operation_id=command.operation_id, epoch=command.fencing_epoch
    )
    if command != expected:
        raise ContractError("Runtime command differs from stored plan step")
    result = (
        VerificationResult.PASS
        if all(
            getattr(proof, name) == VerificationResult.PASS
            for name in ("functional", "security_fix", "protection")
        )
        else VerificationResult.FAIL
    )
    return EvidenceRecord(
        evidence_id,
        "patch-runtime:" + command.step_id,
        command.scope,
        plan.revisions,
        RUNTIME_VERIFIER_VERSION,
        proof.observed_at,
        min(proof.valid_until, binding.valid_until),
        result,
        "patch-runtime:" + binding.fingerprint,
        proof.fingerprint,
    )


class PatchRuntimeAuthority:
    def __init__(self, *, plan_for, envelope_provider, resolve_trust, clock):
        from sova_security.adapters.ed25519_evidence import Ed25519EvidenceVerifier

        self.plan_for = plan_for
        self.envelope_provider = envelope_provider
        self.resolve_trust = resolve_trust
        self.clock = clock
        self.verifier = Ed25519EvidenceVerifier(resolve_trust)

    def __call__(self, actor, binding, command, proof):
        from sova_security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust

        envelope = self.envelope_provider(actor, binding, command, proof)
        if (
            not isinstance(envelope, EvidenceEnvelope)
            or envelope.issuer_id != proof.verifier_id
        ):
            raise ContractError("Registered independent runtime envelope required")
        plan = self.plan_for(command)
        record = patch_runtime_record(
            plan, binding, command, proof, evidence_id=envelope.evidence.evidence_id
        )
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        trust = self.resolve_trust(envelope.issuer_id, envelope.key_id)
        if not isinstance(trust, VerifierTrust):
            raise ContractError("Registered runtime verifier trust required")
        trust.require_authorized(envelope, self.clock())
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        if (
            self.resolve_trust(envelope.issuer_id, envelope.key_id) != trust
            or self.plan_for(command) != plan
        ):
            raise ContractError(
                "Runtime authority changed during signature verification"
            )
