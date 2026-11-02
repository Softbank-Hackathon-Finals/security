from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from modernization_support import rehearsal_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.application.patch_execution import PatchExecutionGuard
from sova_security.contracts.commands import ContractError
from sova_security.contracts.plans import PlanApproval
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.patch_execution import (
    compile_patch,
    PatchRuntimeObservation,
    require_postflight,
)
from sova_security.domain.remediation import evaluate_rehearsal
from sova_security.domain.remediation import Applicability, RehearsalTarget, TargetRole
from sova_security.domain.patch_reassessment import PatchReassessment


def bundle(scope, now):
    inputs, _, request, receipt = rehearsal_bundle(scope, now)
    at = now + timedelta(seconds=4)
    decision = evaluate_rehearsal(request, receipt, now=at)
    inventories, adapters = (inputs[0],), {scope: "registered-oci-adapter"}
    plan, binding = compile_patch(
        request,
        receipt,
        decision,
        inventories=inventories,
        adapters=adapters,
        plan_id="patch-plan",
        created_by="operator",
        now=at,
    )
    return request, receipt, decision, inventories, adapters, plan, binding


def test_compilation_uses_existing_unapproved_lifecycle_plan(scope, now):
    request, receipt, _, inventories, _, plan, binding = bundle(scope, now)
    assert plan.purpose.value == "change"
    assert plan.steps[0].expected_revision == inventories[0].resource_revision
    assert plan.steps[0].parameters_json.count(receipt.artifacts[0].image_digest) == 1
    assert binding.plan_digest == plan.fingerprint
    assert request.proposal.fingerprint in plan.steps[0].parameters_json
    assert decode(encode(binding).encode()) == binding


def test_cross_environment_rehearsal_does_not_imply_multi_environment_apply(scope, now):
    request, receipt, _, inventories, adapters, _, _ = bundle(scope, now)
    destination = replace(scope, environment_id="rke2", resource_id="destination-app")
    inventory = replace(
        inventories[0], scope=destination, resource_revision="target-v1"
    )
    proposal = replace(request.proposal, applicability=Applicability.BOTH)
    both = replace(
        request,
        proposal=proposal,
        targets=(
            *request.targets,
            RehearsalTarget(
                destination,
                TargetRole.TARGET,
                inventory.fingerprint,
                inventory.image_digest,
            ),
        ),
        requirements=(
            *request.requirements,
            *(replace(r, scope=destination) for r in request.requirements),
        ),
    )
    receipt = replace(
        receipt,
        request_digest=both.fingerprint,
        proposal_digest=proposal.fingerprint,
        artifacts=(
            *receipt.artifacts,
            replace(receipt.artifacts[0], scope=destination),
        ),
        proofs=(
            *receipt.proofs,
            *(replace(p, scope=destination) for p in receipt.proofs),
        ),
    )
    decision = evaluate_rehearsal(both, receipt, now=now + timedelta(seconds=4))
    kwargs = dict(
        inventories=(*inventories, inventory),
        adapters={**adapters, destination: "rke2-adapter"},
        plan_id="target-patch",
        created_by="operator",
        now=now + timedelta(seconds=4),
    )
    with pytest.raises(ContractError, match="one explicit execution scope"):
        compile_patch(both, receipt, decision, **kwargs)
    plan, binding = compile_patch(
        both, receipt, decision, execution_scope=destination, **kwargs
    )
    assert len(plan.steps) == 1 and plan.steps[0].scope == destination
    assert {o.scope for o in plan.obligations} == {scope, destination}
    assert len(binding.artifacts) == 2  # Compatibility evidence remains bound.


@pytest.mark.parametrize(
    "case",
    [
        "denied",
        "forged-receipt",
        "late-decision",
        "inventory-drift",
        "duplicate-inventory",
        "missing-adapter",
        "extra-adapter",
    ],
)
def test_compilation_rejects_unadmitted_or_changed_inputs(scope, now, case):
    request, receipt, decision, inventories, adapters, _, _ = bundle(scope, now)
    if case == "denied":
        decision = replace(decision, allowed=False, reasons=("blocked",))
    if case == "forged-receipt":
        receipt = replace(receipt, issuer_id="attacker")
    if case == "late-decision":
        decision = replace(
            decision, valid_until=decision.valid_until + timedelta(seconds=1)
        )
    if case == "inventory-drift":
        inventories = (replace(inventories[0], resource_revision="changed"),)
    if case == "duplicate-inventory":
        inventories *= 2
    if case == "missing-adapter":
        adapters = {}
    if case == "extra-adapter":
        adapters = {**adapters, replace(scope, resource_id="other"): "other-adapter"}
    with pytest.raises(ContractError):
        compile_patch(
            request,
            receipt,
            decision,
            inventories=inventories,
            adapters=adapters,
            plan_id="patch-plan",
            created_by="operator",
            now=now + timedelta(seconds=5),
        )


def guarded(
    scope, now, *, mutate=lambda *_: None, auth=lambda *_: None, holds=lambda *_: None
):
    request, receipt, decision, inventories, adapters, plan, binding = bundle(
        scope, now
    )
    state = {"inputs": (request, receipt, inventories, adapters), "binding": binding}

    def verify(*_, **__):
        mutate(state)
        return decision

    guard = PatchExecutionGuard(
        admission=SimpleNamespace(verify=verify),
        binding_for=lambda _: state["binding"],
        inputs_for=lambda _: state["inputs"],
        authenticate_binding=lambda *_: None,
        authorize=auth,
        require_no_holds=holds,
        clock=lambda: now + timedelta(seconds=5),
    )
    return guard, state, plan, binding


def test_guard_binds_complete_plan_and_current_registration(scope, now):
    guard, _, plan, binding = guarded(scope, now)
    assert guard.check("actor", plan) == binding.valid_until
    changed = replace(plan, steps=(replace(plan.steps[0], adapter_id="unregistered"),))
    with pytest.raises(ContractError, match="differs"):
        guard.check("actor", changed)


def test_repackaging_by_another_actor_does_not_allow_proposer_self_approval(scope, now):
    guard, state, plan, binding = guarded(scope, now)
    plan = replace(plan, created_by="packager")
    state["binding"] = replace(binding, plan_digest=plan.fingerprint)
    for approver in ("operator", "independent-verifier"):
        approval = PlanApproval(
            plan.fingerprint, approver, plan.purpose, plan.valid_until
        )
        with pytest.raises(ContractError, match="cannot approve"):
            guard.check_approval(plan, approval)
    guard.check_approval(
        plan,
        PlanApproval(
            plan.fingerprint, "separate-reviewer", plan.purpose, plan.valid_until
        ),
    )


@pytest.mark.parametrize(
    "deny",
    [
        "authorization",
        "active-hold",
        "binding-revoked",
        "registry-changed",
        "binding-false",
    ],
)
def test_patch_does_not_bypass_authority_or_incident_holds(scope, now, deny):
    def mutate(state):
        if deny == "binding-revoked":
            state["binding"] = None
        if deny == "registry-changed":
            a, b, c, d = state["inputs"]
            state["inputs"] = (a, b, c, {scope: "other"})

    guard, _, plan, _ = guarded(
        scope,
        now,
        mutate=mutate,
        auth=lambda *_: False if deny == "authorization" else None,
        holds=lambda *_: False if deny == "active-hold" else None,
    )
    if deny == "binding-false":
        guard.authenticate_binding = lambda *_: False
    with pytest.raises(ContractError):
        guard.check("actor", plan)


def observation_bundle(scope, now):
    *_, plan, binding = bundle(scope, now)
    command = plan.command("patch-1", operation_id="operation-1", epoch=1)
    reassessment = PatchReassessment(
        scope,
        binding.proposal_digest,
        binding.artifacts[0].fingerprint,
        "a" * 64,
        "b" * 64,
        True,
        (),
        now + timedelta(seconds=9),
        binding.valid_until,
    )
    proof = PatchRuntimeObservation(
        scope,
        plan.fingerprint,
        command.fingerprint,
        binding.artifacts[0],
        "resource-v2",
        "independent-runtime-verifier",
        "e" * 64,
        R.PASS,
        R.PASS,
        R.PASS,
        now + timedelta(seconds=10),
        binding.valid_until,
        reassessment.fingerprint,
    )
    return binding, command, proof, reassessment


def test_postflight_requires_actual_approved_artifact_and_new_observation(scope, now):
    binding, command, proof, reassessment = observation_bundle(scope, now)
    assert require_postflight(
        binding,
        proof,
        command=command,
        not_before=now + timedelta(seconds=7),
        now=now + timedelta(seconds=11),
        reassessment=reassessment,
    )
    assert decode(encode(proof).encode()) == proof


@pytest.mark.parametrize(
    "case",
    [
        "image",
        "source",
        "configuration",
        "provenance",
        "command",
        "scope",
        "pre-execution",
        "failed-fix",
        "unknown-protection",
        "expired",
        "rescan-missing",
        "rescan-failed",
        "rescan-predates-apply",
    ],
)
def test_postflight_never_promotes_apply_response_or_uncertain_proof(scope, now, case):
    binding, command, proof, reassessment = observation_bundle(scope, now)
    if case in {"image", "source", "configuration", "provenance"}:
        proof = replace(
            proof, artifact=replace(proof.artifact, **{case + "_digest": "0" * 64})
        )
    if case == "command":
        proof = replace(proof, command_digest="0" * 64)
    if case == "scope":
        command = replace(command, scope=replace(scope, resource_id="other"))
    if case == "pre-execution":
        proof = replace(proof, observed_at=now + timedelta(seconds=6))
    if case == "failed-fix":
        proof = replace(proof, security_fix=R.FAIL)
    if case == "unknown-protection":
        proof = replace(proof, protection=R.UNKNOWN)
    if case == "rescan-missing":
        proof = replace(proof, reassessment_digest="0" * 64)
    if case == "rescan-failed":
        reassessment = replace(
            reassessment, allowed=False, reasons=("selected-finding-still-present",)
        )
        proof = replace(proof, reassessment_digest=reassessment.fingerprint)
    if case == "rescan-predates-apply":
        reassessment = replace(reassessment, observed_at=now + timedelta(seconds=6))
        proof = replace(proof, reassessment_digest=reassessment.fingerprint)
    at = binding.valid_until if case == "expired" else now + timedelta(seconds=11)
    with pytest.raises(ContractError):
        require_postflight(
            binding,
            proof,
            command=command,
            not_before=now + timedelta(seconds=7),
            now=at,
            reassessment=reassessment,
        )
