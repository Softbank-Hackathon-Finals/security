from dataclasses import replace
from types import SimpleNamespace

import pytest

from opa_support import opa_bundle
from sova_security.adapters.modernization_codec import encode, decode
from sova_security.adapters.opa_evidence import opa_evidence
from sova_security.application.opa_policy import OPAPlanPolicy
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.governance import StoredHold
from governance_support import bundle as governance_bundle
from sova_security.contracts.plans import PlanPurpose


def service(scope, now, *, verdict=(True, ()), mutate=lambda _: None):
    policy, plan, evidence = opa_bundle(scope, now)
    state = {
        "policy": policy,
        "evidence": (evidence,),
        "calls": 0,
        "allowed": True,
        "holds": (),
    }

    def evaluate(p, body):
        state["calls"] += 1
        mutate(state)
        return verdict

    instance = OPAPlanPolicy(
        policy_provider=lambda _: state["policy"],
        evidence_provider=lambda _: state["evidence"],
        authenticate_policy=lambda _: None,
        authenticate_evidence=lambda value: value,
        authorize=lambda *_: state["allowed"],
        evaluator=SimpleNamespace(evaluate=evaluate),
        holds=SimpleNamespace(
            tenant_id=scope.tenant_id, active_holds=lambda _: state["holds"]
        ),
        clock=lambda: now,
    )
    return instance, state, policy, plan


def test_opa_is_additional_and_bound_into_immutable_plan(scope, now):
    instance, _, policy, plan = service(scope, now)
    result = instance.evaluate("operator", plan)
    assert result.allowed and instance.for_actor("operator")(plan, now) > now
    record = opa_evidence(
        plan, policy, result, evidence_id="signed-by-independent-policy-verifier"
    )
    assert record.obligation_id == policy.obligation.obligation_id
    assert record.artifact_digest == result.fingerprint
    for value in (policy, result):
        assert decode(encode(value).encode()) == value


@pytest.mark.parametrize(
    "case",
    ["missing", "failed", "unknown", "not-applicable", "policy-unbound", "wrong-scope"],
)
def test_opa_allow_never_overrides_failed_python_requirements(scope, now, case):
    instance, state, _, plan = service(scope, now)
    if case == "missing":
        state["evidence"] = ()
    if case in {"failed", "unknown"}:
        state["evidence"] = (
            replace(
                state["evidence"][0], result=R.FAIL if case == "failed" else R.UNKNOWN
            ),
        )
    if case == "not-applicable":
        state["evidence"] = (
            replace(
                state["evidence"][0],
                result=R.NOT_APPLICABLE,
                justification="not sufficient",
                approved_by="operator",
            ),
        )
    if case == "policy-unbound":
        plan = replace(plan, obligations=plan.obligations[:-1])
    if case == "wrong-scope":
        plan = replace(
            plan,
            steps=(replace(plan.steps[0], scope=replace(scope, resource_id="other")),),
        )
    assert not instance.evaluate("operator", plan).allowed
    with pytest.raises(ContractError, match="blocks"):
        instance.for_actor("operator")(plan, now)


def test_opa_deny_intersects_otherwise_passing_controls(scope, now):
    instance, _, _, plan = service(
        scope, now, verdict=(False, ("operator-policy-deny",))
    )
    assert not instance.evaluate("operator", plan).allowed


def test_opa_never_clears_or_bypasses_app_security_holds(scope, now):
    instance, state, _, plan = service(scope, now)
    state["holds"] = (StoredHold(governance_bundle(scope, now)[4], 1),)
    result = instance.evaluate("operator", plan)
    assert not result.allowed and "security-hold-active" in result.reasons
    assert state["calls"] == 0

    def raise_hold(current):
        current["holds"] = (StoredHold(governance_bundle(scope, now)[4], 1),)

    instance, _, _, plan = service(scope, now, mutate=raise_hold)
    with pytest.raises(ContractError, match="changed"):
        instance.evaluate("operator", plan)


def test_ordinary_opa_profile_cannot_replace_emergency_response_authority(scope, now):
    instance, _, _, plan = service(scope, now)
    plan = replace(
        plan,
        purpose=PlanPurpose.SECURITY_RESPONSE,
        reason="separate emergency profile required",
    )
    result = instance.evaluate("operator", plan)
    assert not result.allowed and "plan-purpose-not-covered" in result.reasons


def test_opa_unknown_malformed_or_denied_actor_never_grants(scope, now):
    instance, state, _, plan = service(scope, now, verdict=(1, ()))
    with pytest.raises(ContractError):
        instance.evaluate("operator", plan)
    state["allowed"] = False
    state["calls"] = 0
    with pytest.raises(ContractError):
        instance.evaluate("operator", plan)
    assert state["calls"] == 0


def test_policy_change_after_approval_requires_a_different_plan(scope, now):
    instance, state, policy, plan = service(scope, now)
    state["policy"] = replace(policy, revision=2)
    result = instance.evaluate("operator", plan)
    assert not result.allowed and "policy-not-bound" in result.reasons
    instance, _, _, plan = service(
        scope,
        now,
        mutate=lambda state: state.update(policy=replace(state["policy"], revision=2)),
    )
    with pytest.raises(ContractError, match="changed"):
        instance.evaluate("operator", plan)


def test_policy_expiry_before_dispatch_never_calls_engine(scope, now):
    instance, state, policy, plan = service(scope, now)
    state["policy"] = replace(policy, valid_until=now)
    with pytest.raises(ContractError, match="expired"):
        instance.evaluate("operator", plan)
    assert state["calls"] == 0
