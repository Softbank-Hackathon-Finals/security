from dataclasses import replace
from datetime import timedelta

import pytest

from modernization_support import rehearsal_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.contracts.commands import ContractError
from sova_security.domain.assessment import Coverage, Compromise, Severity
from sova_security.domain.patch_reassessment import reassess_patch
from sova_security.domain.assessment import assess_risk


def bundle(scope, now):
    before, baseline, request, receipt = rehearsal_bundle(scope, now)
    artifact = receipt.artifacts[0]
    at = now + timedelta(seconds=10)
    inventory = replace(
        before[0],
        source_digest=artifact.source_digest,
        image_digest=artifact.image_digest,
        configuration_digest=artifact.configuration_digest,
        resource_revision="resource-v2",
        observed_at=at,
        components=(replace(before[0].components[0], version="1.1"),),
    )
    scan = replace(
        before[1],
        inventory_digest=inventory.fingerprint,
        image_digest=inventory.image_digest,
        findings=(),
        observed_at=at,
    )
    exposure = replace(
        before[2],
        inventory_digest=inventory.fingerprint,
        resource_revision=inventory.resource_revision,
        observed_at=at,
    )
    return (
        request.proposal,
        artifact,
        baseline,
        before,
        (inventory, scan, exposure, before[3]),
    )


def check(values, now):
    proposal, artifact, baseline, before, after = values
    return reassess_patch(
        proposal,
        artifact,
        baseline,
        before_inputs=before,
        after_inputs=after,
        expected_policy_digest=after[3].fingerprint,
        not_before=now + timedelta(seconds=8),
        now=now + timedelta(seconds=11),
    )


def test_real_reassessment_is_distinct_from_http_health(scope, now):
    result, assessment = check(bundle(scope, now), now)
    assert result.allowed and assessment.complete
    assert result.assessment_digest == assessment.fingerprint
    assert decode(encode(result).encode()) == result


def test_fixing_selected_issue_cannot_increase_an_existing_issue(scope, now):
    proposal, artifact, _, before, after = bundle(scope, now)
    low = replace(
        before[1].findings[0], advisory_id="SOVA-TEST-OTHER", severity=Severity.LOW
    )
    before = (
        before[0],
        replace(before[1], findings=(*before[1].findings, low)),
        *before[2:],
    )
    baseline = assess_risk(*before, now=now)
    proposal = replace(proposal, assessment_digest=baseline.fingerprint)
    after = (
        after[0],
        replace(
            after[1],
            findings=(
                replace(low, installed_version="1.1", severity=Severity.CRITICAL),
            ),
        ),
        *after[2:],
    )
    result, _ = check((proposal, artifact, baseline, before, after), now)
    assert not result.allowed and "advisory-severity-increased" in result.reasons


@pytest.mark.parametrize(
    "case", ["still-present", "new-advisory", "partial", "compromised"]
)
def test_rescan_does_not_treat_a_running_app_as_a_fixed_app(scope, now, case):
    proposal, artifact, baseline, before, after = bundle(scope, now)
    inventory, scan, exposure, policy = after
    if case in {"still-present", "new-advisory"}:
        finding = replace(
            before[1].findings[0],
            installed_version="1.1",
            advisory_id="SOVA-TEST-NEW"
            if case == "new-advisory"
            else before[1].findings[0].advisory_id,
        )
        scan = replace(scan, findings=(finding,))
    if case == "partial":
        scan = replace(scan, coverage=Coverage.PARTIAL)
    if case == "compromised":
        exposure = replace(exposure, compromise=Compromise.SUSPECTED)
    result, _ = check(
        (proposal, artifact, baseline, before, (inventory, scan, exposure, policy)), now
    )
    assert not result.allowed


@pytest.mark.parametrize(
    "case", ["wrong-image", "old-evidence", "baseline-forged", "policy-substitution"]
)
def test_reassessment_requires_exact_artifact_and_fresh_authenticated_inputs(
    scope, now, case
):
    proposal, artifact, baseline, before, after = bundle(scope, now)
    if case == "wrong-image":
        artifact = replace(artifact, image_digest="0" * 64)
    if case == "old-evidence":
        after = (after[0], replace(after[1], observed_at=now), *after[2:])
    if case == "baseline-forged":
        baseline = replace(baseline, scan_digest="0" * 64)
    expected = after[3].fingerprint if case != "policy-substitution" else "0" * 64
    with pytest.raises(ContractError):
        reassess_patch(
            proposal,
            artifact,
            baseline,
            before_inputs=before,
            after_inputs=after,
            expected_policy_digest=expected,
            not_before=now + timedelta(seconds=8),
            now=now + timedelta(seconds=11),
        )
