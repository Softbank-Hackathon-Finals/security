from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json

import pytest

from sova_security.adapters.modernization_codec import encode, decode
from sova_security.adapters.team_control_results import import_control_run
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R
from team_controls_support import team_control_bundle


@pytest.fixture
def team_bundle():
    return team_control_bundle()


def project(body, profile, now):
    return import_control_run(json.dumps(body).encode(), registration=profile, now=now)


def test_actual_team_example_bridges_without_host_imports(team_bundle):
    body, profile, now = team_bundle
    result = project(body, profile, now)
    assert all(record.result == R.PASS for record in result.evidence)
    assert decode(encode(profile).encode()) == profile
    assert decode(encode(result).encode()) == result
    serialized = encode(result)
    assert "curl -s" not in serialized and "excerpt" not in serialized
    assert (
        result.registration.schema_digest
        == "7c9728028af9c9d8bc45f5e8a8ba2b3ba0e38c96b7373b7338b49c8f37adfeb9"
    )


def test_denial_does_not_pass_when_positive_control_is_not_run(team_bundle):
    body, profile, now = team_bundle
    body["results"][0]["positive_control"] = "not_applicable"
    result = project(body, profile, now)
    assert result.evidence[0].result == R.UNKNOWN
    assert result.evidence[0].justification == "positive-control-unverified"


def test_registered_expected_outcome_cannot_be_changed_to_allow(team_bundle):
    body, profile, now = team_bundle
    row = body["results"][0]
    row.update(expected="allow", observed="allow")
    with pytest.raises(ContractError, match="expected outcome"):
        project(body, profile, now)


@pytest.mark.parametrize(
    "field,value", [("method_version", "2"), ("verdict", "UNKNOWN")]
)
def test_mismatch_or_unknown_never_becomes_pass(team_bundle, field, value):
    body, profile, now = team_bundle
    body["results"][0][field] = value
    if field == "verdict":
        body["results"][0]["unknown_reason"] = "TOOL_ERROR"
    assert project(body, profile, now).evidence[0].result == R.UNKNOWN


def test_missing_row_stays_unknown(team_bundle):
    body, profile, now = team_bundle
    body["results"] = body["results"][1:]
    result = project(body, profile, now)
    assert result.evidence[0].result == R.UNKNOWN
    assert len(result.evidence) == len(profile.tests)


@pytest.mark.parametrize(
    "mode",
    [
        "duplicate",
        "control-mismatch",
        "unexpected",
        "contradiction",
        "future",
        "malformed-date",
        "wrong-app",
        "wrong-role",
        "schema-extra",
    ],
)
def test_schema_and_semantic_lies_block(team_bundle, mode):
    body, profile, now = team_bundle
    row = body["results"][0]
    if mode == "duplicate":
        body["results"].append(deepcopy(row))
    if mode == "control-mismatch":
        row["control_id"] = "AUD-01"
    if mode == "unexpected":
        row["test_id"] = "IAM-01.999"
    if mode == "contradiction":
        row["observed"] = "allow"
    if mode == "future":
        body["finished_at"] = "2099-11-04T09:04:20Z"
    if mode == "malformed-date":
        row["evidence"]["collected_at"] = "bad date"
    if mode == "wrong-app":
        body["app"] = "another-app"
    if mode == "wrong-role":
        body["environment"]["role"] = "target"
    if mode == "schema-extra":
        body["grant"] = True
    with pytest.raises(ContractError):
        project(body, profile, now)


def test_stale_evidence_is_a_current_unknown_not_refreshed_pass(team_bundle):
    body, profile, now = team_bundle
    profile = replace(profile, maximum_evidence_age_seconds=30)
    result = project(body, profile, now)
    assert all(r.result == R.UNKNOWN for r in result.evidence)
    assert all(r.justification == "evidence-expired" for r in result.evidence)


def test_fail_observation_remains_fail(team_bundle):
    body, profile, now = team_bundle
    body["results"][0].update(observed="allow", verdict="FAIL")
    assert project(body, profile, now).evidence[0].result == R.FAIL


def test_gate_comparison_is_not_imported_as_execution_authority(team_bundle):
    _, profile, now = team_bundle
    with pytest.raises(ContractError, match="Only raw control runs"):
        project({"kind": "gate_comparison", "decision": "PASS"}, profile, now)


def test_profile_cannot_remove_denial_positive_control(team_bundle):
    _, profile, _ = team_bundle
    with pytest.raises(ContractError, match="Denial tests"):
        replace(profile.tests[0], positive_control_required=False)


@pytest.mark.parametrize("target_state", ["PASS", "FAIL", "UNKNOWN", "method-mismatch"])
def test_team_run_feeds_existing_parity_without_second_gate_engine(
    team_bundle, target_state
):
    from sova_security.adapters.team_control_results import parity_record
    from sova_security.domain.governance import ControlFamily
    from sova_security.domain.protection_parity import (
        ProtectionEndpoint,
        ProtectionRequirement,
        ProtectionPolicy,
        Availability,
        assess_protection,
    )

    body, profile, now = team_bundle
    binding = profile.tests[0]
    source_scope = profile.scope
    target_scope = replace(
        source_scope, environment_id="env-rke2", resource_id="target-app"
    )

    def endpoint(scope, provider):
        return ProtectionEndpoint(
            scope,
            provider,
            "registered-runtime-probe",
            Availability.AVAILABLE,
            Availability.AVAILABLE,
            "a" * 64,
            "b" * 64,
            "d" * 64,
            binding.verifier_version,
        )

    source, target = endpoint(source_scope, "aws"), endpoint(target_scope, "onprem")
    requirement = ProtectionRequirement(
        "team-control:" + binding.test_id,
        ControlFamily.IDENTITY,
        "Anonymous attachment reads must be rejected",
        source,
        target,
    )
    policy = ProtectionPolicy(
        source_scope.tenant_id,
        source_scope.application_id,
        1,
        (requirement,),
        now - timedelta(minutes=10),
        now + timedelta(minutes=10),
    )
    profile = replace(
        profile, tests=(binding,), revisions=source.revisions(policy.fingerprint)
    )
    body["results"] = body["results"][:1]
    source_run = project(body, profile, now)
    target_body = deepcopy(body)
    target_body["environment"] = {
        "id": "env-rke2",
        "role": "target",
        "ref": "onprem:rke2/target",
    }
    target_body["run_id"] = "run-target"
    row = target_body["results"][0]
    if target_state == "FAIL":
        row.update(observed="allow", verdict="FAIL")
    if target_state == "UNKNOWN":
        row.update(verdict="UNKNOWN", unknown_reason="TIMEOUT", observed=None)
    if target_state == "method-mismatch":
        row["method_version"] = "2"
    target_profile = replace(
        profile,
        scope=target_scope,
        role="target",
        environment_ref="onprem:rke2/target",
        revisions=target.revisions(policy.fingerprint),
    )
    target_run = project(target_body, target_profile, now)
    records = (
        parity_record(source_run, policy, test_id=binding.test_id, side="source"),
        parity_record(target_run, policy, test_id=binding.test_id, side="target"),
    )
    assert assess_protection(policy, records, now=now)["accepted"] == (
        target_state == "PASS"
    )
    with pytest.raises(ContractError):
        parity_record(target_run, policy, test_id=binding.test_id, side="source")
