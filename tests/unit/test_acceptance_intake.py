from copy import deepcopy
from datetime import timedelta
import json

import pytest

from sova_security.application.acceptance_intake import intake_plan
from sova_security.contracts.commands import ContractError


def raw(value):
    return json.dumps(value).encode()


def run_for(plan, now, role="source"):
    return {"kind": "control_run", "schema_version": "1", "run_id": "synthetic-" + role,
        "environment": {"id": "private-" + role, "role": role, "ref": "private-endpoint-reference"},
        "app": "demo-chat", "started_at": now.isoformat(), "finished_at": now.isoformat(),
        "results": [{"test_id": r["test_id"], "control_id": r["control_id"], "method_version": r["method_version"],
            "expected": r["expected"], "observed": None,
            "positive_control": "fail" if r["positive_control"] == "required" else "not_applicable",
            "verdict": "UNKNOWN", "unknown_reason": "NOT_RUN", "evidence": None} for r in plan["required_tests"]]}


def test_empty_intake_preserves_full_catalog_and_all_missing_rows(now):
    plan = intake_plan(now=now)
    assert len(plan["required_tests"]) == 20
    assert plan["reported_counts"] == {"source": {"NOT_PROVIDED": 20}, "target": {"NOT_PROVIDED": 20}}
    assert not plan["live_verified"] and not plan["authorizes_execution"]
    assert all(r["tasks"] and r["prerequisite"] and r["acceptance"] == "LIVE_NOT_VERIFIED" for r in plan["required_tests"])


def test_three_tls_reports_never_fill_other_seventeen_or_authenticate_pass(now):
    plan = intake_plan(now=now)
    source = run_for(plan, now)
    for row in source["results"]:
        if row["test_id"] in {"ENC-01.1", "ENC-01.2", "ENC-01.3"}:
            row.update(verdict="PASS", observed=row["expected"], unknown_reason=None,
                positive_control="not_applicable" if row["test_id"] == "ENC-01.1" else "pass",
                evidence={"collected_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
                    "tool": "test", "command": "private-command-with-token", "output_sha256": "sha256:" + "a" * 64,
                    "excerpt": "private-excerpt"})
    target = deepcopy(source)
    target["environment"].update(role="target", id="private-target")
    result = intake_plan(now=now, control_runs=(raw(source), raw(target)))
    assert result["reported_counts"] == {"source": {"PASS": 3, "UNKNOWN": 17}, "target": {"PASS": 3, "UNKNOWN": 17}}
    text = json.dumps(result)
    for secret in ("private-command", "private-excerpt", "private-endpoint", "private-source", "synthetic-source"):
        assert secret not in text
    assert not result["live_verified"] and all(r["acceptance"] == "LIVE_NOT_VERIFIED" for r in result["required_tests"])
    assert all(r["source"]["coverage"] == "REPORTED_UNAUTHENTICATED" for r in result["required_tests"] if r["source"]["reported_verdict"] == "PASS")
    expired = intake_plan(now=now + timedelta(hours=2), control_runs=(raw(source),))
    assert all(r["source"]["coverage"] == "EVIDENCE_NOT_CURRENT" for r in expired["required_tests"] if r["source"]["reported_verdict"] == "PASS")


@pytest.mark.parametrize("case", ["duplicate-role", "same-environment", "duplicate-test", "foreign-app", "future", "gate-instead-of-run"])
def test_ambiguous_or_mismatched_runs_fail_without_raw_value_in_error(now, case):
    plan = intake_plan(now=now)
    source, target = run_for(plan, now), run_for(plan, now, "target")
    if case == "duplicate-role":
        target = deepcopy(source)
    elif case == "same-environment":
        target["environment"]["id"] = source["environment"]["id"]
    elif case == "duplicate-test":
        source["results"].append(source["results"][0])
    elif case == "foreign-app":
        source["app"] = "private-foreign-application"
    elif case == "future":
        source["finished_at"] = (now + timedelta(seconds=1)).isoformat()
    else:
        source["kind"] = "gate_comparison"
    with pytest.raises(ContractError) as error:
        intake_plan(now=now, control_runs=(raw(source), raw(target)))
    assert "private" not in str(error.value)


@pytest.mark.parametrize("state,age,error", [("FAILED", 0, "INGESTION_GAP"), ("DISABLED", 0, "NOT_ENABLED"),
    ("STALE", 0, None), ("OK", 901, None), ("OK", 0, None)])
def test_status_success_is_not_positive_finding_and_failure_is_not_zero(now, state, age, error):
    checked = int((now - timedelta(seconds=age)).timestamp() * 1000)
    data = {"kind": "source_status", "source": "gcp_scc", "environment_id": "private-gcp-environment",
        "state": state, "checked_time": checked, "last_success_time": checked}
    if error:
        data["error_code"] = error
    result = intake_plan(now=now, source_statuses=(raw(data),))
    status = result["source_statuses"][0]
    assert status["positive_finding"] == "NOT_ESTABLISHED"
    assert status["coverage"] == ("REPORTED_UNAUTHENTICATED" if state == "OK" and not age else "GAP_OR_STALE")
    assert "private-gcp-environment" not in json.dumps(result)
    with pytest.raises(ContractError):
        intake_plan(now=now, source_statuses=(raw(data), raw(data)))


def test_duplicate_json_keys_and_unbounded_input_are_rejected(now):
    for bad in (b'{"kind":"control_run","kind":"control_run"}', b" " * (2 * 1024 * 1024 + 1)):
        with pytest.raises(ContractError):
            intake_plan(now=now, control_runs=(bad,))
