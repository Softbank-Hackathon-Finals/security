"""Synthetic OCSF projections match pinned official output, no live AWS scan."""

from dataclasses import replace
import hashlib
import json

import pytest

from sova_security.adapters.modernization_codec import encode, decode
from sova_security.adapters.prowler_reports import (
    prowler_configuration,
    configuration_evidence,
    VERIFIER,
)
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import (
    VerificationResult as Result,
    VerificationObligation,
    Gate,
    evaluate_gate,
)
from prowler_support import configuration_registration, event


@pytest.fixture
def registration(scope, now):
    return configuration_registration(scope, now)


def project(events, registration, now):
    return prowler_configuration(
        json.dumps(events).encode(), registration=registration, now=now
    )


def test_complete_selected_checks_are_config_only_and_codec_bound(registration, now):
    raw = json.dumps(
        [event(registration, now, check=c) for c in registration.expected_checks]
    ).encode()
    snapshot = prowler_configuration(raw, registration=registration, now=now)
    assert snapshot.all_selected_checks_pass
    assert snapshot.report_digest == hashlib.sha256(raw).hexdigest()
    assert decode(encode(snapshot).encode()) == snapshot
    record = configuration_evidence(
        snapshot, check_id=registration.expected_checks[0], evidence_id="signed-later"
    )
    assert record.verifier_version == VERIFIER
    assert record.result == Result.PASS
    runtime = VerificationObligation(
        "runtime-tls-enforced",
        registration.scope,
        Gate.PROTECTION,
        "tls-probe.v1",
        True,
    )
    assert not evaluate_gate(
        Gate.PROTECTION, (runtime,), (record,), registration.revisions, now=now
    ).accepted


@pytest.mark.parametrize(
    "status,result",
    [
        ("FAIL", Result.FAIL),
        ("MANUAL", Result.UNKNOWN),
        ("ERROR", Result.UNKNOWN),
        (None, Result.UNKNOWN),
        (True, Result.UNKNOWN),
    ],
)
def test_non_pass_status_is_never_promoted(registration, now, status, result):
    snapshot = project([event(registration, now, status=status)], registration, now)
    assert snapshot.checks[0].result == result
    assert snapshot.checks[1].reason == "missing"
    assert not snapshot.all_selected_checks_pass


@pytest.mark.parametrize(
    "status,status_id",
    [("Suppressed", 4), ("New", True), ("Resolved", 2), (None, 1), ("New", 99)],
)
def test_lifecycle_status_is_not_check_success(registration, now, status, status_id):
    finding = event(registration, now)
    finding.update(status=status, status_id=status_id)
    assert project([finding], registration, now).checks[0].result == Result.UNKNOWN


@pytest.mark.parametrize(
    "path,value",
    [
        (("metadata", "product", "version"), "5.46.0"),
        (("metadata", "product", "uid"), "untrusted-tool"),
        (("cloud", "account", "uid"), "000000000000"),
        (("cloud", "provider"), "gcp"),
        (("cloud", "region"), "eu-west-1"),
        (("metadata", "event_code"), "unregistered_check"),
        (("class_uid",), True),
        (("time",), True),
    ],
)
def test_report_identity_mismatch_blocks(registration, now, path, value):
    finding = event(registration, now)
    current = finding
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value
    with pytest.raises(ContractError):
        project([finding], registration, now)


def test_resource_alias_and_duplicate_fail(registration, now):
    finding = event(registration, now)
    finding["resources"][0]["uid"] += "-other"
    with pytest.raises(ContractError):
        project([finding], registration, now)
    finding = event(registration, now)
    with pytest.raises(ContractError):
        project([finding, finding], registration, now)


@pytest.mark.parametrize("offset", [-301, -300, 1])
def test_stale_and_future_observation_rejected(registration, now, offset):
    finding = event(registration, now)
    finding["time"] += offset
    with pytest.raises(ContractError):
        project([finding], registration, now)


@pytest.mark.parametrize(
    "raw", [b'[{"time":1,"time":2}]', b"[NaN]", b"{}", b'[] , "injected": true']
)
def test_malformed_report_and_envelope_injection_rejected(registration, now, raw):
    with pytest.raises(ContractError):
        prowler_configuration(raw, registration=registration, now=now)


def test_empty_report_is_missing_not_vacuous_pass(registration, now):
    snapshot = project([], registration, now)
    assert all(c.result == Result.UNKNOWN for c in snapshot.checks)
    assert not snapshot.all_selected_checks_pass


def test_registration_cannot_accept_foreign_account_arn(registration):
    with pytest.raises(ContractError):
        replace(registration, account_id="000000000000")
