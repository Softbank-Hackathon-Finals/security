from dataclasses import replace
from datetime import timedelta
import hashlib
import json

import pytest

from prowler_support import configuration_registration, event

from sova_security.application.configuration_scan import (
    ConfigurationAssessmentService,
    COLLECTOR,
)
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.ports.modernization import StoredSecurityArtifact


@pytest.fixture
def registration(scope, now):
    return configuration_registration(scope, now)


@pytest.fixture
def service(registration, now):
    raw = json.dumps(
        [event(registration, now, check=c) for c in registration.expected_checks]
    ).encode()
    receipt = EvidenceRecord(
        "collector-receipt",
        "prowler-collection:" + registration.fingerprint,
        registration.scope,
        registration.revisions,
        COLLECTOR,
        now,
        now + timedelta(minutes=1),
        VerificationResult.PASS,
        "registered-report",
        hashlib.sha256(raw).hexdigest(),
    )
    state = {
        "registration": registration,
        "report": (raw, receipt),
        "allowed": True,
        "stored": {},
        "signature": True,
        "time": now,
        "late": lambda: None,
    }

    class Repo:
        tenant_id = registration.scope.tenant_id

        def register(self, scope, value, *, actor_id):
            value = StoredSecurityArtifact(scope, value, 1, False)
            state["stored"][value.value.fingerprint] = value
            state["late"]()
            return value

        def get(self, scope, fingerprint):
            return state["stored"][fingerprint]

    instance = ConfigurationAssessmentService(
        registration_provider=lambda _: state["registration"],
        report_provider=lambda _: state["report"],
        authenticate_registration=lambda _: True,
        authenticate_report=lambda _: state["signature"],
        authorize=lambda *_: state["allowed"],
        artifacts=Repo(),
        clock=lambda: state["time"],
    )
    return instance, state


def test_authenticated_report_is_durably_stored(service, registration):
    instance, state = service
    result = instance.collect("collector", scope=registration.scope)
    assert result.all_selected_checks_pass
    assert result.valid_until == state["report"][1].valid_until
    assert result.fingerprint in state["stored"]


@pytest.mark.parametrize(
    "field",
    [
        "scope",
        "version",
        "digest",
        "obligation",
        "expired",
        "future",
        "result",
        "revisions",
    ],
)
def test_report_receipt_cannot_be_rebound(service, registration, now, field):
    instance, state = service
    raw, receipt = state["report"]
    changes = {
        "scope": {"scope": replace(registration.scope, application_id="other")},
        "version": {"verifier_version": "other-collector"},
        "digest": {"artifact_digest": "f" * 64},
        "obligation": {"obligation_id": "unregistered-profile"},
        "expired": {"observed_at": now - timedelta(minutes=2), "valid_until": now},
        "future": {"observed_at": now + timedelta(seconds=1)},
        "result": {"result": VerificationResult.UNKNOWN},
        "revisions": {"revisions": replace(receipt.revisions, configuration="f" * 64)},
    }
    state["report"] = (raw, replace(receipt, **changes[field]))
    with pytest.raises(ContractError):
        instance.collect("collector", scope=registration.scope)
    assert not state["stored"]


@pytest.mark.parametrize("field", ["allowed", "signature"])
def test_false_callbacks_are_denial(service, registration, field):
    instance, state = service
    state[field] = False
    with pytest.raises(ContractError):
        instance.collect("collector", scope=registration.scope)
    assert not state["stored"]


@pytest.mark.parametrize("field", ["allowed", "signature", "time", "registration"])
def test_late_revocation_never_returns_success(service, registration, now, field):
    instance, state = service

    def late():
        state[field] = {
            "allowed": False,
            "signature": False,
            "time": now + timedelta(minutes=1),
            "registration": replace(
                registration,
                scanner_version="5.47.0",
                expected_checks=(registration.expected_checks[0],),
            ),
        }[field]

    state["late"] = late
    with pytest.raises(ContractError):
        instance.collect("collector", scope=registration.scope)
