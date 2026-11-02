from dataclasses import replace
from datetime import timedelta
import hashlib
import json

import pytest
from team_controls_support import team_control_bundle
from sova_security.application.team_controls import TeamControlRunService, COLLECTOR
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.ports.modernization import StoredSecurityArtifact


@pytest.fixture
def team_importer():
    body, registration, now = team_control_bundle()
    raw = json.dumps(body).encode()
    receipt = EvidenceRecord(
        "team-collection-receipt",
        "team-control-collection:" + registration.fingerprint,
        registration.scope,
        registration.revisions,
        COLLECTOR,
        now,
        now + timedelta(minutes=1),
        VerificationResult.PASS,
        "synthetic-team-report",
        hashlib.sha256(raw).hexdigest(),
    )
    state = {
        "registration": registration,
        "report": (raw, receipt),
        "trusted": True,
        "allowed": True,
        "stored": {},
        "late": lambda: None,
    }

    class Repo:
        tenant_id = registration.scope.tenant_id

        def register(self, scope, value, *, actor_id):
            stored = StoredSecurityArtifact(scope, value, 1, False)
            state["stored"][value.fingerprint] = stored
            state["late"]()
            return stored

        def get(self, scope, fingerprint):
            return state["stored"][fingerprint]

    service = TeamControlRunService(
        registration_provider=lambda _: state["registration"],
        report_provider=lambda _: state["report"],
        authenticate_registration=lambda _: state["trusted"],
        authenticate_report=lambda _: state["trusted"],
        authorize=lambda *_: state["allowed"],
        artifacts=Repo(),
        clock=lambda: now,
    )
    return service, state, registration


def test_raw_collection_and_profile_are_authenticated_before_import(team_importer):
    service, state, registration = team_importer
    result = service.import_current("operator", scope=registration.scope)
    assert len(result.evidence) == 3
    assert result.valid_until == state["report"][1].valid_until
    assert result.fingerprint in state["stored"]


@pytest.mark.parametrize(
    "mode", ["raw", "scope", "version", "expired", "denied", "unsigned"]
)
def test_untrusted_or_rebound_team_run_never_persists(team_importer, mode):
    service, state, registration = team_importer
    raw, receipt = state["report"]
    if mode == "raw":
        raw += b" "
    if mode == "scope":
        receipt = replace(receipt, scope=replace(receipt.scope, tenant_id="other"))
    if mode == "version":
        receipt = replace(receipt, verifier_version="unregistered")
    if mode == "expired":
        receipt = replace(
            receipt,
            observed_at=receipt.observed_at - timedelta(seconds=10),
            valid_until=receipt.observed_at,
        )
    if mode == "denied":
        state["allowed"] = False
    if mode == "unsigned":
        state["trusted"] = False
    state["report"] = raw, receipt
    with pytest.raises(ContractError):
        service.import_current("operator", scope=registration.scope)
    assert not state["stored"]


@pytest.mark.parametrize("field", ["allowed", "trusted"])
def test_late_revoke_never_returns_success(team_importer, field):
    service, state, registration = team_importer
    state["late"] = lambda: state.update({field: False})
    with pytest.raises(ContractError):
        service.import_current("operator", scope=registration.scope)
