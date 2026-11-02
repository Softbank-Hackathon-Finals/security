"""Authenticated import into the existing security artifact/evidence system."""

from sova_security.adapters.vulnerability_reports import MAX_BYTES
from dataclasses import replace
import hashlib

from sova_security.application.artifact_registration import register_artifact
from sova_security.application.boundary import require_accept, require_authentication
from sova_security.adapters.team_control_results import import_control_run
from sova_security.contracts.commands import ContractError, utc
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.team_controls import TeamControlRegistration

COLLECTOR = "team-bravo.controls.collector.v1"


class TeamControlRunService:
    def __init__(
        self,
        *,
        registration_provider,
        report_provider,
        authenticate_registration,
        authenticate_report,
        authorize,
        artifacts,
        clock,
    ):
        self.registration_provider = registration_provider
        self.report_provider = report_provider
        self.authenticate_registration = authenticate_registration
        self.authenticate_report = authenticate_report
        self.authorize = authorize
        self.artifacts = artifacts
        self.clock = clock

    def import_current(self, actor, *, scope):
        started = utc(self.clock())
        require_accept(self.authorize, actor, scope, "security:import-team-controls")
        if self.artifacts.tenant_id != scope.tenant_id:
            raise ContractError("Team control store tenant mismatch")
        registration = self.registration_provider(scope)
        if (
            not isinstance(registration, TeamControlRegistration)
            or registration.scope != scope
        ):
            raise ContractError("Registered team control scope required")
        require_authentication(self.authenticate_registration, registration)
        report = self.report_provider(registration)
        if type(report) is not tuple or len(report) != 2:
            raise ContractError(
                "Raw control run and signed collection receipt required"
            )
        raw, receipt = report
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= MAX_BYTES - 32
            or not isinstance(receipt, EvidenceRecord)
        ):
            raise ContractError("Typed team control collection input required")
        require_authentication(self.authenticate_report, receipt)
        if (
            receipt.scope != scope
            or receipt.revisions != registration.revisions
            or receipt.obligation_id
            != "team-control-collection:" + registration.fingerprint
            or receipt.verifier_version != COLLECTOR
            or receipt.result != VerificationResult.PASS
            or receipt.artifact_digest != hashlib.sha256(raw).hexdigest()
            or not registration.observed_at
            <= receipt.observed_at
            <= started
            < min(receipt.valid_until, registration.valid_until)
        ):
            raise ContractError(
                "Signed team collection receipt does not bind raw report/registration"
            )
        imported = import_control_run(
            raw, registration=registration, now=receipt.observed_at
        )
        deadline = min(imported.valid_until, receipt.valid_until)
        imported = replace(imported, valid_until=deadline)

        def recheck():
            require_accept(
                self.authorize, actor, scope, "security:import-team-controls"
            )
            require_authentication(self.authenticate_registration, registration)
            require_authentication(self.authenticate_report, receipt)
            if (
                self.registration_provider(scope) != registration
                or self.report_provider(registration) != report
            ):
                raise ContractError("Team control authority changed")
            final = utc(self.clock())
            if final < started or final >= imported.valid_until:
                raise ContractError("Team control import expired before return")

        recheck()
        register_artifact(self.artifacts, scope, imported, actor_id=actor)
        recheck()
        return imported
