"""One authorized monitoring tick; scheduling and leases remain host-owned."""

from sova_security.application.boundary import require_accept, require_authentication
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.continuous_security import (
    RuntimeSecurityBaseline,
    review_runtime_security,
)
from sova_security.application.artifact_registration import register_artifact
from sova_security.domain.governance import StoredHold


class ContinuousSecurityMonitor:
    def __init__(
        self,
        *,
        assessment_service,
        current_inputs,
        baseline_provider,
        authenticate_baseline,
        artifacts,
        holds,
        authorize,
        clock,
    ):
        self.assessment_service = assessment_service
        self.current_inputs = current_inputs
        self.baseline_provider = baseline_provider
        self.authenticate_baseline = authenticate_baseline
        self.artifacts = artifacts
        self.holds = holds
        self.authorize = authorize
        self.clock = clock

    def run_once(self, actor, *, scope):
        require_accept(self.authorize, actor, scope, "security:monitor")
        if (
            self.artifacts.tenant_id != scope.tenant_id
            or self.holds.tenant_id != scope.tenant_id
        ):
            raise ContractError("Monitoring tenant mismatch")
        baseline = self.baseline_provider(scope)
        if not isinstance(baseline, RuntimeSecurityBaseline) or baseline.scope != scope:
            raise ContractError("Registered deployment baseline required")
        require_authentication(self.authenticate_baseline, baseline)
        inputs = self.current_inputs(scope)
        if type(inputs) is not tuple or len(inputs) != 4:
            raise ContractError("Current authenticated monitoring inputs required")
        result = self.assessment_service.assess(
            actor,
            scope=scope,
            expected_inputs=tuple(value.fingerprint for value in inputs),
        )
        review = review_runtime_security(baseline, inputs[0], result, now=self.clock())
        require_accept(self.authorize, actor, scope, "security:monitor")
        require_authentication(self.authenticate_baseline, baseline)
        if (
            self.baseline_provider(scope) != baseline
            or self.current_inputs(scope) != inputs
        ):
            raise ContractError("Runtime monitoring registration changed")
        # Contain first: a later audit-store failure must not silently undo a hold.
        # Deduplicated constant reasons avoid a new hold every polling interval.
        for trigger in review.triggers:
            require_accept(self.authorize, actor, scope, "security:hold")
            receipt = self.holds.open_incident(
                scope, "continuous-security:" + trigger, actor
            )
            if (
                type(receipt) is not tuple
                or len(receipt) != 2
                or not isinstance(receipt[0], StoredHold)
                or not receipt[0].active
                or receipt[0].hold.scope != scope
                or type(receipt[1]) is not bool
            ):
                raise ContractError("Security monitoring hold was not confirmed")
        register_artifact(self.artifacts, scope, result, actor_id=actor)
        register_artifact(self.artifacts, scope, review, actor_id=actor)
        require_accept(self.authorize, actor, scope, "security:monitor")
        require_authentication(self.authenticate_baseline, baseline)
        final = utc(self.clock())
        if final < review.observed_at or final >= review.valid_until:
            raise ContractError("Continuous review expired before return")
        if (
            self.baseline_provider(scope) != baseline
            or self.current_inputs(scope) != inputs
        ):
            raise ContractError("Monitoring inputs changed before return")
        # No automatic apply, quarantine, credential rotation or hold release.
        return review
