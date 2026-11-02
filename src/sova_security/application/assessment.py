"""Assessment admission; host supplies trusted current snapshots and identity."""

from sova_security.contracts.commands import ContractError, utc, digest
from sova_security.application.boundary import require_accept
from sova_security.domain.assessment import (
    assess_risk,
    AssetInventory,
    VulnerabilityScan,
    ExposureObservation,
    RiskPolicy,
)


class AssessmentService:
    def __init__(self, *, authorize, authenticate_input, current_inputs, clock):
        self.authorize = authorize
        self.authenticate_input = authenticate_input
        self.current_inputs = current_inputs
        self.clock = clock

    def assess(self, actor, *, scope, expected_inputs):
        """expected_inputs is the four fingerprints shown to this caller."""
        require_accept(self.authorize, actor, scope, "security:assess")
        inputs = self.current_inputs(scope)
        if (
            type(inputs) is not tuple
            or len(inputs) != 4
            or type(expected_inputs) is not tuple
            or len(expected_inputs) != 4
        ):
            raise ContractError(
                "Explicit inventory/scan/exposure/policy bindings required"
            )
        if any(
            not isinstance(value, kind)
            for value, kind in zip(
                inputs,
                (AssetInventory, VulnerabilityScan, ExposureObservation, RiskPolicy),
                strict=True,
            )
        ):
            raise ContractError("Typed assessment authority inputs required")
        if inputs[0].scope != scope:
            raise ContractError("Assessment authority returned another resource scope")
        for value in expected_inputs:
            digest(value)
        if tuple(x.fingerprint for x in inputs) != expected_inputs:
            raise ContractError("Assessment inputs changed")
        for value in inputs:
            require_accept(self.authenticate_input, actor, scope, value)
        before = utc(self.clock())
        result = assess_risk(*inputs, now=before)
        require_accept(self.authorize, actor, scope, "security:assess")
        refreshed = self.current_inputs(scope)
        if refreshed != inputs:
            raise ContractError("Assessment authority changed during evaluation")
        for value in refreshed:
            require_accept(self.authenticate_input, actor, scope, value)
        require_accept(self.authorize, actor, scope, "security:assess")
        if self.current_inputs(scope) != inputs:
            raise ContractError("Assessment inputs changed before return")
        final = utc(self.clock())
        if final < before or final >= result.valid_until:
            raise ContractError("Assessment admission expired")
        # policy expiry is checked in assess_risk; source validity has not been extended.
        return result
