"""Authenticate imported detections and open conservative, deduplicated holds.

A detector never receives deploy, rotate, isolate, release or approval authority.
Resolved, suppressed and sample records are retained without clearing incidents.
"""

from sova_security.application.artifact_registration import register_artifact
from sova_security.application.boundary import require_accept, require_authentication
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.detection import DetectionObservation
from sova_security.domain.governance import StoredHold


class DetectionAdmission:
    def __init__(
        self,
        *,
        current_registration,
        authenticate_registration,
        authenticate_observation,
        artifacts,
        holds,
        authorize,
        clock,
    ):
        self.current_registration = current_registration
        self.authenticate_registration = authenticate_registration
        self.authenticate_observation = authenticate_observation
        self.artifacts, self.holds = artifacts, holds
        self.authorize, self.clock = authorize, clock

    def _current(self, observation):
        r = observation.registration
        if self.current_registration(r.scope, r.source) != r:
            raise ContractError("Detection registration changed/revoked")
        now = utc(self.clock())
        if (
            not r.observed_at <= now < r.valid_until
            or not observation.observed_at <= now < observation.valid_until
        ):
            raise ContractError("Detection authority/evidence expired")

    def _authority(self, actor, observation):
        r = observation.registration
        scope = r.scope
        self._current(observation)
        require_accept(self.authorize, actor, scope, "security:admit-detection")
        require_authentication(self.authenticate_registration, r)
        require_authentication(self.authenticate_observation, observation)
        # Remote signature/key checks may take time or observe a revocation.
        # Do not use their pre-call clock/registration snapshot for a new hold.
        require_accept(self.authorize, actor, scope, "security:admit-detection")
        self._current(observation)

    def admit(self, actor, observation):
        if not isinstance(observation, DetectionObservation):
            raise ContractError("Typed imported detection required")
        scope = observation.scope
        if (self.artifacts.tenant_id, self.holds.tenant_id) != (
            scope.tenant_id,
            scope.tenant_id,
        ):
            raise ContractError("Detection repository tenant mismatch")
        self._authority(actor, observation)
        if observation.requires_hold:
            require_accept(self.authorize, actor, scope, "security:hold")
            self._authority(actor, observation)
            require_accept(self.authorize, actor, scope, "security:hold")
            self._current(observation)
            # Stable per source/resource finding, independent of collection time.
            # A later clean/no-event sample does not close this incident.
            reason = "detection:" + observation.signal + ":" + observation.finding_key
            receipt = self.holds.open_incident(scope, reason, actor)
            if (
                type(receipt) is not tuple
                or len(receipt) != 2
                or not isinstance(receipt[0], StoredHold)
                or not receipt[0].active
                or receipt[0].hold.scope != scope
                or type(receipt[1]) is not bool
            ):
                raise ContractError("Detection incident hold was not confirmed")
        register_artifact(
            self.artifacts, scope, observation.registration, actor_id=actor
        )
        self._authority(actor, observation)
        register_artifact(self.artifacts, scope, observation, actor_id=actor)
        self._authority(actor, observation)
        return observation
