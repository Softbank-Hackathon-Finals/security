"""Application API for authenticated host interfaces and registered evidence.

Never accept a raw client report as authenticated scanner/verifier output. The
host resolves identity/scope, current inventories, signer trust and adapter IDs.
"""

from sova_security.application.boundary import require_accept
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.assessment import Assessment
from sova_security.domain.remediation import RehearsalRequest, RehearsalReceipt
from sova_security.domain.patch_execution import compile_patch
from sova_security.ports.modernization import StoredSecurityArtifact


class SecurityModernizationService:
    def __init__(
        self,
        *,
        artifacts,
        assessment,
        rehearsal,
        lifecycle,
        registered_adapters,
        authorize,
        clock,
    ):
        self.artifacts = artifacts
        self.assessment = assessment
        self.rehearsal = rehearsal
        self.lifecycle = lifecycle
        self.registered_adapters = registered_adapters
        self.authorize = authorize
        self.clock = clock

    def _authorize(self, actor, scope, action):
        if scope.tenant_id != self.artifacts.tenant_id:
            raise ContractError("Host tenant differs from security repository")
        require_accept(self.authorize, actor, scope, action)

    def _load(self, actor, scope, fingerprint, *, kind=None):
        self._authorize(actor, scope, "security:read-artifact")
        stored = self.artifacts.get(scope, fingerprint)
        if (
            not isinstance(stored, StoredSecurityArtifact)
            or stored.scope != scope
            or stored.revoked
            or stored.revision != 1
            or stored.value.fingerprint != fingerprint
            or (kind is not None and not isinstance(stored.value, kind))
        ):
            raise ContractError("Active registered security artifact required")
        return stored

    def inspect(self, actor, *, scope, fingerprint):
        saved = self._load(actor, scope, fingerprint)
        self._authorize(actor, scope, "security:read-artifact")
        if self.artifacts.get(scope, fingerprint) != saved:
            raise ContractError("Artifact changed during inspection")
        return saved.value

    def assess(self, actor, *, scope, expected_inputs):
        self._authorize(actor, scope, "security:assess")
        result = self.assessment.assess(
            actor, scope=scope, expected_inputs=expected_inputs
        )
        if not isinstance(result, Assessment) or result.scope != scope:
            raise ContractError("Assessment returned another scope")
        self._authorize(actor, scope, "security:assess")
        if utc(self.clock()) >= result.valid_until:
            raise ContractError("Assessment expired before persistence")
        self.artifacts.register(scope, result, actor_id=actor)
        # Persistence never grants execution, even for a complete assessment.
        return result

    def review_rehearsal(self, actor, *, scope, request_digest, receipt_digest):
        self._authorize(actor, scope, "security:verify-rehearsal")
        request = self._load(actor, scope, request_digest, kind=RehearsalRequest)
        receipt = self._load(actor, scope, receipt_digest, kind=RehearsalReceipt)
        decision = self.rehearsal.verify(
            actor, request=request.value, receipt=receipt.value
        )
        self._authorize(actor, scope, "security:verify-rehearsal")
        if (
            self.artifacts.get(scope, request_digest) != request
            or self.artifacts.get(scope, receipt_digest) != receipt
            or utc(self.clock()) >= decision.valid_until
        ):
            raise ContractError("Registered rehearsal changed during review")
        self.artifacts.register(scope, decision, actor_id=actor)
        return decision

    def prepare_patch(
        self, actor, *, scope, request_digest, receipt_digest, plan_id, execution_scope
    ):
        self._authorize(actor, scope, "security:prepare-patch")
        request = self._load(actor, scope, request_digest, kind=RehearsalRequest).value
        receipt = self._load(actor, scope, receipt_digest, kind=RehearsalReceipt).value
        # Re-run independent admission; a stored allow is never a lasting permit.
        decision = self.rehearsal.verify(actor, request=request, receipt=receipt)
        inventories = tuple(
            self.rehearsal.target_inventory(t.scope) for t in request.targets
        )
        adapters = self.registered_adapters(request)
        plan, binding = compile_patch(
            request,
            receipt,
            decision,
            inventories=inventories,
            adapters=adapters,
            plan_id=plan_id,
            created_by=actor,
            now=self.clock(),
            execution_scope=execution_scope,
        )
        for target in request.targets:
            self._authorize(actor, target.scope, "security:prepare-patch")
        if (
            self.artifacts.get(scope, request_digest).value != request
            or self.artifacts.get(scope, receipt_digest).value != receipt
        ):
            raise ContractError("Registered rehearsal changed during compilation")
        # Save an unapproved plan first. A crash before binding registration leaves
        # an inert plan: the dispatch guard requires an authenticated active binding.
        self.lifecycle.save_plan(plan)
        if utc(self.clock()) >= binding.valid_until:
            raise ContractError("Compiled patch expired before registration")
        self._authorize(actor, scope, "security:prepare-patch")
        self.artifacts.register(scope, binding, actor_id=actor)
        return plan, binding
