"""Security guard installed on the host's existing approved-plan executor.

This module never dispatches an effect or grants an approval. The host owns
transactional registration, approval revocation, fencing, execution and recovery.
"""

from sova_security.application.boundary import require_accept
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.patch_execution import PatchExecutionBinding, compile_patch


class PatchExecutionGuard:
    def __init__(
        self,
        *,
        admission,
        binding_for,
        inputs_for,
        authenticate_binding,
        authorize,
        require_no_holds,
        clock,
    ):
        self.admission = admission
        self.binding_for = binding_for
        self.inputs_for = inputs_for
        self.authenticate_binding = authenticate_binding
        self.authorize = authorize
        self.require_no_holds = require_no_holds
        self.clock = clock

    def check(self, actor, plan):
        """Rebuild and compare the complete registered plan before each effect.

        inputs_for returns request, receipt, inventories, registered adapters.
        Authenticate these in the host; admission authenticates current rehearsal
        inputs and the independent receipt. An active incident hold is not waived
        by an ordinary patch or by human change approval.
        """
        started = utc(self.clock())
        binding = self.binding_for(plan)
        if not isinstance(binding, PatchExecutionBinding):
            raise ContractError("Registered patch binding required")
        require_accept(self.authenticate_binding, actor, binding)
        require_accept(self.authorize, actor, binding.scope, "security:apply-patch")
        saved = self.inputs_for(binding)
        if type(saved) is not tuple or len(saved) != 4:
            raise ContractError("Registered patch input tuple required")
        request, receipt, inventories, adapters = saved
        # Copy mutable registry output, retaining a snapshot for the final check.
        if type(adapters) is not dict:
            raise ContractError("Registered adapter mapping required")
        adapters = dict(adapters)
        for target in request.targets:
            require_accept(self.authorize, actor, target.scope, "security:apply-patch")
            require_accept(self.require_no_holds, target.scope)
        decision = self.admission.verify(actor, request=request, receipt=receipt)
        fresh_plan, fresh_binding = compile_patch(
            request,
            receipt,
            decision,
            inventories=inventories,
            adapters=adapters,
            plan_id=plan.plan_id,
            created_by=plan.created_by,
            now=started,
        )
        # Binding time is registration time, not each guard invocation.
        if (
            fresh_plan != plan
            or binding.plan_digest != plan.fingerprint
            or binding.request_digest != fresh_binding.request_digest
            or binding.receipt_digest != fresh_binding.receipt_digest
            or binding.decision_digest != fresh_binding.decision_digest
            or binding.artifacts != fresh_binding.artifacts
            or binding.valid_until != fresh_binding.valid_until
        ):
            raise ContractError("Registered patch differs from approved lifecycle plan")
        require_accept(self.authenticate_binding, actor, binding)
        if self.binding_for(plan) != binding or self.inputs_for(binding) != (
            request,
            receipt,
            inventories,
            adapters,
        ):
            raise ContractError(
                "Patch registration changed during dispatch authorization"
            )
        for target in request.targets:
            require_accept(self.authorize, actor, target.scope, "security:apply-patch")
            require_accept(self.require_no_holds, target.scope)
        final = utc(self.clock())
        if not binding.created_at <= started <= final < binding.valid_until:
            raise ContractError("Patch authority expired or clock moved backwards")
        return binding.valid_until
