from typing import Protocol

from sova_security.domain.opa_policy import OPAPolicy


class OPAEvaluator(Protocol):
    def evaluate(
        self, policy: OPAPolicy, input_document: dict
    ) -> tuple[bool, tuple[str, ...]]:
        """Pinned engine/policy; bounded output. A verdict is not authorization."""
        ...
