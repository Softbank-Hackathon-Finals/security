"""Host-owned Harbor/execution ports. No credentials or caller-chosen URLs."""

from typing import Protocol
from sova_security.domain.remediation import RehearsalRequest, RehearsalReceipt


class HarborRehearsalPort(Protocol):
    def submit(self, request: RehearsalRequest, *, idempotency_key: str) -> str:
        """Submit the exact registered request; return the durable host operation ID.

        Host enforces sandbox admission, quotas and idempotency. If the remote
        outcome is uncertain, reconcile by the existing key instead of retrying
        a different submission or silently choosing another sandbox.
        """
        ...

    def inspect(self, operation_id: str) -> RehearsalReceipt | None:
        """Read authenticated independent-verifier output; None means pending."""
        ...
