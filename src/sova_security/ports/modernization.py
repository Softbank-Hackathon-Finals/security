"""Security-owned artifact storage, not lifecycle approval or execution."""

from dataclasses import dataclass
from typing import Protocol

from sova_security.contracts.commands import ResourceScope


@dataclass(frozen=True, slots=True)
class StoredSecurityArtifact:
    scope: ResourceScope
    value: object
    revision: int
    revoked: bool


class SecurityArtifactRepository(Protocol):
    tenant_id: str

    def register(
        self, scope: ResourceScope, value, *, actor_id: str
    ) -> StoredSecurityArtifact: ...
    def get(
        self, scope: ResourceScope, fingerprint: str, *, require_active: bool = True
    ) -> StoredSecurityArtifact: ...
    def request(self, scope: ResourceScope, request_id: str): ...
    def program(self, scope: ResourceScope, subject_digest: str): ...
    def program_routes(self, scope: ResourceScope, program_digest: str): ...
    def revoke(
        self,
        scope: ResourceScope,
        fingerprint: str,
        *,
        expected_revision: int,
        actor_id: str,
        reason: str,
    ) -> StoredSecurityArtifact: ...
