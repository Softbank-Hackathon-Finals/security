"""Read-only comparisons. A matching shadow result has no admission authority."""

from dataclasses import dataclass

from sova_security.contracts.commands import ContractError
from sova_security.domain.review_service import validate_review


@dataclass(frozen=True, slots=True)
class ShadowComparison:
    context_digest: str
    matched: bool
    changed_checks: tuple[str, ...]
    remote_available: bool
    execution_authorized: bool = False


def compare_shadow(local_service, remote_client, *, actor, scope, subject_digest, phase, not_before=None):
    registration = remote_client.current_registration(scope, subject_digest, phase)
    local = local_service.review(actor, scope=scope, subject_digest=subject_digest, phase=phase, not_before=not_before)
    validate_review(local, registration)
    try:
        remote = remote_client.review(scope=scope, subject_digest=subject_digest, phase=phase,
                                      mode="shadow", not_before=not_before)
    except ContractError:
        return ShadowComparison(registration.fingerprint, False, (), False)
    if remote.context_digest != registration.fingerprint or remote.mode != "shadow":
        raise ContractError("Shadow comparison registration changed")
    def rows(review):
        return {r.check_id: (r.result, r.reason, r.evidence_id, r.references) for r in review.results}
    before, after = rows(local), rows(remote.review)
    changed = tuple(sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k)))
    return ShadowComparison(registration.fingerprint, not changed, changed, True)
