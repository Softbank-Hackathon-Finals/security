"""Trusted boundary callback conventions shared by security use cases."""

from sova_security.contracts.commands import ContractError
from dataclasses import is_dataclass


def require_accept(callback, *args, **kwargs):
    """Accept only explicit True or the documented raise-on-deny None convention.

    These callbacks are host-owned dependencies, never obtained from user input.
    A bare False, integer, string or returned unverified object cannot grant access.
    """
    result = callback(*args, **kwargs)
    if result is not None and result is not True:
        raise ContractError("Trusted boundary did not accept the request")


def require_authentication(callback, subject):
    """Permit an exact authenticated typed subject as well as None/True.

    Signature adapters may return the verified EvidenceRecord. Arbitrary truthy
    objects, false verdicts and a different attested subject are never accepted.
    """
    result = callback(subject)
    if result is None or result is True:
        return
    if (
        is_dataclass(subject)
        and not isinstance(subject, type)
        and type(result) is type(subject)
        and result == subject
    ):
        return
    raise ContractError("Trusted authentication did not accept this subject")
