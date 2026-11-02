"""Trusted boundary callback conventions shared by security use cases."""

from sova_security.contracts.commands import ContractError


def require_accept(callback, *args, **kwargs):
    """Accept only explicit True or the documented raise-on-deny None convention.

    These callbacks are host-owned dependencies, never obtained from user input.
    A bare False, integer, string or returned unverified object cannot grant access.
    """
    result = callback(*args, **kwargs)
    if result is not None and result is not True:
        raise ContractError("Trusted boundary did not accept the request")
