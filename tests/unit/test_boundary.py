from dataclasses import replace

import pytest

from governance_support import bundle
from sova_security.application.boundary import require_accept, require_authentication
from sova_security.contracts.commands import ContractError


@pytest.mark.parametrize("result", [False, 0, 1, "allow", {}, [], object()])
def test_truthiness_is_not_authority(result):
    with pytest.raises(ContractError):
        require_accept(lambda: result)


def test_verified_typed_record_return_is_supported_without_accepting_false(scope, now):
    evidence = bundle(scope, now)[3]
    for result in (None, True, evidence, replace(evidence)):
        require_authentication(lambda _: result, evidence)
    for result in (
        False,
        1,
        "verified",
        {},
        replace(evidence, artifact_digest="0" * 64),
    ):
        with pytest.raises(ContractError):
            require_authentication(lambda _: result, evidence)
    with pytest.raises(ContractError):
        require_authentication(lambda _: False, False)
