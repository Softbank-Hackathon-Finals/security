from dataclasses import replace
from datetime import timedelta
import hashlib

from governance_support import bundle
from sova_security.adapters.opa_local import (
    restricted_capabilities,
    preflight_policy_source,
)
from sova_security.domain.opa_policy import OPAPolicy


def opa_bundle(scope, now, engine_digest="a" * 64):
    _, plan, _, evidence, _ = bundle(scope, now)
    policy = OPAPolicy(
        scope,
        "operator-preflight",
        1,
        preflight_policy_source(),
        engine_digest,
        hashlib.sha256(restricted_capabilities()).hexdigest(),
        (scope,),
        plan.obligations,
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    return (
        policy,
        replace(plan, obligations=(*plan.obligations, policy.obligation)),
        evidence,
    )
