"""Optional composition with the real T10/T19 authority, not a replacement gate.

Platform imports are lazy: the standalone security core has no platform runtime
dependency. The pinned platform packages must be installed by the platform host.
"""

from dataclasses import replace

from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.review_service import HostReviewBinding, ReviewRegistration
from sova_security.domain.security_program import ProgramKind, ProgramPhase

PLATFORM_BASELINE = "b19488e2debbee8bbe120f1309eadbe19df85b6f"
PLATFORM_BASELINES = ("f602b39a949b99f3e2e7be901103063e78a52a70", PLATFORM_BASELINE)


def t10_host_binding(program, session, plan, *, baseline_sha=PLATFORM_BASELINE):
    """Structural projection of a host-authenticated session. Not authentication."""
    from bravo_gate.contract import decode
    from bravo_gate.t10 import PlanGateSession

    if baseline_sha not in PLATFORM_BASELINES:
        raise ContractError("Explicitly qualified platform source revision required")
    if type(session) is not PlanGateSession:
        raise ContractError("Actual platform PlanGateSession required")
    spec = decode(plan["spec_json"].encode())
    ctx = session.context
    prefix = "recheck_" if session.gate_phase == "post_apply" else ""
    if (session.plan_id != plan["plan_id"] or spec["plan_id"] != plan["plan_id"]
            or ctx.tenant_id != plan["tenant_id"] or spec["tenant_id"] != ctx.tenant_id
            or ctx.tenant_id != program.target.tenant_id or ctx.app != program.target.application_id
            or spec["workload_id"] != ctx.app or spec["plan_digest"] != program.subject_digest
            or ctx.plan_digest != program.subject_digest
            or spec.get(prefix + "profile_id") != ctx.profile_id
            or spec.get(prefix + "profile_version") != ctx.profile_version
            or spec["source_environment_id"] != program.source.environment_id
            or spec["target_environment_id"] != program.target.environment_id
            or ctx.source_environment_id != program.source.environment_id
            or ctx.target_environment_id != program.target.environment_id):
        raise ContractError("Platform plan, profile, environment or tenant differs")
    return HostReviewBinding("platform-t10", baseline_sha, plan["plan_id"], program.subject_digest,
                             session.fingerprint, ctx.profile_id, ctx.profile_version,
                             session.gate_phase, session.application_id)


class T10ProgramAuthority:
    """Add a fresh remote condition inside the existing T10 authority call.

    upstream must be the configured real T10GateAuthority, including all current
    operational/SHIFT/approval checks. The same connection/plan lock is passed
    through; remote I/O itself is not a distributed lock or immediate revocation.
    """

    def __init__(self, *, upstream, load_session, load_registration, client, scope, clock, baseline_sha=PLATFORM_BASELINE):
        from bravo_gate.t10 import T10GateAuthority
        from sova_security.adapters.remote_review import RemoteReviewClient
        if type(upstream) is not T10GateAuthority or type(client) is not RemoteReviewClient:
            raise ContractError("Existing platform authority and remote client required")
        if not callable(load_registration):
            raise ContractError("Registration reader under the host plan lock required")
        if baseline_sha not in PLATFORM_BASELINES:
            raise ContractError("Explicitly qualified platform source revision required")
        self.baseline_sha = baseline_sha
        self.upstream, self.load_session, self.client = upstream, load_session, client
        self.load_registration = load_registration
        self.scope, self.clock = scope, clock

    def __call__(self, connection, principal, plan, *, now, approved_by, approval_id):
        from bravo_gate.contract import fingerprint

        if connection is None or principal.tenant_id != self.scope.tenant_id or plan.get("state") != "SHIFT":
            raise ContractError("Current tenant-bound platform transaction required")
        def operational():
            return self.upstream(connection, principal, plan, now=now,
                                 approved_by=approved_by, approval_id=approval_id)
        started = utc(self.clock())
        first = operational()
        session = self.load_session(connection, principal, plan)
        # Enrollment/revocation writers for this host record must take this same
        # plan lock. The remote database is not a substitute for that local fence.
        registration = self.load_registration(connection, principal, plan, ProgramPhase.PREFLIGHT)
        if type(registration) is not ReviewRegistration or registration.program.kind != ProgramKind.MIGRATION:
            raise ContractError("Registered migration preflight required")
        binding = t10_host_binding(registration.program, session, plan, baseline_sha=self.baseline_sha)
        if registration.host_binding != binding:
            raise ContractError("Registered security context differs from current platform session")
        if self.client.current_registration(self.scope, registration.program.subject_digest, ProgramPhase.PREFLIGHT) != registration:
            raise ContractError("Client registration differs from locked platform registration")
        response = self.client.review(scope=self.scope, subject_digest=registration.program.subject_digest,
                                      phase=ProgramPhase.PREFLIGHT, mode="enforce")
        if not response.review.passed:
            raise ContractError("Additional security program has not passed")
        latest = operational()
        current = self.load_session(connection, principal, plan)
        finished = utc(self.clock())
        if (latest != first or current.fingerprint != session.fingerprint
                or self.load_registration(connection, principal, plan, ProgramPhase.PREFLIGHT) != registration
                or self.client.current_registration(self.scope, registration.program.subject_digest, ProgramPhase.PREFLIGHT) != registration
                or finished < started or finished >= response.valid_until):
            raise ContractError("Platform or remote authority changed during admission")
        # Stable binding changes invalidate approval; per-request nonce/time does not.
        return replace(latest, revision=fingerprint(dict(kind="security-program-t10.v1", upstream=latest.revision,
                        registration=registration.fingerprint, session=session.fingerprint)))
