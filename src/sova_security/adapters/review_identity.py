"""Consume existing short-lived workload credentials and online TokenReview."""

import base64
from dataclasses import dataclass
from datetime import UTC, datetime

from sova_security.adapters.review_https import BearerCredential, bearer
from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, canonical_json, identifier, utc
from sova_security.domain.review_service import ReviewPrincipal


class ExecCredentialProvider:
    """Wrap the host's T7 acquire/standard exec provider without minting tokens."""

    def __init__(self, acquire, *, clock):
        self.acquire, self.clock = acquire, clock

    def __call__(self):
        try:
            result = self.acquire()
            if (type(result) is not dict or set(result) != {"apiVersion", "kind", "status"}
                    or result["apiVersion"] != "client.authentication.k8s.io/v1"
                    or result["kind"] != "ExecCredential" or type(result["status"]) is not dict
                    or set(result["status"]) != {"token", "expirationTimestamp"}):
                raise ValueError()
            value = BearerCredential(result["status"]["token"], datetime.fromisoformat(result["status"]["expirationTimestamp"]))
            if utc(self.clock()) >= value.valid_until:
                raise ValueError()
            return value
        except Exception:
            raise ContractError("Current host-issued credential unavailable") from None


@dataclass(frozen=True, slots=True)
class WorkloadGrant:
    username: str
    uid: str
    principal: ReviewPrincipal

    def __post_init__(self):
        identifier(self.username)
        identifier(self.uid)
        if not self.username.startswith("system:serviceaccount:") or type(self.principal) is not ReviewPrincipal:
            raise ContractError("Registered workload identity required")


class TokenReviewAuthenticator:
    """TokenReview verifies signature/current bound objects; claims only bound time.

    The registered grant supplies the tenant, scopes and permissions. JWT claims
    and Kubernetes groups never enroll an identity or widen a grant.
    """

    def __init__(self, *, audience, transport, reviewer_credential, grant_for, clock):
        self.audience = identifier(audience)
        self.transport, self.reviewer_credential = transport, reviewer_credential
        self.grant_for, self.clock = grant_for, clock

    def __call__(self, token):
        try:
            bearer(token)
            # This parse is NOT signature verification. Successful online verification below is mandatory.
            parts = token.split(".")
            if len(parts) != 3 or any(not p for p in parts):
                return None
            claims = bounded_report(base64.b64decode(parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True))
            if any(type(claims.get(k)) is not int for k in ("iat", "nbf", "exp")):
                return None
            now = utc(self.clock())
            start = datetime.fromtimestamp(max(claims["iat"], claims["nbf"]), UTC)
            end = datetime.fromtimestamp(claims["exp"], UTC)
            if not start <= now < end:
                return None
            reviewer = self.reviewer_credential()
            if type(reviewer) is not BearerCredential or now >= reviewer.valid_until:
                return None
            raw = canonical_json({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                                  "spec": {"token": token, "audiences": [self.audience]}}, limit=32768).encode()
            value = bounded_report(self.transport.post("/apis/authentication.k8s.io/v1/tokenreviews", raw, reviewer))
            if value.get("apiVersion") != "authentication.k8s.io/v1" or value.get("kind") != "TokenReview":
                return None
            status = value.get("status", {})
            if (type(status) is not dict or status.get("authenticated") is not True or status.get("error")
                    or type(status.get("audiences")) is not list or self.audience not in status["audiences"]):
                return None
            user = status.get("user", {})
            if type(user) is not dict or claims.get("sub") != user.get("username"):
                return None
            grant = self.grant_for(user.get("username"), user.get("uid"))
            if type(grant) is not WorkloadGrant or (grant.username, grant.uid) != (user.get("username"), user.get("uid")):
                return None
            p = grant.principal
            finished = utc(self.clock())
            if not max(start, p.issued_at) <= now <= finished < min(end, p.valid_until, reviewer.valid_until):
                return None
            return ReviewPrincipal(p.subject_id, p.tenant_id, p.scopes, p.modes,
                                   max(start, p.issued_at), min(end, p.valid_until), p.grant_digest)
        except Exception:
            # Neither unverified token contents nor provider diagnostics cross the boundary.
            return None
