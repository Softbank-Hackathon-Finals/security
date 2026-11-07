"""Resource-bound detection evidence; a finding is not a mutation permit."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    digest,
    identifier,
)
from sova_security.domain.assessment import Document, window

SCHEMA_DIGEST = "22ad580baf4854ef1d272a497ebe708ef48a65d47fc3840eb2d00b3fa441f8b1"
CURRENT_SCHEMA_DIGEST = "efa3e36bf8ec704622fefc40c84a2c23242f55b6a1907c151d3ffdda5f0e7202"
SOURCES = {
    "aws_security_hub",
    "aws_guardduty",
    "gcp_scc",
    "falco",
    "kyverno",
    "bravo_controls",
}


@dataclass(frozen=True, slots=True)
class DetectionRegistration(Document):
    scope: ResourceScope
    source: str
    provider: str
    account_id: str
    region: str
    resource_uid: str
    resource_revision: str
    maximum_age_seconds: int
    observed_at: datetime
    valid_until: datetime
    namespace: str | None = None
    schema_digest: str = SCHEMA_DIGEST

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or self.source not in SOURCES:
            raise ContractError("Typed registered detection scope/source required")
        if (
            self.provider not in {"AWS", "GCP", "onprem"}
            or self.schema_digest not in {SCHEMA_DIGEST, CURRENT_SCHEMA_DIGEST}
        ):
            raise ContractError("Pinned detection provider/schema required")
        expected = {
            "aws_security_hub": "AWS",
            "aws_guardduty": "AWS",
            "gcp_scc": "GCP",
        }.get(self.source)
        if expected is not None and self.provider != expected:
            raise ContractError("Detection source/provider mismatch")
        for value in (
            self.account_id,
            self.region,
            self.resource_uid,
            self.resource_revision,
        ):
            identifier(value)
        # T33 display masking is deliberately lossy. A collision between two
        # masked accounts/resources cannot establish ownership of either one.
        for value in (self.account_id, self.resource_uid, self.namespace):
            if value is not None and ("*" in value or "[REDACTED" in value.upper()):
                raise ContractError("Unmasked detection identity registration required")
        if (
            type(self.maximum_age_seconds) is not int
            or not 1 <= self.maximum_age_seconds <= 900
        ):
            raise ContractError("Detection evidence age must be bounded to 15 minutes")
        if self.namespace is not None:
            identifier(self.namespace)
        window(self)


@dataclass(frozen=True, slots=True)
class DetectionObservation(Document):
    registration: DetectionRegistration
    report_digest: str
    upstream_digest: str
    finding_key: str
    kind: str
    signal: str
    sample: bool
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.registration, DetectionRegistration):
            raise ContractError("Registered detection observation required")
        for value in (self.report_digest, self.upstream_digest, self.finding_key):
            digest(value)
        if self.kind not in {"finding", "source_status"} or self.signal not in {
            "detected-threat",
            "policy-violation",
            "vulnerability-observed",
            "unverified-security",
            "coverage-unavailable",
            "lifecycle-only",
            "coverage-observed",
        }:
            raise ContractError("Known detection kind/signal required")
        if type(self.sample) is not bool:
            raise ContractError("Explicit detection sample provenance required")
        if self.kind == "source_status" and (
            self.sample
            or self.signal not in {"coverage-unavailable", "coverage-observed"}
        ):
            raise ContractError(
                "Source status cannot claim a sample or finding lifecycle"
            )
        if self.kind == "finding" and self.signal in {
            "coverage-unavailable",
            "coverage-observed",
        }:
            raise ContractError("A finding cannot establish source coverage")
        window(self)
        if (
            not self.registration.observed_at
            <= self.observed_at
            < self.valid_until
            <= min(
                self.registration.valid_until,
                self.observed_at
                + timedelta(seconds=self.registration.maximum_age_seconds),
            )
        ):
            raise ContractError("Detection evidence exceeds registered window")

    @property
    def scope(self):
        return self.registration.scope

    @property
    def requires_hold(self):
        return not self.sample and self.signal not in {
            "lifecycle-only",
            "coverage-observed",
        }
