"""Deterministic risk assessment of bounded, revision-bound scanner evidence.

Objects validate structure, not issuer authority. Callers must authenticate every
input and its collection coverage. A PASS is never an execution authorization.
"""

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import StrEnum, Enum
import hashlib

from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)


def _plain(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    return value


class Document:
    @property
    def document(self):
        return {"schema_version": 1, **_plain(self)}

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=1048576).encode()
        ).hexdigest()


def bounded_tuple(values, kind, *, limit=4096, nonempty=False):
    if type(values) is not tuple or len(values) > limit or (nonempty and not values):
        raise ContractError("Bounded immutable collection required")
    if any(not isinstance(v, kind) for v in values):
        raise ContractError("Typed collection members required")


def window(subject):
    object.__setattr__(subject, "observed_at", utc(subject.observed_at))
    object.__setattr__(subject, "valid_until", utc(subject.valid_until))
    if subject.observed_at >= subject.valid_until:
        raise ContractError("Positive evidence validity window required")


def current(subject, now):
    return subject.observed_at <= utc(now) < subject.valid_until


class Coverage(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class Reachability(StrEnum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


class Compromise(StrEnum):
    NO_OBSERVED_INDICATORS = "no_observed_indicators"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Priority(StrEnum):
    EMERGENCY = "emergency"
    URGENT = "urgent"
    PLANNED = "planned"
    REVIEW = "review"


@dataclass(frozen=True, slots=True)
class Component(Document):
    component_id: str
    name: str
    version: str
    ecosystem: str
    purl: str | None = None

    def __post_init__(self):
        for name in ("component_id", "name", "version", "ecosystem"):
            identifier(getattr(self, name), name, limit=512)
        if self.purl is not None:
            identifier(self.purl, "purl", limit=2048)
            if not self.purl.startswith("pkg:"):
                raise ContractError("A package URL is required")


@dataclass(frozen=True, slots=True)
class AssetInventory(Document):
    scope: ResourceScope
    resource_revision: str
    source_digest: str
    image_digest: str
    configuration_digest: str
    sbom_digest: str
    collector_id: str
    coverage: Coverage
    components: tuple[Component, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.coverage, Coverage
        ):
            raise ContractError("Typed inventory scope and coverage required")
        identifier(self.resource_revision)
        identifier(self.collector_id)
        for name in (
            "source_digest",
            "image_digest",
            "configuration_digest",
            "sbom_digest",
        ):
            digest(getattr(self, name))
        bounded_tuple(self.components, Component)
        if len({c.component_id for c in self.components}) != len(self.components):
            raise ContractError("Unique component IDs required")
        object.__setattr__(
            self,
            "components",
            tuple(sorted(self.components, key=lambda c: c.component_id)),
        )
        window(self)


@dataclass(frozen=True, slots=True)
class Vulnerability(Document):
    advisory_id: str
    component_id: str
    installed_version: str
    severity: Severity
    fixed_version: str | None

    def __post_init__(self):
        for name in ("advisory_id", "component_id", "installed_version"):
            identifier(getattr(self, name), name, limit=512)
        if not isinstance(self.severity, Severity):
            raise ContractError("Typed advisory severity required")
        if self.fixed_version is not None:
            identifier(self.fixed_version, "fixed_version", limit=512)


@dataclass(frozen=True, slots=True)
class ScannerProfile(Document):
    """Operator-registered invocation metadata, authenticated outside this model."""

    scanner_id: str
    scanner_version: str
    database_digest: str
    include_all_packages: bool
    ignore_unfixed: bool
    suppressions_enabled: bool
    severities: tuple[Severity, ...]

    def __post_init__(self):
        identifier(self.scanner_id)
        identifier(self.scanner_version)
        digest(self.database_digest)
        if any(
            type(getattr(self, f)) is not bool
            for f in ("include_all_packages", "ignore_unfixed", "suppressions_enabled")
        ):
            raise ContractError("Explicit scanner invocation flags required")
        bounded_tuple(self.severities, Severity, limit=5, nonempty=True)
        if len(set(self.severities)) != len(self.severities):
            raise ContractError("Duplicate scanner severity filter")
        object.__setattr__(self, "severities", tuple(sorted(self.severities)))

    @property
    def unfiltered(self):
        return (
            self.include_all_packages
            and not self.ignore_unfixed
            and not self.suppressions_enabled
            and set(self.severities) == set(Severity)
        )


@dataclass(frozen=True, slots=True)
class VulnerabilityScan(Document):
    scope: ResourceScope
    inventory_digest: str
    image_digest: str
    report_digest: str
    scanner_id: str
    scanner_version: str
    database_digest: str
    profile_digest: str
    coverage: Coverage
    findings: tuple[Vulnerability, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.coverage, Coverage
        ):
            raise ContractError("Typed scan scope and coverage required")
        for name in (
            "inventory_digest",
            "image_digest",
            "report_digest",
            "database_digest",
            "profile_digest",
        ):
            digest(getattr(self, name))
        identifier(self.scanner_id)
        identifier(self.scanner_version)
        bounded_tuple(self.findings, Vulnerability, limit=2048)
        keys = [(f.component_id, f.advisory_id) for f in self.findings]
        if len(set(keys)) != len(keys):
            raise ContractError("Duplicate advisory/component pair")
        object.__setattr__(
            self,
            "findings",
            tuple(sorted(self.findings, key=lambda f: (f.component_id, f.advisory_id))),
        )
        window(self)


@dataclass(frozen=True, slots=True)
class ExposureObservation(Document):
    scope: ResourceScope
    resource_revision: str
    inventory_digest: str
    evidence_digest: str
    verifier_id: str
    reachability: Reachability
    compromise: Compromise
    business_critical: bool
    known_exploited: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if (
            not isinstance(self.scope, ResourceScope)
            or not isinstance(self.reachability, Reachability)
            or not isinstance(self.compromise, Compromise)
        ):
            raise ContractError("Typed exposure observations required")
        if type(self.business_critical) is not bool:
            raise ContractError("Explicit criticality required")
        identifier(self.resource_revision)
        identifier(self.verifier_id)
        digest(self.inventory_digest)
        digest(self.evidence_digest)
        bounded_tuple(self.known_exploited, str, limit=2048)
        for value in self.known_exploited:
            identifier(value, limit=512)
        if len(set(self.known_exploited)) != len(self.known_exploited):
            raise ContractError("Duplicate exploitation reference")
        object.__setattr__(self, "known_exploited", tuple(sorted(self.known_exploited)))
        window(self)


@dataclass(frozen=True, slots=True)
class RiskPolicy(Document):
    scope: ResourceScope
    policy_id: str
    revision: int
    issued_at: datetime
    valid_until: datetime
    accepted_scanner_profiles: tuple[str, ...]

    def __post_init__(self):
        bounded_tuple(self.accepted_scanner_profiles, str, limit=32, nonempty=True)
        for profile in self.accepted_scanner_profiles:
            digest(profile)
        if len(set(self.accepted_scanner_profiles)) != len(
            self.accepted_scanner_profiles
        ):
            raise ContractError("Unique scanner profile bindings required")
        object.__setattr__(
            self,
            "accepted_scanner_profiles",
            tuple(sorted(self.accepted_scanner_profiles)),
        )
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed policy scope required")
        identifier(self.policy_id)
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive policy revision required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.issued_at >= self.valid_until:
            raise ContractError("Positive policy window required")


@dataclass(frozen=True, slots=True)
class RiskDecision(Document):
    advisory_id: str
    component_id: str
    priority: Priority
    reasons: tuple[str, ...]
    response: str

    def __post_init__(self):
        identifier(self.advisory_id, limit=512)
        identifier(self.component_id, limit=512)
        if not isinstance(self.priority, Priority) or self.response not in {
            "contain-investigate",
            "preserve-rebuild-rotate",
            "propose-patch",
            "review-mitigation",
        }:
            raise ContractError("Typed risk priority and known response required")
        bounded_tuple(self.reasons, str, limit=32, nonempty=True)
        for reason in self.reasons:
            identifier(reason, limit=512)


@dataclass(frozen=True, slots=True)
class Assessment(Document):
    scope: ResourceScope
    inventory_digest: str
    scan_digest: str
    exposure_digest: str
    policy_digest: str
    decisions: tuple[RiskDecision, ...]
    complete: bool
    reasons: tuple[str, ...]
    assessed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or type(self.complete) is not bool:
            raise ContractError("Typed assessment scope/completeness required")
        for name in (
            "inventory_digest",
            "scan_digest",
            "exposure_digest",
            "policy_digest",
        ):
            digest(getattr(self, name))
        bounded_tuple(self.decisions, RiskDecision, limit=2048)
        bounded_tuple(self.reasons, str, limit=32)
        for value in self.reasons:
            identifier(value)
        if self.complete != (not self.reasons):
            raise ContractError(
                "Assessment completeness conflicts with unresolved reasons"
            )
        object.__setattr__(self, "assessed_at", utc(self.assessed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.assessed_at >= self.valid_until:
            raise ContractError("Assessment has no remaining validity")


def assess_risk(inventory, scan, exposure, policy, *, now):
    """Compare authenticated, current inputs. Never turns a finding into authority."""
    if (
        not isinstance(inventory, AssetInventory)
        or not isinstance(scan, VulnerabilityScan)
        or not isinstance(exposure, ExposureObservation)
        or not isinstance(policy, RiskPolicy)
    ):
        raise ContractError("Typed assessment inputs required")
    now = utc(now)
    if not policy.issued_at <= now < policy.valid_until or any(
        not current(x, now) for x in (inventory, scan, exposure)
    ):
        raise ContractError("Assessment input expired or from future")
    if (
        not (inventory.scope == scan.scope == exposure.scope == policy.scope)
        or scan.inventory_digest != inventory.fingerprint
        or exposure.inventory_digest != inventory.fingerprint
        or scan.image_digest != inventory.image_digest
        or exposure.resource_revision != inventory.resource_revision
    ):
        raise ContractError("Assessment scope or revision binding mismatch")
    if scan.profile_digest not in policy.accepted_scanner_profiles:
        raise ContractError("Scanner invocation profile is not approved")
    components = {c.component_id: c for c in inventory.components}
    reasons = []
    if inventory.coverage != Coverage.COMPLETE or scan.coverage != Coverage.COMPLETE:
        reasons.append("incomplete-coverage")
    if exposure.reachability == Reachability.UNKNOWN:
        reasons.append("unknown-reachability")
    if exposure.compromise == Compromise.UNKNOWN:
        reasons.append("unknown-compromise-state")
    decisions = []
    for finding in scan.findings:
        component = components.get(finding.component_id)
        if component is None or component.version != finding.installed_version:
            raise ContractError("Finding does not match installed component")
        why = ["installed-version-matched", "severity:" + str(finding.severity)]
        if exposure.compromise in {Compromise.SUSPECTED, Compromise.CONFIRMED}:
            why.append("compromise:" + str(exposure.compromise))
            response = (
                "contain-investigate"
                if exposure.compromise == Compromise.SUSPECTED
                else "preserve-rebuild-rotate"
            )
            priority = Priority.EMERGENCY
        else:
            response = "propose-patch" if finding.fixed_version else "review-mitigation"
            known = finding.advisory_id in exposure.known_exploited
            if known:
                why.append("known-exploited")
            if exposure.reachability == Reachability.REACHABLE:
                why.append("reachable")
            if exposure.business_critical:
                why.append("business-critical")
            if known:
                priority = Priority.URGENT
            elif finding.severity == Severity.UNKNOWN or reasons:
                priority = Priority.REVIEW
            elif finding.severity in {Severity.CRITICAL, Severity.HIGH} and (
                exposure.reachability == Reachability.REACHABLE
                or exposure.business_critical
            ):
                priority = Priority.URGENT
            else:
                priority = Priority.PLANNED
        decisions.append(
            RiskDecision(
                finding.advisory_id,
                finding.component_id,
                priority,
                tuple(why),
                response,
            )
        )
    # Compromise is actionable even when no CVE was reported; no fictional advisory is created.
    if exposure.compromise in {Compromise.SUSPECTED, Compromise.CONFIRMED}:
        reasons.append("incident-response-required")
    if any(f.severity == Severity.UNKNOWN for f in scan.findings):
        reasons.append("unknown-advisory-severity")
    return Assessment(
        inventory.scope,
        inventory.fingerprint,
        scan.fingerprint,
        exposure.fingerprint,
        policy.fingerprint,
        tuple(decisions),
        not reasons,
        tuple(reasons),
        now,
        min(
            inventory.valid_until,
            scan.valid_until,
            exposure.valid_until,
            policy.valid_until,
        ),
    )
