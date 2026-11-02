"""Scoped configuration facts, deliberately distinct from runtime protection."""

from dataclasses import dataclass
from datetime import datetime
import re

from sova_security.contracts.commands import ContractError, ResourceScope, digest
from sova_security.contracts.evidence import RevisionSet, VerificationResult
from sova_security.domain.assessment import Document, bounded_tuple, window


@dataclass(frozen=True, slots=True)
class ConfigurationScanRegistration(Document):
    scope: ResourceScope
    revisions: RevisionSet
    account_id: str
    region: str
    resource_uid: str
    scanner_version: str
    expected_checks: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed configuration scan scope/revisions required")
        if type(self.account_id) is not str or not re.fullmatch(
            r"[0-9]{12}", self.account_id
        ):
            raise ContractError("Registered AWS account required")
        if type(self.region) is not str or not re.fullmatch(
            r"[a-z]{2}-[a-z]+-[0-9]+", self.region
        ):
            raise ContractError("Registered commercial AWS region required")
        if type(self.resource_uid) is not str or not re.fullmatch(
            r"arn:aws:[a-z0-9-]+:"
            + re.escape(self.region)
            + ":"
            + self.account_id
            + r":[A-Za-z0-9:/_.+=,@-]{1,400}",
            self.resource_uid,
        ):
            raise ContractError("Region/account-bound AWS resource ARN required")
        if self.scanner_version != "5.47.0":
            raise ContractError(
                "Only qualified Prowler 5.47.0 output profile supported"
            )
        bounded_tuple(self.expected_checks, str, limit=128, nonempty=True)
        if len(set(self.expected_checks)) != len(self.expected_checks) or any(
            re.fullmatch(r"[a-z][a-z0-9_]{0,127}", check) is None
            for check in self.expected_checks
        ):
            raise ContractError("Unique registered configuration checks required")
        window(self)


@dataclass(frozen=True, slots=True)
class ConfigurationCheck(Document):
    check_id: str
    result: VerificationResult
    reason: str

    def __post_init__(self):
        if (
            type(self.check_id) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", self.check_id) is None
        ):
            raise ContractError("Configuration check ID required")
        if self.result not in (
            VerificationResult.PASS,
            VerificationResult.FAIL,
            VerificationResult.UNKNOWN,
        ) or not isinstance(self.result, VerificationResult):
            raise ContractError("Explicit configuration result required")
        if self.reason not in {
            "configuration-pass",
            "configuration-fail",
            "missing",
            "suppressed-or-unrecognized",
            "manual-or-error",
        }:
            raise ContractError("Known configuration reason required")
        expected = {
            "configuration-pass": VerificationResult.PASS,
            "configuration-fail": VerificationResult.FAIL,
        }.get(self.reason, VerificationResult.UNKNOWN)
        if self.result != expected:
            raise ContractError("Configuration reason/result mismatch")


@dataclass(frozen=True, slots=True)
class ConfigurationScanSnapshot(Document):
    registration: ConfigurationScanRegistration
    report_digest: str
    checks: tuple[ConfigurationCheck, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.registration, ConfigurationScanRegistration):
            raise ContractError("Registered configuration scan required")
        digest(self.report_digest)
        bounded_tuple(self.checks, ConfigurationCheck, limit=128, nonempty=True)
        if tuple(c.check_id for c in self.checks) != self.registration.expected_checks:
            raise ContractError("Exact ordered configuration check coverage required")
        window(self)
        if (
            not self.registration.observed_at
            <= self.observed_at
            < self.valid_until
            <= self.registration.valid_until
        ):
            raise ContractError("Configuration facts exceed registration window")

    @property
    def scope(self):
        return self.registration.scope

    @property
    def all_selected_checks_pass(self):
        # Selected configuration checks only, never runtime or whole-account safety.
        return all(c.result == VerificationResult.PASS for c in self.checks)
