"""Prowler OCSF array projection; no AWS calls or scanner implementation.

Authenticate raw report/registration out of band. This adapter only establishes
selected configuration facts, never real denial, TLS, restore or tenant isolation.
"""

from datetime import UTC, datetime, timedelta
import hashlib

from sova_security.adapters.vulnerability_reports import bounded_report, MAX_BYTES
from sova_security.contracts.commands import ContractError, utc
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.configuration_scan import (
    ConfigurationCheck,
    ConfigurationScanRegistration,
    ConfigurationScanSnapshot,
)

VERIFIER = "sova.prowler.configuration.v1"


def prowler_configuration(raw, *, registration, now):
    now = utc(now)
    if (
        not isinstance(registration, ConfigurationScanRegistration)
        or not registration.observed_at <= now < registration.valid_until
    ):
        raise ContractError("Current registered Prowler scope required")
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES - 32:
        raise ContractError("Bounded OCSF array bytes required")
    # Reuse duplicate-key/depth/node/finite-number checks without changing the
    # existing object-only report parser or silently rewriting the raw artifact.
    envelope = bounded_report(b'{"findings":' + raw + b"}")
    if set(envelope) != {"findings"}:
        raise ContractError("Invalid OCSF array envelope")
    findings = envelope["findings"]
    if type(findings) is not list or len(findings) > 128:
        raise ContractError("Scoped OCSF finding array required")
    checks = {}
    oldest = now
    for finding in findings:
        if (
            type(finding) is not dict
            or finding.get("class_uid") != 2004
            or type(finding.get("class_uid")) is not int
        ):
            raise ContractError("OCSF Detection Finding required")
        metadata = finding.get("metadata")
        cloud = finding.get("cloud")
        resources = finding.get("resources")
        if (
            type(metadata) is not dict
            or type(cloud) is not dict
            or type(resources) is not list
            or len(resources) != 1
            or type(resources[0]) is not dict
        ):
            raise ContractError("Scoped Prowler metadata/cloud/resource required")
        product = metadata.get("product")
        if (
            type(product) is not dict
            or product.get("uid") != "prowler"
            or product.get("version") != registration.scanner_version
        ):
            raise ContractError("Registered Prowler product/version required")
        account = cloud.get("account")
        resource = resources[0]
        if (
            type(account) is not dict
            or cloud.get("provider") != "aws"
            or account.get("uid") != registration.account_id
            or cloud.get("region") != registration.region
            or resource.get("region") != registration.region
            or resource.get("uid") != registration.resource_uid
        ):
            raise ContractError("Prowler account/region/resource mismatch")
        check_id = metadata.get("event_code")
        if (
            type(check_id) is not str
            or check_id not in registration.expected_checks
            or check_id in checks
        ):
            raise ContractError("Unexpected or duplicate Prowler check")
        timestamp = finding.get("time")
        if type(timestamp) is not int:
            raise ContractError("Prowler integer Unix-second timestamp required")
        try:
            observed = datetime.fromtimestamp(timestamp, UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise ContractError("Invalid Prowler timestamp") from exc
        if not (
            registration.observed_at <= observed <= now
            and now - timedelta(minutes=5) < observed
        ):
            raise ContractError("Prowler observation stale/future/outside registration")
        oldest = min(oldest, observed)
        # status_id/status describe lifecycle (e.g. muted), not PASS/FAIL.
        if (
            finding.get("status") != "New"
            or type(finding.get("status_id")) is not int
            or finding["status_id"] != 1
        ):
            result, reason = VerificationResult.UNKNOWN, "suppressed-or-unrecognized"
        elif finding.get("status_code") == "PASS":
            result, reason = VerificationResult.PASS, "configuration-pass"
        elif finding.get("status_code") == "FAIL":
            result, reason = VerificationResult.FAIL, "configuration-fail"
        else:
            result, reason = VerificationResult.UNKNOWN, "manual-or-error"
        checks[check_id] = ConfigurationCheck(check_id, result, reason)
    return ConfigurationScanSnapshot(
        registration,
        hashlib.sha256(raw).hexdigest(),
        tuple(
            checks.get(c, ConfigurationCheck(c, VerificationResult.UNKNOWN, "missing"))
            for c in registration.expected_checks
        ),
        oldest,
        min(registration.valid_until, oldest + timedelta(minutes=5)),
    )


def configuration_evidence(snapshot, *, check_id, evidence_id):
    """Unsigned configuration-only record for an independent signer."""
    if not isinstance(snapshot, ConfigurationScanSnapshot):
        raise ContractError("Typed configuration scan snapshot required")
    check = next((c for c in snapshot.checks if c.check_id == check_id), None)
    if check is None:
        raise ContractError("Registered configuration check required")
    return EvidenceRecord(
        evidence_id,
        "prowler-configuration:" + check_id,
        snapshot.registration.scope,
        snapshot.registration.revisions,
        VERIFIER,
        snapshot.observed_at,
        snapshot.valid_until,
        check.result,
        "prowler-configuration:" + snapshot.fingerprint,
        snapshot.fingerprint,
    )
