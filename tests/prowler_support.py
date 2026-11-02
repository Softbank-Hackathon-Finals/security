"""Synthetic subset of the official Prowler 5.47.0 OCSF output shape."""

from datetime import timedelta
from sova_security.contracts.evidence import RevisionSet
from sova_security.domain.configuration_scan import ConfigurationScanRegistration


def configuration_registration(scope, now):
    return ConfigurationScanRegistration(
        scope,
        RevisionSet(*[c * 64 for c in "abcd"]),
        "123456789012",
        "ap-northeast-2",
        "arn:aws:rds:ap-northeast-2:123456789012:db:registered-app",
        "5.47.0",
        ("rds_instance_storage_encrypted", "rds_instance_no_public_access"),
        now - timedelta(minutes=2),
        now + timedelta(minutes=10),
    )


def event(registration, now, *, check=None, status="PASS"):
    return {
        "class_uid": 2004,
        "metadata": {
            "event_code": check or registration.expected_checks[0],
            "product": {"uid": "prowler", "version": "5.47.0"},
        },
        "cloud": {
            "provider": "aws",
            "account": {"uid": registration.account_id},
            "region": registration.region,
        },
        "resources": [
            {"uid": registration.resource_uid, "region": registration.region}
        ],
        "time": int(now.timestamp()),
        "status_id": 1,
        "status": "New",
        "status_code": status,
    }
