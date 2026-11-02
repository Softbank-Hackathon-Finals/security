"""Synthetic scanner inputs for controlled tests, not claims about real CVEs."""

from datetime import timedelta
import json

from sova_security.adapters.vulnerability_reports import cyclone_inventory, trivy_scan
from sova_security.domain.assessment import (
    ExposureObservation,
    Reachability,
    Compromise,
    Coverage,
    RiskPolicy,
    ScannerProfile,
    Severity,
)


def scanner_profile():
    return ScannerProfile(
        "registered-trivy",
        "qualified-schema2",
        "d" * 64,
        True,
        False,
        False,
        tuple(Severity),
    )


def modern_bundle(scope, now):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "bom-ref": "driver",
                "name": "sample-driver",
                "version": "1.0",
                "purl": "pkg:pypi/sample-driver@1.0",
            }
        ],
    }
    inventory = cyclone_inventory(
        json.dumps(sbom).encode(),
        scope=scope,
        resource_revision="resource-v1",
        source_digest="a" * 64,
        image_digest="b" * 64,
        configuration_digest="c" * 64,
        collector_id="registered-inventory",
        coverage=Coverage.COMPLETE,
        observed_at=now,
        valid_until=now + timedelta(minutes=10),
    )
    report = {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"RepoDigests": ["registry.example/owned@sha256:" + "b" * 64]},
        "Results": [
            {
                "Target": "requirements.lock",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Packages": [{"Name": "sample-driver", "Version": "1.0"}],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "SOVA-TEST-001",
                        "PkgName": "sample-driver",
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                        "FixedVersion": "1.1",
                    }
                ],
            }
        ],
    }
    scan = trivy_scan(
        json.dumps(report).encode(),
        inventory=inventory,
        profile=scanner_profile(),
        coverage=Coverage.COMPLETE,
        observed_at=now,
        valid_until=now + timedelta(minutes=5),
    )
    exposure = ExposureObservation(
        scope,
        inventory.resource_revision,
        inventory.fingerprint,
        "e" * 64,
        "registered-network-probe",
        Reachability.REACHABLE,
        Compromise.NO_OBSERVED_INDICATORS,
        True,
        (),
        now,
        now + timedelta(minutes=3),
    )
    policy = RiskPolicy(
        scope,
        "risk-v1",
        1,
        now - timedelta(seconds=1),
        now + timedelta(minutes=8),
        (scanner_profile().fingerprint,),
    )
    return inventory, scan, exposure, policy, sbom, report
