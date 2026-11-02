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


def rehearsal_bundle(scope, now):
    from sova_security.contracts.evidence import VerificationResult as R
    from sova_security.domain.assessment import assess_risk
    from sova_security.domain.remediation import (
        Applicability,
        ChangeKind,
        FileChange,
        RemediationProposal,
        SandboxProfile,
        RehearsalTarget,
        TargetRole,
        VerificationRequirement,
        RehearsalRequest,
        TestedArtifact,
        TestProof,
        RehearsalReceipt,
        fix_test_id,
    )

    inputs = modern_bundle(scope, now)[:4]
    inventory, _, _, _ = inputs
    assessment = assess_risk(*inputs, now=now)
    until = now + timedelta(minutes=2)
    changes = (FileChange("src/app.py", "1" * 64, "2" * 64),)
    proposal = RemediationProposal(
        scope,
        assessment.fingerprint,
        inventory.fingerprint,
        assessment.policy_digest,
        inventory.source_digest,
        inventory.image_digest,
        inventory.configuration_digest,
        "3" * 64,
        ChangeKind.PATCH,
        Applicability.SOURCE_ONLY,
        (assessment.decisions[0].fingerprint,),
        changes,
        "operator",
        now,
        until,
    )
    profile = SandboxProfile(
        "registered-harbor-profile",
        "4" * 64,
        "5" * 64,
        "6" * 64,
        "7" * 64,
        120,
        512,
        ("src/app.py",),
    )
    target = RehearsalTarget(
        scope, TargetRole.SOURCE, inventory.fingerprint, inventory.image_digest
    )
    requirements = tuple(
        VerificationRequirement(scope, name, baseline)
        for name, baseline in (
            (fix_test_id(proposal.findings[0]), R.FAIL),
            ("functional", R.PASS),
            ("compatibility", None),
        )
    )
    request = RehearsalRequest(
        "rehearsal-1",
        proposal,
        profile,
        (target,),
        requirements,
        "independent-verifier",
        now,
        until,
    )
    proofs = []
    for test in requirements:
        if test.baseline_expected is not None:
            proofs.append(
                TestProof(
                    scope,
                    test.test_id,
                    "before",
                    test.baseline_expected,
                    inventory.image_digest,
                    "9" * 64,
                    now + timedelta(seconds=1),
                    until,
                )
            )
        proofs.append(
            TestProof(
                scope,
                test.test_id,
                "after",
                R.PASS,
                "8" * 64,
                "9" * 64,
                now + timedelta(seconds=2),
                until,
            )
        )
    receipt = RehearsalReceipt(
        request.fingerprint,
        proposal.fingerprint,
        request.verifier_issuer,
        profile.runner_image_digest,
        profile.verifier_image_digest,
        profile.test_bundle_digest,
        profile.egress_policy_digest,
        True,
        2,
        128,
        R.PASS,
        R.PASS,
        changes,
        (TestedArtifact(scope, "8" * 64, "f" * 64, "c" * 64, "1" * 64),),
        tuple(proofs),
        now + timedelta(seconds=3),
        until,
    )
    return inputs, assessment, request, receipt
