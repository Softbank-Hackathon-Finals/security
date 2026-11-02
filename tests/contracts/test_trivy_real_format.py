"""A small sanitized shape projection from a real official scanner run."""

from pathlib import Path
from datetime import timedelta
import json

from sova_security.adapters.vulnerability_reports import cyclone_inventory, trivy_scan
from sova_security.domain.assessment import Coverage, ScannerProfile, Severity


def test_official_trivy_0761_cyclonedx_and_python_purl_shape(scope, now):
    data = json.loads(
        (
            Path(__file__).parents[1] / "fixtures/trivy-0.76.1-projection.json"
        ).read_text()
    )
    inventory = cyclone_inventory(
        json.dumps(data["sbom"]).encode(),
        scope=scope,
        resource_revision="format-qualification",
        source_digest="a" * 64,
        image_digest="b" * 64,
        configuration_digest="c" * 64,
        collector_id="qualified-scanner-projection",
        coverage=Coverage.PARTIAL,
        observed_at=now,
        valid_until=now + timedelta(minutes=1),
    )
    profile = ScannerProfile(
        "trivy", "0.76.1", "d" * 64, True, False, False, tuple(Severity)
    )
    scan = trivy_scan(
        json.dumps(data["report"]).encode(),
        inventory=inventory,
        profile=profile,
        coverage=Coverage.PARTIAL,
        observed_at=now,
        valid_until=now + timedelta(minutes=1),
    )
    assert len(scan.findings) == 1 and scan.coverage == Coverage.PARTIAL
    assert scan.findings[0].component_id == inventory.components[0].component_id
    assert scan.findings[0].installed_version == inventory.components[0].version
