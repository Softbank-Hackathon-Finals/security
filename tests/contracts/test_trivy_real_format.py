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
    assert len(scan.findings) == 3 and scan.coverage == Coverage.PARTIAL
    components = {c.component_id: c for c in inventory.components}
    assert len(components) == 3  # OS distribution metadata is not a package.
    for finding in scan.findings:
        assert finding.installed_version == components[finding.component_id].version
    assert "1:2.41-5" in {c.version for c in components.values()}
