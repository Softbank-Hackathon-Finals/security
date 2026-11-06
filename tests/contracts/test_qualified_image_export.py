from datetime import timedelta
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("qualified_export", Path(__file__).resolve().parents[2] / "scripts/export_qualified_image.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


@pytest.mark.parametrize("fault", [None, "block", "unknown", "high", "source", "architecture", "image", "label", "stale", "future"])
def test_only_the_exact_recent_scanned_image_is_exportable(now, fault):
    manifest = dict(commit_sha="a" * 40, platform="linux/arm64")
    decision = dict(source_commit="a" * 40, platform="linux/arm64", local_image_config_id="sha256:" + "b" * 64,
        gate="PASS", policy="service-image-high-critical.v4", observed_at=now.isoformat(),
        severity_counts=dict(HIGH=0, CRITICAL=0, UNKNOWN=0))
    inspected = [dict(Id=decision["local_image_config_id"], Os="linux", Architecture="arm64",
        Config=dict(Labels={"org.opencontainers.image.revision": manifest["commit_sha"]}))]
    if fault in {"block", "unknown"}:
        decision["gate"] = fault.upper()
    elif fault == "high":
        decision["severity_counts"]["HIGH"] = 1
    elif fault == "source":
        decision["source_commit"] = "c" * 40
    elif fault == "architecture":
        inspected[0]["Architecture"] = "amd64"
    elif fault == "image":
        inspected[0]["Id"] = "sha256:" + "c" * 64
    elif fault == "label":
        inspected[0]["Config"]["Labels"]["org.opencontainers.image.revision"] = "c" * 40
    elif fault in {"stale", "future"}:
        decision["observed_at"] = (now + timedelta(minutes=31 if fault == "future" else -31)).isoformat()
    if fault is None:
        result = exporter.qualification(manifest, decision, inspected, now)
        assert result["registry_digest"] is None
        assert result["release_authorized"] is result["signed_attestation"] is False
    else:
        with pytest.raises(ValueError):
            exporter.qualification(manifest, decision, inspected, now)
