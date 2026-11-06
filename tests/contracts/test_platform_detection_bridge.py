"""Actual T33 normalizer; synthetic inputs, no AWS/GCP/cluster connection."""

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from sova_security.adapters.team_detection import import_detection, CURRENT_SOURCE_COMMIT
from sova_security.contracts.commands import ContractError
from sova_security.domain.detection import CURRENT_SCHEMA_DIGEST, DetectionRegistration


@pytest.fixture
def producer():
    location = os.environ.get("SOVA_PLATFORM_SOURCE")
    if not location:
        pytest.skip("Explicit platform checkout required; this is not live collection")
    root = Path(location).resolve()
    git = ["git", "-c", "safe.directory=" + root.as_posix(), "-C", str(root)]
    head = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    if head != CURRENT_SOURCE_COMMIT:
        pytest.skip("T33 bridge requires its explicit current source qualification")
    assert not subprocess.check_output(git + ["status", "--porcelain"])
    directory = root / "docs/security/detection"
    assert hashlib.sha256((directory / "finding.schema.json").read_bytes()).hexdigest() == CURRENT_SCHEMA_DIGEST
    original = list(sys.path)
    sys.path.insert(0, str(root / "services/security-findings/src"))
    try:
        from bravo_findings.normalize import Normalizer
        from bravo_findings.rules import Rules
        yield Normalizer(Rules(directory)), directory
    finally:
        sys.path[:] = original


@pytest.mark.parametrize("source,example", [
    ("falco", "onprem-falco-shell"), ("kyverno", "onprem-kyverno-fail"),
])
def test_real_onprem_normalizer_preserves_exact_registered_mapping(producer, scope, now, source, example):
    normalizer, directory = producer
    raw = json.loads((directory / "examples" / (example + ".raw.json")).read_text(encoding="utf-8"))
    if source == "falco":
        raw["time"] = now.isoformat()
    else:
        raw["timestamp"] = now.isoformat()
    data = normalizer.normalize(source, raw, environment_id=scope.environment_id,
        collected_time=int(now.timestamp() * 1000))
    resource = data["resources"][0]
    r = DetectionRegistration(scope, source, "onprem", "onprem", "local", resource["uid"],
        "registered-revision", 300, now - timedelta(seconds=1), now + timedelta(minutes=5),
        namespace=resource.get("namespace"), schema_digest=CURRENT_SCHEMA_DIGEST)
    result = import_detection(json.dumps(data).encode(), registration=r,
        collected_resource_uid=r.resource_uid, collected_resource_revision=r.resource_revision, now=now)
    assert result.requires_hold and result.registration.schema_digest == CURRENT_SCHEMA_DIGEST
    with pytest.raises(ContractError):
        import_detection(json.dumps(data).encode(), registration=replace(r, namespace="other-namespace"),
            collected_resource_uid=r.resource_uid, collected_resource_revision=r.resource_revision, now=now)


def test_actual_aws_masking_cannot_be_silently_used_as_account_ownership(producer, scope, now):
    normalizer, directory = producer
    raw = json.loads((directory / "examples/aws-guardduty-via-security-hub.raw.json").read_text(encoding="utf-8"))
    raw["AwsAccountId"] = "123456789012"
    raw["UpdatedAt"] = now.isoformat()
    raw["Resources"] = [{"Type": "AwsS3Bucket", "Id": "owned-bucket"}]
    data = normalizer.normalize("aws_security_hub", raw, environment_id=scope.environment_id,
        collected_time=int(now.timestamp() * 1000))
    assert data["cloud"]["account"]["uid"] != raw["AwsAccountId"]
    r = DetectionRegistration(scope, "aws_security_hub", "AWS", raw["AwsAccountId"], data["cloud"]["region"],
        "owned-bucket", "r1", 300, now - timedelta(seconds=1), now + timedelta(minutes=5),
        schema_digest=CURRENT_SCHEMA_DIGEST)
    with pytest.raises(ContractError):
        import_detection(json.dumps(data).encode(), registration=r,
            collected_resource_uid=r.resource_uid, collected_resource_revision=r.resource_revision, now=now)
