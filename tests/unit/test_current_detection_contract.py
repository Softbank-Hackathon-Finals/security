"""Explicit contract selection; display masking never proves resource ownership."""

from dataclasses import replace
from datetime import timedelta
import hashlib
from importlib.resources import files
import json

import pytest

from sova_security.adapters.team_detection import SCHEMA_FILES, import_detection
from sova_security.contracts.commands import ContractError
from sova_security.domain.detection import (
    CURRENT_SCHEMA_DIGEST, SCHEMA_DIGEST, DetectionRegistration,
)


def registration(scope, now, **changes):
    return replace(DetectionRegistration(
        scope, "falco", "onprem", "onprem", "local", "pod-uid-one", "revision-one",
        300, now - timedelta(seconds=1), now + timedelta(minutes=5),
        namespace="test-namespace", schema_digest=CURRENT_SCHEMA_DIGEST,
    ), **changes)


def finding(r, now):
    return {
        "class_uid": 2004, "category_uid": 2, "activity_id": 1, "type_uid": 200401,
        "severity_id": 4, "status_id": 1, "time": int(now.timestamp() * 1000),
        "finding_info": {"uid": "sha256:" + "a" * 64, "title": "synthetic test"},
        "metadata": {"version": "1.1.0", "product": {"name": "Falco"}},
        "cloud": {"provider": "onprem"},
        "resources": [{"type": "Pod", "uid": r.resource_uid, "namespace": r.namespace}],
        "bravo": {
            "source": r.source, "environment_id": r.scope.environment_id,
            "category": "THREAT", "control_ids": [], "normalizer_version": "2",
            "collected_time": int(now.timestamp() * 1000), "raw_sha256": "sha256:" + "b" * 64,
        },
    }


def parse(doc, r, now):
    return import_detection(json.dumps(doc).encode(), registration=r,
        collected_resource_uid=r.resource_uid, collected_resource_revision=r.resource_revision, now=now)


@pytest.mark.parametrize("digest,name", SCHEMA_FILES.items())
def test_pinned_schema_bytes_match_registration_contract(digest, name):
    assert hashlib.sha256(files("sova_security").joinpath("schemas/" + name).read_bytes()).hexdigest() == digest


def test_current_contract_roundtrip_requires_explicit_registration(scope, now):
    from sova_security.adapters.modernization_codec import encode, decode
    r = registration(scope, now)
    doc = finding(r, now)
    observation = parse(doc, r, now)
    assert observation.requires_hold and not observation.sample
    assert decode(encode(observation).encode()) == observation
    with pytest.raises(ContractError):
        parse(doc, replace(r, schema_digest=SCHEMA_DIGEST), now)


@pytest.mark.parametrize("version", [None, "1", 2, True, "3"])
def test_current_finding_never_silently_downgrades_normalizer(scope, now, version):
    r = registration(scope, now)
    doc = finding(r, now)
    if version is None:
        del doc["bravo"]["normalizer_version"]
    else:
        doc["bravo"]["normalizer_version"] = version
    with pytest.raises(ContractError):
        parse(doc, r, now)


def test_ingestion_gap_with_recent_success_is_still_unavailable(scope, now):
    r = registration(scope, now)
    doc = {"kind": "source_status", "source": r.source, "environment_id": scope.environment_id,
        "state": "FAILED", "checked_time": int(now.timestamp() * 1000),
        "last_success_time": int(now.timestamp() * 1000), "error_code": "INGESTION_GAP"}
    result = parse(doc, r, now)
    assert result.signal == "coverage-unavailable" and result.requires_hold
    with pytest.raises(ContractError):
        parse(doc, replace(r, schema_digest=SCHEMA_DIGEST), now)


@pytest.mark.parametrize("field,value", [
    ("account_id", "****9012"), ("resource_uid", "arn:aws:s3:****9012:bucket"),
    ("resource_uid", "[REDACTED]"), ("namespace", "team-****9012"),
])
def test_lossy_display_identity_cannot_be_registered_as_exact_owner(scope, now, field, value):
    with pytest.raises(ContractError):
        registration(scope, now, **{field: value})


def test_stale_and_collector_revision_changes_remain_rejected(scope, now):
    r = registration(scope, now)
    doc = finding(r, now)
    doc["time"] -= 300_000
    with pytest.raises(ContractError):
        parse(doc, r, now)
    with pytest.raises(ContractError):
        import_detection(json.dumps(finding(r, now)).encode(), registration=r,
            collected_resource_uid=r.resource_uid, collected_resource_revision="different", now=now)
