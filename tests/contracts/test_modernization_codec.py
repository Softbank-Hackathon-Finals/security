from datetime import timedelta
import json

import pytest
from modernization_support import rehearsal_bundle, scanner_profile
from sova_security.adapters.modernization_codec import encode, decode
from sova_security.contracts.commands import ContractError
from sova_security.domain.remediation import evaluate_rehearsal


def test_roundtrip_preserves_every_scope_revision_and_artifact_binding(scope, now):
    inputs, assessment, request, receipt = rehearsal_bundle(scope, now)
    objects = (
        scanner_profile(),
        *inputs,
        assessment,
        request.proposal,
        request.profile,
        request,
        receipt,
        evaluate_rehearsal(request, receipt, now=now + timedelta(seconds=4)),
    )
    for original in objects:
        restored = decode(encode(original).encode())
        assert type(restored) is type(original)
        assert restored == original and restored.fingerprint == original.fingerprint


@pytest.mark.parametrize(
    "case",
    [
        "envelope-extra",
        "value-extra",
        "unknown-kind",
        "dynamic-import",
        "boolean-version",
        "wrong-scalar",
        "nested-extra",
        "wrong-enum",
        "naive-time",
    ],
)
def test_schema_confusion_never_loads_unregistered_types(scope, now, case):
    _, _, request, _ = rehearsal_bundle(scope, now)
    assert decode(encode(request).encode()) == request  # Warm metadata must not weaken later validation.
    data = json.loads(encode(request))
    if case == "envelope-extra":
        data["execute"] = "arbitrary"
    if case == "value-extra":
        data["value"]["command"] = "arbitrary"
    if case == "unknown-kind":
        data["kind"] = "new.v2"
    if case == "dynamic-import":
        data["kind"] = "os.system"
    if case == "boolean-version":
        data["schema_version"] = True
    if case == "wrong-scalar":
        data["value"]["profile"]["max_seconds"] = True
    if case == "nested-extra":
        data["value"]["proposal"]["scope"]["account"] = "foreign"
    if case == "wrong-enum":
        data["value"]["proposal"]["kind"] = "execute-shell"
    if case == "naive-time":
        data["value"]["created_at"] = "2026-10-31T07:00:00"
    with pytest.raises(ContractError):
        decode(json.dumps(data).encode())


def test_collection_mutability_and_duplicate_fields_are_not_silently_coerced(
    scope, now
):
    _, _, request, _ = rehearsal_bundle(scope, now)
    data = json.loads(encode(request))
    data["value"]["targets"] = {"scope": "not-a-list"}
    with pytest.raises(ContractError):
        decode(json.dumps(data).encode())
    with pytest.raises(ContractError):
        decode(
            b'{"schema_version":1,"kind":"risk-policy.v1","kind":"os.system","value":{}}'
        )


def test_roundtrip_does_not_supply_execution_or_signing_authority(scope, now):
    _, _, request, _ = rehearsal_bundle(scope, now)
    data = json.loads(encode(request))
    assert "credentials" not in data["value"]
    assert data["value"]["profile"]["production_credentials_allowed"] is False
    data["value"]["profile"]["production_credentials_allowed"] = True
    with pytest.raises(ContractError):
        decode(json.dumps(data).encode())
