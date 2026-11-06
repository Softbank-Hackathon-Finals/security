"""Frozen T33 OCSF input bridge, not a SIEM, raw detector or attack classifier.

An authenticated collector must additionally bind exact resource UID/revision.
Masked/missing resource IDs cannot authorize an app-specific hold. Display links,
commands and free text are never followed, executed or copied into the projection.
"""

from datetime import UTC, datetime, timedelta
import hashlib
from importlib.resources import files
import json

from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.detection import (
    DetectionRegistration,
    DetectionObservation,
    SCHEMA_DIGEST,
)

SOURCE_COMMIT = "cbb03cdb705719c94c7ad84fa8aa44f08a1b480b"


def _validator():
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from referencing.exceptions import NoSuchResource

    raw = files("sova_security").joinpath("schemas/team-detection-v1.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_DIGEST:
        raise ContractError("Pinned detection schema changed")
    schema = json.loads(raw)
    Draft202012Validator.check_schema(schema)

    def refuse(uri):
        raise NoSuchResource(ref=uri)

    return Draft202012Validator(schema, registry=Registry(retrieve=refuse))


def _time(value):
    if type(value) is not int:
        raise ContractError("Integer millisecond timestamp required")
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OSError, ValueError, OverflowError):
        raise ContractError("Bounded detection timestamp required") from None


def import_detection(
    raw, *, registration, collected_resource_uid, collected_resource_revision, now
):
    """Only trusted collection bindings can populate collected_resource_*.

    This function does not authenticate bytes. Admission below must authenticate
    this exact observation and its registration before any hold/store effect.
    """
    now = utc(now)
    r = registration
    if (
        not isinstance(r, DetectionRegistration)
        or not r.observed_at <= now < r.valid_until
    ):
        raise ContractError("Current detection registration required")
    if (collected_resource_uid, collected_resource_revision) != (
        r.resource_uid,
        r.resource_revision,
    ):
        raise ContractError("Authenticated collection resource/revision mismatch")
    data = bounded_report(raw)
    from jsonschema.exceptions import ValidationError

    try:
        _validator().validate(data)
    except ValidationError:
        raise ContractError("Detection does not match pinned team schema") from None
    report_digest = hashlib.sha256(raw).hexdigest()
    producer_deadline = r.valid_until
    kind = "source_status" if data.get("kind") == "source_status" else "finding"
    if kind == "source_status":
        if (data["source"], data["environment_id"]) != (
            r.source,
            r.scope.environment_id,
        ):
            raise ContractError("Detection source/environment mismatch")
        observed = _time(data["checked_time"])
        signal = "coverage-unavailable"
        if data["state"] == "OK":
            success = _time(data["last_success_time"])
            if success > observed:
                raise ContractError("Source heartbeat follows collection time")
            if now - timedelta(seconds=r.maximum_age_seconds) < success <= observed:
                signal = "coverage-observed"
                producer_deadline = success + timedelta(seconds=r.maximum_age_seconds)
        key = hashlib.sha256(
            (r.source + ":" + r.scope.environment_id + ":source_status").encode()
        ).hexdigest()
        upstream = report_digest
        sample = False
    else:
        bravo, cloud = data["bravo"], data["cloud"]
        if (bravo["source"], bravo["environment_id"], cloud["provider"]) != (
            r.source,
            r.scope.environment_id,
            r.provider,
        ):
            raise ContractError("Detection source/environment/provider mismatch")
        if r.provider in {"AWS", "GCP"} and (
            cloud.get("account", {}).get("uid"),
            cloud.get("region"),
        ) != (r.account_id, r.region):
            raise ContractError("Detection account/region mismatch")
        resources = data.get("resources", [])
        if len(resources) != 1 or resources[0]["uid"] != r.resource_uid:
            raise ContractError("Exact unmasked detection resource required")
        if resources[0].get("namespace") != r.namespace:
            raise ContractError("Exact registered detection namespace mapping required")
        if data["type_uid"] != data["class_uid"] * 100 + data["activity_id"]:
            raise ContractError("Detection OCSF type arithmetic mismatch")
        observed = _time(bravo["collected_time"])
        occurred = _time(data["time"])
        if occurred > observed or now - occurred >= timedelta(
            seconds=r.maximum_age_seconds
        ):
            raise ContractError("Detection stale/future event time")
        producer_deadline = occurred + timedelta(seconds=r.maximum_age_seconds)
        sample = bravo.get("sample", False)
        key = hashlib.sha256(
            (
                r.source
                + ":"
                + r.scope.environment_id
                + ":"
                + data["finding_info"]["uid"]
            ).encode()
        ).hexdigest()
        upstream = bravo["raw_sha256"][7:]
        # Resolved/suppressed/closed findings retain provenance; they cannot
        # release an existing incident, and are never a clean security verdict.
        if data["status_id"] in {3, 4} or data["activity_id"] == 3:
            signal = "lifecycle-only"
        elif data["status_id"] not in {1, 2} or data["severity_id"] in {0, 99}:
            signal = "unverified-security"
        elif data["class_uid"] == 2004:
            signal = "detected-threat"
        elif data["class_uid"] == 2002:
            signal = "vulnerability-observed"
        else:
            signal = {
                "Fail": "policy-violation",
                "Warning": "unverified-security",
                "Pass": "lifecycle-only",
            }[data["compliance"]["status"]]
    if not r.observed_at <= observed <= now or now - observed >= timedelta(
        seconds=r.maximum_age_seconds
    ):
        raise ContractError("Detection observation stale/future/outside registration")
    return DetectionObservation(
        r,
        report_digest,
        upstream,
        key,
        kind,
        signal,
        sample,
        observed,
        min(r.valid_until, observed + timedelta(seconds=r.maximum_age_seconds), producer_deadline),
    )
