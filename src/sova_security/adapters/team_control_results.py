"""Team T5 schema bridge; no second test runner, comparator or exception engine.

The host authenticates registration and full raw report before accepting output.
Commands/excerpts/URIs are neither executed, fetched nor copied into projections.
"""

from datetime import datetime, timedelta
import hashlib
from importlib.resources import files
import json
from types import MappingProxyType

from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, utc
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.team_controls import (
    TeamControlRegistration,
    ImportedControlRun,
    CURRENT_SCHEMA_DIGEST,
    LEGACY_SCHEMA_DIGEST,
)

SCHEMA_SHA256 = "7c9728028af9c9d8bc45f5e8a8ba2b3ba0e38c96b7373b7338b49c8f37adfeb9"
SOURCE_COMMIT = "fc5a25e46904f55908da8bdee7122e4ad1574c5f"
CURRENT_SOURCE_COMMIT = "505d451fd8c374de755b160fca24f1a481820a50"
SCHEMA_FILES = MappingProxyType(
    {
        LEGACY_SCHEMA_DIGEST: "team-control-result-v1.json",
        CURRENT_SCHEMA_DIGEST: "team-control-result-20261106.json",
    }
)


def _validator(schema_digest=SCHEMA_SHA256):
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry
    from referencing.exceptions import NoSuchResource

    if schema_digest not in SCHEMA_FILES:
        raise ContractError("Registered team schema snapshot required")
    raw = (
        files("sova_security")
        .joinpath("schemas/" + SCHEMA_FILES[schema_digest])
        .read_bytes()
    )
    if hashlib.sha256(raw).hexdigest() != schema_digest:
        raise ContractError("Pinned team control schema changed")
    schema = json.loads(raw)
    Draft202012Validator.check_schema(schema)

    def no_remote_reference(uri):
        raise NoSuchResource(ref=uri)

    # Only the vendored schema and its local $defs can participate. No report
    # field can cause an arbitrary URL/schema to be retrieved.
    return Draft202012Validator(
        schema,
        format_checker=FormatChecker(formats=["date-time"]),
        registry=Registry(retrieve=no_remote_reference),
    )


def _time(value):
    try:
        return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (AttributeError, ValueError, TypeError) as exc:
        raise ContractError("Aware team control timestamp required") from exc


def import_control_run(raw, *, registration, now):
    now = utc(now)
    if (
        not isinstance(registration, TeamControlRegistration)
        or not registration.observed_at <= now < registration.valid_until
    ):
        raise ContractError("Current team control registration required")
    data = bounded_report(raw)
    if data.get("kind") != "control_run":
        raise ContractError(
            "Only raw control runs can be imported; gate decisions grant no authority"
        )
    from jsonschema.exceptions import ValidationError

    try:
        _validator(registration.schema_digest).validate(data)
    except ValidationError:
        # The library's message contains values, possibly secrets. Do not expose it.
        raise ContractError(
            "Team control run does not match pinned JSON Schema"
        ) from None
    scope = registration.scope
    if data["app"] != scope.application_id or data["environment"] != {
        "id": scope.environment_id,
        "role": registration.role,
        "ref": registration.environment_ref,
    }:
        raise ContractError("Team control app/environment binding mismatch")
    started, finished = _time(data["started_at"]), _time(data["finished_at"])
    if not registration.observed_at <= started <= finished <= now:
        raise ContractError("Team control run time outside registration")
    rows = data["results"]
    if len(rows) > 128:
        raise ContractError("Bounded team control result set required")
    selected = {t.test_id: t for t in registration.tests}
    result_rows = {}
    for row in rows:
        test_id = row["test_id"]
        if (
            test_id not in selected
            or test_id in result_rows
            or row["control_id"] != test_id.split(".")[0]
        ):
            raise ContractError(
                "Unexpected, duplicate or mislabelled team control test"
            )
        result_rows[test_id] = row
    report_digest = hashlib.sha256(raw).hexdigest()
    records = []
    for binding in registration.tests:
        row = result_rows.get(binding.test_id)
        result, reason = VerificationResult.UNKNOWN, "not-run"
        observed = now
        deadline = min(registration.valid_until, now + timedelta(seconds=30))
        if row is not None:
            if row["expected"] != binding.expected:
                raise ContractError("Team report changed registered expected outcome")
            if row["verdict"] in {"PASS", "FAIL"} and (
                row["observed"] == row["expected"]
            ) != (row["verdict"] == "PASS"):
                raise ContractError(
                    "Team verdict contradicts observed/expected outcome"
                )
            proof = row["evidence"]
            if proof is not None:
                collected, expires = (
                    _time(proof["collected_at"]),
                    _time(proof["expires_at"]),
                )
                if not started <= collected <= finished or collected >= expires:
                    raise ContractError("Team evidence times contradict run")
            reason = row["unknown_reason"] or "unverified"
            if row["method_version"] != binding.method_version:
                reason = "method-mismatch"
            elif (
                binding.positive_control_required and row["positive_control"] != "pass"
            ):
                reason = "positive-control-unverified"
            elif proof is not None and not collected <= now < min(
                expires,
                collected
                + timedelta(seconds=registration.maximum_evidence_age_seconds),
            ):
                reason = "evidence-expired"
            elif row["verdict"] in {"PASS", "FAIL"}:
                result = (
                    VerificationResult.PASS
                    if row["verdict"] == "PASS"
                    else VerificationResult.FAIL
                )
                observed = collected
                deadline = min(
                    registration.valid_until,
                    expires,
                    collected
                    + timedelta(seconds=registration.maximum_evidence_age_seconds),
                )
                reason = "verified-observation"
        identity = hashlib.sha256(
            (
                registration.fingerprint + ":" + data["run_id"] + ":" + binding.test_id
            ).encode()
        ).hexdigest()
        records.append(
            EvidenceRecord(
                "team-control-" + identity,
                "team-control:" + binding.test_id,
                scope,
                registration.revisions,
                binding.verifier_version,
                observed,
                deadline,
                result,
                "team-control-report:" + report_digest,
                report_digest,
                reason,
            )
        )
    return ImportedControlRun(
        registration,
        data["run_id"],
        report_digest,
        tuple(records),
        now,
        min(r.valid_until for r in records),
    )


def parity_record(imported, policy, *, test_id, side):
    """Map one explicitly registered team test to the existing parity engine.

    Returns an unsigned record. The independent verifier must sign this exact
    mapped record; a collection signature cannot be reused for another payload.
    """
    from dataclasses import replace
    from sova_security.domain.protection_parity import ProtectionPolicy

    if (
        not isinstance(imported, ImportedControlRun)
        or not isinstance(policy, ProtectionPolicy)
        or side not in {"source", "target"}
    ):
        raise ContractError("Typed team run and explicit parity side required")
    requirement = next(
        (
            r
            for r in policy.requirements
            if r.requirement_id == "team-control:" + test_id
        ),
        None,
    )
    if requirement is None:
        raise ContractError("Team test was not explicitly bound in parity policy")
    endpoint = getattr(requirement, side)
    record = next(
        (r for r in imported.evidence if r.obligation_id == "team-control:" + test_id),
        None,
    )
    if (
        record is None
        or imported.registration.role != side
        or imported.scope != endpoint.scope
        or imported.registration.revisions != endpoint.revisions(policy.fingerprint)
        or record.verifier_version != endpoint.verifier_version
        or requirement.source.verifier_version != requirement.target.verifier_version
    ):
        raise ContractError(
            "Team test method, scope or revision differs from parity policy"
        )
    return replace(
        record,
        obligation_id=requirement.obligation(side).obligation_id,
        valid_until=min(record.valid_until, imported.valid_until, policy.valid_until),
    )
