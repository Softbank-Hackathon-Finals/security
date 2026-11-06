"""Offline intake planning, never an authenticated gate or a cloud test runner.

Keep reported verdicts separate from acceptance. No raw identifiers, excerpts,
commands, URLs or credentials are copied into the diagnostic output.
"""

from collections import Counter
from datetime import UTC, datetime, timedelta
import hashlib
from importlib.resources import files
import json

from sova_security.adapters.team_control_results import _validator as controls_validator
from sova_security.adapters.team_detection import _validator as detection_validator
from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.team_controls import CURRENT_SCHEMA_DIGEST as CONTROL_SCHEMA
from sova_security.domain.detection import CURRENT_SCHEMA_DIGEST as DETECTION_SCHEMA

PLATFORM_SHA = "c364e6284d2e635ff86001e2feac88560ed23ebc"
PROFILES_SHA256 = "47870083fb7f48b8a607bb261314a611b503ad655b6c9435afa61c1b1e1381d3"

# Routing/prerequisites only. Test semantics are always taken from T5 profiles.
ROUTES = {
    "SEC-01": (["T14", "T7", "T9"], "Current workload identity, registered Secret and allowed/denied callers"),
    "ENC-02": (["T14", "T6", "T9"], "Current Secret version and existing encryption-key metadata"),
    "ENC-01": (["T14", "T6", "T8", "T30"], "Registered app/pooler/DB paths, CA, TLS hostname and scoped reader"),
    "AUD-01": (["T14", "T34"], "Canary event window and read-only audit search for both environments"),
    "NET-01": (["T14", "T6", "T30"], "Registered external/internal probe locations and positive controls"),
    "IAM-01": (["T14", "T9"], "Exact resource ownership and scoped policy/anonymous access probes"),
    "ISO-01": (["T14", "T30"], "Two distinct app identities, resources and normal access controls"),
    "DR-01": (["T14", "T35"], "Backup ID, isolated restore target, marker and independent deletion-denial probes"),
}


def _validate(validator, data, kind):
    from jsonschema.exceptions import ValidationError
    try:
        validator.validate(data)
    except ValidationError:
        raise ContractError("Intake input does not match pinned platform schema") from None
    if data.get("kind") != kind:
        raise ContractError("Explicit intake document kind required")


def _time(value):
    try:
        return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, TypeError, AttributeError):
        raise ContractError("Aware intake timestamp required") from None


def _epoch(value):
    if type(value) is not int:
        raise ContractError("Integer intake timestamp required")
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OSError, ValueError, OverflowError):
        raise ContractError("Bounded intake timestamp required") from None


def intake_plan(*, now, control_runs=(), source_statuses=()):
    """Return a fixed-full-profile work list and unauthenticated report coverage.

    An empty input produces every required row as NOT_PROVIDED. A complete
    report still cannot establish source authenticity, plan binding or live PASS.
    """
    now = utc(now)
    if type(control_runs) not in {tuple, list} or type(source_statuses) not in {tuple, list}:
        raise ContractError("Bounded intake document lists required")
    control_runs, source_statuses = tuple(control_runs), tuple(source_statuses)
    if len(control_runs) > 2 or len(source_statuses) > 32:
        raise ContractError("Bounded source/target intake required")
    raw_profiles = files("sova_security").joinpath("schemas/team-control-profiles-20261107.json").read_bytes()
    if hashlib.sha256(raw_profiles).hexdigest() != PROFILES_SHA256:
        raise ContractError("Pinned intake profile changed")
    catalog = json.loads(raw_profiles)
    _validate(controls_validator(CONTROL_SCHEMA), catalog, "evaluation_profiles")
    profile = next(p for p in catalog["profiles"] if (p["id"], p["version"]) == ("full", "1"))
    required = profile["required_test_ids"]
    runs, receipts = {}, []
    for raw in control_runs:
        data = bounded_report(raw)
        _validate(controls_validator(CONTROL_SCHEMA), data, "control_run")
        role = data["environment"]["role"]
        if role in runs:
            raise ContractError("One source and one target for the same workload required")
        if runs and data["app"] != next(iter(runs.values()))["app"]:
            raise ContractError("Matching source and target workload references required")
        if any(data["run_id"] == other["run_id"] for other in runs.values()):
            raise ContractError("Distinct source and target run references required")
        if not _time(data["started_at"]) <= _time(data["finished_at"]) <= now:
            raise ContractError("Ordered, non-future intake run required")
        items = data["results"]
        ids = [r["test_id"] for r in items]
        if len(ids) != len(set(ids)) or any(i not in catalog["tests"] for i in ids):
            raise ContractError("Unique known intake tests required")
        runs[role] = data
        receipts.append({"kind": "control_run", "role": role, "sha256": hashlib.sha256(raw).hexdigest()})
    if len(runs) == 2 and runs["source"]["environment"]["id"] == runs["target"]["environment"]["id"]:
        raise ContractError("Distinct source and target environments required")
    rows = []
    for test_id in required:
        spec = catalog["tests"][test_id]
        tasks, prerequisite = ROUTES[spec["control_id"]]
        if test_id == "SEC-01.2":
            tasks = ["T14"]
        elif test_id == "SEC-01.3":
            tasks = ["T14", "T34"]
        row = {"test_id": test_id, **spec, "tasks": list(tasks), "prerequisite": prerequisite,
            "acceptance": "LIVE_NOT_VERIFIED", "execution": "NOT_EXECUTED"}
        for role in ("source", "target"):
            found = next((r for r in runs.get(role, {}).get("results", []) if r["test_id"] == test_id), None)
            observation = {"reported_verdict": None, "coverage": "NOT_PROVIDED"}
            if found is not None:
                proof = found["evidence"]
                coverage = "REPORTED_UNAUTHENTICATED"
                if any(found[k] != spec[k] for k in ("control_id", "method_version", "expected")):
                    coverage = "CONTRACT_MISMATCH"
                elif proof is None:
                    coverage = "EVIDENCE_NOT_PROVIDED"
                elif not _time(proof["collected_at"]) <= now < _time(proof["expires_at"]):
                    coverage = "EVIDENCE_NOT_CURRENT"
                observation = {"reported_verdict": found["verdict"], "unknown_reason": found["unknown_reason"],
                    "coverage": coverage}
            row[role] = observation
        rows.append(row)
    statuses, seen = [], set()
    for raw in source_statuses:
        data = bounded_report(raw)
        _validate(detection_validator(DETECTION_SCHEMA), data, "source_status")
        key = data["source"], data["environment_id"]
        if key in seen:
            raise ContractError("Ambiguous duplicate source status; select one collection window")
        seen.add(key)
        checked = _epoch(data["checked_time"])
        success = _epoch(data["last_success_time"]) if "last_success_time" in data else None
        if checked > now or (success is not None and success > checked):
            raise ContractError("Ordered non-future source status required")
        current = now - timedelta(minutes=15) < checked
        if success is not None:
            current = current and now - timedelta(minutes=15) < success
        statuses.append({"source": data["source"],
            "scope_sha256": hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest(),
            "reported_state": data["state"], "error_code": data.get("error_code"),
            "coverage": "REPORTED_UNAUTHENTICATED" if current and data["state"] == "OK" else "GAP_OR_STALE",
            "positive_finding": "NOT_ESTABLISHED", "acceptance": "LIVE_NOT_VERIFIED"})
        receipts.append({"kind": "source_status", "sha256": hashlib.sha256(raw).hexdigest()})
    counts = {role: dict(Counter(r[role]["reported_verdict"] or "NOT_PROVIDED" for r in rows))
        for role in ("source", "target")}
    return {"kind": "platform-security-intake.v1", "platform_sha": PLATFORM_SHA,
        "profiles_sha256": PROFILES_SHA256, "generated_at": now.isoformat(),
        "profile": {"id": profile["id"], "version": profile["version"]},
        "workload_reference_sha256": hashlib.sha256(next(iter(runs.values()))["app"].encode()).hexdigest() if runs else None,
        "live_verified": False, "authorizes_execution": False,
        "scope": "Offline diagnostic; input authenticity and current plan binding are NOT verified",
        "required_tests": rows, "reported_counts": counts, "source_statuses": statuses,
        "receipts": receipts,
        "detection_followup": {"task": "T33", "sources": ["aws_security_hub", "aws_guardduty", "gcp_scc", "falco", "kyverno"],
            "aws_selection": "Security Hub or explicitly registered direct GuardDuty; no silent fallback",
            "positive_finding": "NOT_ESTABLISHED", "scope_mapping": "Exact authenticated resource mapping required"}}
