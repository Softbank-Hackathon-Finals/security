"""Strict, bounded JSON for the fixed modernization contract registry.

No pickle, dynamic module loading, user type names or unknown fields. New kinds
must be added deliberately with compatibility tests. Documents carry no trust
merely because they decode successfully.
"""

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from types import UnionType, MappingProxyType
from typing import get_args, get_origin, get_type_hints, Union

from sova_security.contracts.commands import ContractError, canonical_json
from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.domain import assessment as a
from sova_security.domain import remediation as r
from sova_security.domain import patch_execution as p

KINDS = MappingProxyType(
    {
        "asset-inventory.v1": a.AssetInventory,
        "scanner-profile.v1": a.ScannerProfile,
        "vulnerability-scan.v1": a.VulnerabilityScan,
        "exposure-observation.v1": a.ExposureObservation,
        "risk-policy.v1": a.RiskPolicy,
        "risk-assessment.v1": a.Assessment,
        "remediation-proposal.v1": r.RemediationProposal,
        "sandbox-profile.v1": r.SandboxProfile,
        "rehearsal-request.v1": r.RehearsalRequest,
        "rehearsal-receipt.v1": r.RehearsalReceipt,
        "rehearsal-decision.v1": r.RehearsalDecision,
        "patch-execution-binding.v1": p.PatchExecutionBinding,
        "patch-runtime-observation.v1": p.PatchRuntimeObservation,
    }
)


def kind_of(value):
    for kind, cls in KINDS.items():
        if type(value) is cls:
            return kind
    raise ContractError("Unknown public security contract kind")


def encode(value):
    return canonical_json(
        {"schema_version": 1, "kind": kind_of(value), "value": value.document},
        limit=1048576,
    )


def _decode(kind, value, depth=0):
    if depth > 24:
        raise ContractError("Contract nesting limit exceeded")
    origin, args = get_origin(kind), get_args(kind)
    if origin in {UnionType, Union}:
        if value is None and type(None) in args:
            return None
        choices = [t for t in args if t is not type(None)]
        if len(choices) != 1:
            raise ContractError("Ambiguous union contract is not supported")
        return _decode(choices[0], value, depth + 1)
    if origin is tuple:
        if (
            type(value) is not list
            or len(value) > 8192
            or len(args) != 2
            or args[1] is not Ellipsis
        ):
            raise ContractError("Bounded homogeneous contract array required")
        return tuple(_decode(args[0], v, depth + 1) for v in value)
    if kind is datetime:
        if type(value) is not str:
            raise ContractError("Contract timestamp text required")
        return datetime.fromisoformat(value)
    if isinstance(kind, type) and issubclass(kind, Enum):
        if type(value) is not str:
            raise ContractError("Contract enumeration string required")
        return kind(value)
    if is_dataclass(kind):
        if type(value) is not dict or set(value) != {f.name for f in fields(kind)}:
            raise ContractError("Contract object fields differ from registered schema")
        hints = get_type_hints(kind)
        return kind(
            **{
                f.name: _decode(hints[f.name], value[f.name], depth + 1)
                for f in fields(kind)
            }
        )
    if kind in {str, bool, int, float} and type(value) is kind:
        return value
    raise ContractError("Contract value type mismatch")


def decode(raw):
    data = bounded_report(raw)
    if (
        set(data) != {"schema_version", "kind", "value"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
    ):
        raise ContractError("Unsupported security contract envelope")
    kind, value = data["kind"], data["value"]
    if type(kind) is not str or kind not in KINDS or type(value) is not dict:
        raise ContractError("Unknown security contract kind")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ContractError("Unsupported security value schema")
    body = {k: v for k, v in value.items() if k != "schema_version"}
    try:
        result = _decode(KINDS[kind], body)
        # Normalize all values before returning. Representation aliases cannot bypass integrity checks.
        encode(result)
        return result
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        raise ContractError("Invalid security contract document") from exc
