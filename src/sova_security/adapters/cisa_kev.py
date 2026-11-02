"""Official KEV schema projection, no arbitrary URL fetch or CVE scanner."""

from datetime import datetime, date
import hashlib
from importlib.resources import files
import json

from sova_security.adapters.bounded_json import bounded_json_object
from sova_security.contracts.commands import ContractError, utc
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.exploitation_intelligence import (
    KnownExploitedCatalog,
    catalog_version,
)

SCHEMA_SHA256 = "0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7"
VERIFIER = "sova.security.cisa-kev.v1"


def parse_cisa_kev(
    raw, *, source_reference, minimum_catalog_version, observed_at, valid_until
):
    from jsonschema import Draft7Validator, FormatChecker
    from jsonschema.exceptions import ValidationError
    from referencing import Registry
    from referencing.exceptions import NoSuchResource

    data = bounded_json_object(raw, max_bytes=8 * 1024 * 1024, max_nodes=200000)
    entries = data.get("vulnerabilities")
    if type(entries) is not list or not 1 <= len(entries) <= 8192:
        raise ContractError("Bounded nonempty KEV catalog required")
    schema_raw = (
        files("sova_security").joinpath("schemas/cisa-kev-v1.json").read_bytes()
    )
    if hashlib.sha256(schema_raw).hexdigest() != SCHEMA_SHA256:
        raise ContractError("Pinned official KEV schema changed")

    def no_remote_reference(uri):
        raise NoSuchResource(ref=uri)

    validator = Draft7Validator(
        json.loads(schema_raw),
        format_checker=FormatChecker(formats=["date-time", "date"]),
        registry=Registry(retrieve=no_remote_reference),
    )
    try:
        validator.validate(data)
        released = utc(
            datetime.fromisoformat(data["dateReleased"].replace("Z", "+00:00"))
        )
        if type(data["count"]) is not int or data["count"] != len(entries):
            raise ContractError("KEV declared count differs from actual entries")
        if catalog_version(data["catalogVersion"]) < catalog_version(
            minimum_catalog_version
        ):
            raise ContractError("KEV catalog rollback below registered version")
        if any(
            date.fromisoformat(row["dateAdded"]) > released.date() for row in entries
        ):
            raise ContractError("KEV entry added after catalog release")
    except (ValidationError, ValueError, TypeError):
        raise ContractError("Invalid or out-of-policy KEV catalog") from None
    return KnownExploitedCatalog(
        source_reference,
        hashlib.sha256(raw).hexdigest(),
        data["catalogVersion"],
        released,
        tuple(row["cveID"] for row in entries),
        observed_at,
        valid_until,
    )


def catalog_evidence(catalog, *, scope, revisions, evidence_id):
    """Unsigned app-scoped record for an authorized public-intelligence collector."""
    if not isinstance(catalog, KnownExploitedCatalog):
        raise ContractError("Typed CISA catalog required")
    return EvidenceRecord(
        evidence_id,
        "cisa-kev:" + catalog.catalog_version,
        scope,
        revisions,
        VERIFIER,
        catalog.observed_at,
        catalog.valid_until,
        VerificationResult.PASS,
        "cisa-kev:" + catalog.fingerprint,
        catalog.fingerprint,
    )
