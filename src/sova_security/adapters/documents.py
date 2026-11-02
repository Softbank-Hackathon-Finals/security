"""Version-one bounded document hashing; no lifecycle persistence dependency."""

import hashlib
from sova_security.contracts.commands import canonical_json


def document_hash(value: dict) -> str:
    return hashlib.sha256(canonical_json(value, limit=262144).encode()).hexdigest()
