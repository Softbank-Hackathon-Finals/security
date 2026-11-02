"""Bounded standard JSON decoding shared by fixed report profiles."""

import json
import math

from sova_security.contracts.commands import ContractError


def bounded_json_object(raw, *, max_bytes, max_nodes):
    if (
        type(max_bytes) is not int
        or not 1 <= max_bytes <= 8 * 1024 * 1024
        or type(max_nodes) is not int
        or not 1 <= max_nodes <= 200000
    ):
        raise ContractError("Bounded parser resource profile required")
    if type(raw) is not bytes or not 0 < len(raw) <= max_bytes:
        raise ContractError("Bounded report bytes required")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("Duplicate report field")
            result[key] = value
        return result

    def invalid(_):
        raise ContractError("Non-finite JSON is forbidden")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid
        )
        stack, count = [(value, 0)], 0
        while stack:
            item, depth = stack.pop()
            count += 1
            if depth > 24 or count > max_nodes:
                raise ContractError("Report nesting or node limit exceeded")
            if isinstance(item, dict):
                for key in item:
                    key.encode("utf-8")
                stack.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                stack.extend((v, depth + 1) for v in item)
            elif isinstance(item, str):
                item.encode("utf-8")
            elif type(item) is float and not math.isfinite(item):
                # json's parse_constant catches NaN/Infinity literals, not the
                # numeric overflow of a valid JSON exponent such as 1e9999.
                raise ContractError("Non-finite JSON number is forbidden")
        if type(value) is not dict:
            raise ContractError("Report object required")
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ContractError("Invalid bounded report JSON") from None
