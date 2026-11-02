package sova.security

import rego.v1

default decision := {"allow": false, "reasons": ["invalid-input"]}

decision := {"allow": count(deny) == 0, "reasons": sort([r | r := deny[_]])} if {
    input.schema_version == 1
    is_array(input.checks)
    count(input.checks) > 0
}

deny contains "unverified-control" if {
    some check in input.checks
    object.get(check, "result", "unknown") != "pass"
}

deny contains "scope-not-covered" if {
    object.get(input, "scope_covered", false) != true
}

deny contains "policy-not-bound" if {
    object.get(input, "policy_bound", false) != true
}

deny contains "security-hold-active" if {
    object.get(input, "hold_active", true) != false
}

deny contains "plan-purpose-not-covered" if {
    object.get(input, "purpose_covered", false) != true
}
