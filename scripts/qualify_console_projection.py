"""Local cross-repository qualification; never calls a cloud or grants authority.

Run with the console's locked development Python environment. Both checkout
revisions must be explicit. Fixture identities, grants and snapshots are local;
this result must not be used as an operational acceptance receipt.
"""

import argparse
from datetime import timedelta
import hashlib
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def checkout(root, revision):
    root = root.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("full_source_revision_required")
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != revision:
        raise ValueError("source_revision_mismatch")
    for arguments in (["diff", "--quiet"], ["diff", "--cached", "--quiet"]):
        subprocess.run(["git", "-C", str(root), *arguments], check=True)
    return root


def qualify(platform, security, platform_revision, security_revision):
    services = platform / "services"
    paths = [security / "src", security / "tests/unit"]
    paths += [p / "src" for p in services.iterdir() if (p / "src").is_dir()]
    sys.path[:0] = [str(p) for p in paths]
    for name, expected in (
        ("sova_security.adapters.console_workload", security / "src"),
        ("bravo_console.workload", services / "console/src"),
        ("bravo_platform_events.plan_api", services / "platform-events/src"),
    ):
        module = importlib.import_module(name)
        if not Path(module.__file__).resolve().is_relative_to(expected):
            raise ValueError("imported_source_mismatch")

    from test_console_workload import NOW, snapshot
    from sova_security.adapters.console_workload import (
        ConsolePlanBinding, project_security_snapshots,
    )
    from bravo_platform_events.plan_api import Principal, create_plan_app
    from bravo_platform_events.plans import PlanSpec, PlanStore
    from bravo_console.workload import PlanWorkload, RegisteredWorkload
    from bravo_console.composition import compose_console
    from fastapi.testclient import TestClient

    cases = (
        ("current", 200), ("no-session", 403), ("other-tenant", 403),
        ("read-denied", 403), ("producer-revoked", 503),
        ("digest-mismatch", 503), ("producer-revision-mismatch", 503),
        ("foreign-environment", 503), ("plan-changed", 503),
        ("producer-revoked-during-read", 503), ("permission-revoked-during-read", 403),
        ("disconnected", 503), ("expired", 200), ("post-attempt", 405),
    )
    results = []
    current = None
    for fault, expected in cases:
        with tempfile.TemporaryDirectory(prefix="console-qualification-") as temp:
            store = PlanStore(Path(temp) / "plan.db")
            spec = PlanSpec("plan-console", "tenant", "app", "source", "target",
                            "a" * 64, "b" * 64)
            store.register_plan(spec, run_id="fixture", occurred_at=NOW.isoformat())
            state = {"producer": True, "permission": True, "loads": 0}

            def identity(request):
                if request.cookies.get("fixture-session") != "test-only":
                    return None
                return Principal("fixture-reader", "other" if fault == "other-tenant" else "tenant")

            api = create_plan_app(store, resolve_principal=identity)

            def load(_scope, plan):
                state["loads"] += 1
                if fault == "disconnected":
                    raise RuntimeError("fixture-private-error-must-not-escape")
                binding = ConsolePlanBinding("tenant", plan["workload_id"], plan["plan_id"],
                    plan["plan_digest"], plan["version"], plan["source_environment_id"],
                    plan["target_environment_id"])
                snapshots = (snapshot(count=10), snapshot(count=10,
                    environment="foreign" if fault == "foreign-environment" else "target"))
                value = project_security_snapshots(binding, snapshots,
                    stream_id="fixture-registration", revision=1, now=NOW, provenance="synthetic")
                raw = json.dumps(value, ensure_ascii=False).encode()
                digest = hashlib.sha256(raw).hexdigest()
                if fault == "plan-changed":
                    with store._transaction(write=True, plan_id=plan["plan_id"]) as connection:
                        connection.execute("UPDATE plans SET version=version+1 WHERE plan_id=?",
                                           (plan["plan_id"],))
                if fault == "producer-revoked-during-read":
                    state["producer"] = False
                if fault == "permission-revoked-during-read":
                    state["permission"] = False
                return RegisteredWorkload("fixture-security",
                    "0" * 40 if fault == "producer-revision-mismatch" else security_revision,
                    "0" * 64 if fault == "digest-mismatch" else digest, raw)

            reader = PlanWorkload(api, load=load,
                authorize=lambda *_: state["permission"] and fault != "read-denied",
                authenticate=lambda *_: state["producer"] and fault != "producer-revoked",
                producer_id="fixture-security", source_revision=security_revision,
                provenance="synthetic", clock=lambda: NOW + timedelta(minutes=10)
                if fault == "expired" else NOW)
            app = compose_console(api, store, public_origin="https://console.example.invalid",
                resolve_principal=identity, authorize_panel=lambda *_: False,
                authorize_operation=lambda *_: False, workload=reader)
            cookies = {} if fault == "no-session" else {"fixture-session": "test-only"}
            with TestClient(app, base_url="https://console.example.invalid", cookies=cookies) as client:
                method = client.post if fault == "post-attempt" else client.get
                response = method("/v1/plans/plan-console/workload")
            if response.status_code != expected:
                raise AssertionError((fault, response.status_code, expected))
            if "private-" in response.text:
                raise AssertionError("private_detail_exposed")
            if fault in {"no-session", "other-tenant", "read-denied", "post-attempt"}:
                assert state["loads"] == 0
            if expected == 200:
                document = response.json()
                if fault == "current":
                    current = document
                assert document["authorizes_execution"] is False
                assert len(document["nodes"]) == 20
                assert all(n["health"] == "unknown" for n in document["nodes"])
                assert all(r["status"] == "unknown" for r in document["responses"])
                assert all(e["state"] == "unknown" for e in document["edges"])
                if fault == "expired":
                    # Preserve historical expiry. The browser removes current claims.
                    assert document["expires_at"] <= reader.clock().isoformat()
            results.append({"case": fault, "status": response.status_code,
                            "producer_reads": state["loads"]})
    module = (services / "console/src/bravo_console/static/workload-model.js").as_uri()
    code = "import {workloadDocument,projectedWorkload} from " + json.dumps(module) + ";" + """
let raw=''; for await (const part of process.stdin) raw+=part;
const doc=JSON.parse(raw), plan={plan_id:doc.plan_id,plan_digest:doc.plan_digest,version:doc.plan_version};
const now=Date.parse(doc.observed_at), parsed=workloadDocument(doc,plan,now);
const active=projectedWorkload(parsed,{now});
const expired=projectedWorkload(parsed,{now:Date.parse(doc.expires_at)});
if(active.nodes.length!==20||active.nodes.filter(n=>n.security==='warning').length!==2||
   active.nodes.some(n=>n.health!=='unknown')||active.edges.some(e=>e.state!=='unknown')||
   active.responses.some(r=>r.status!=='unknown')||expired.nodes.some(n=>n.security!=='unknown'))
    throw Error('projection_consumer_mismatch');
console.log(JSON.stringify({nodes:20,configuration_warnings:2,runtime_effect_claims:0,expired_claims:0}));
"""
    consumer = subprocess.run(["node", "--input-type=module", "-e", code],
        input=json.dumps(current), capture_output=True, text=True, check=True)
    return {"scope": "local real T10/console/security code with synthetic identity and resources",
            "operational_acceptance": False, "authorizes_execution": False,
            "platform_revision": platform_revision, "security_revision": security_revision,
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "cases": results, "javascript_consumer": json.loads(consumer.stdout)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-root", type=Path, required=True)
    parser.add_argument("--platform-revision", required=True)
    parser.add_argument("--security-revision", required=True)
    args = parser.parse_args()
    security = checkout(Path(__file__).resolve().parents[1], args.security_revision)
    platform = checkout(args.platform_root, args.platform_revision)
    print(json.dumps(qualify(platform, security, args.platform_revision,
                             args.security_revision), indent=2))


if __name__ == "__main__":
    main()
