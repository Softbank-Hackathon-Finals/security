"""Standalone TLS review host with mounted grants and existing PostgreSQL stores."""

import argparse
from datetime import UTC, datetime
import ssl

from sova_security.adapters.review_mounts import (
    LocalReviewAudit, MountedTokenCredential, MountedWorkloadGrants, mounted_bytes,
)
from sova_security.adapters.review_https import HTTPSJSONTransport
from sova_security.adapters.review_identity import TokenReviewAuthenticator
from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.application.review_service import SecurityReviewEndpoint
from sova_security.contracts.commands import ContractError
from sova_security.contracts.commands import identifier
from sova_security.interfaces.review_asgi import SecurityReviewApp


def app_from_config(path, *, clock=None):
    clock = clock or (lambda: datetime.now(UTC))
    data = bounded_report(mounted_bytes(path, limit=16384))
    if set(data) != {"schema_version", "tenant_id", "database_dsn_file", "tokenreview_origin", "tokenreview_ca_file",
                     "reviewer_token_file", "audience", "grants_file", "local_audit_file"}:
        raise ContractError("Explicit standalone review configuration required")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ContractError("Unsupported standalone review configuration")
    identifier(data["tenant_id"])
    import psycopg
    from sova_security.adapters.postgres_review import PostgresReviewHost
    from sova_security.adapters.review_database import require_reader
    from sova_security.adapters.review_connections import RequestScopedReader

    def connect_read():
        dsn = mounted_bytes(data["database_dsn_file"], limit=8192).decode().strip()
        connection = psycopg.connect(dsn, connect_timeout=2, autocommit=True,
            options="-c statement_timeout=2000 -c default_transaction_read_only=on -c idle_in_transaction_session_timeout=3000")
        try:
            connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
            params = connection.info.get_parameters()
            if not params.get("host", "").startswith("/") and (
                not connection.info.ssl_in_use or params.get("sslmode") != "verify-full"
            ):
                raise ContractError("Verified TLS or registered private Unix socket required")
        except Exception:
            connection.close()
            raise
        return connection

    reader = RequestScopedReader(connect_read, validate=lambda connection: require_reader(connection, tenant_id=data["tenant_id"]))
    host = PostgresReviewHost(reader.connect, clock=clock)
    context = ssl.create_default_context(cadata=mounted_bytes(data["tokenreview_ca_file"], limit=65536).decode("ascii"))
    verifier = TokenReviewAuthenticator(audience=data["audience"],
        transport=HTTPSJSONTransport(data["tokenreview_origin"], tls_context=context),
        reviewer_credential=MountedTokenCredential(data["reviewer_token_file"], clock=clock),
        grant_for=MountedWorkloadGrants(data["grants_file"]), clock=clock)
    endpoint = SecurityReviewEndpoint(authenticate=verifier, registration_for=host.registration_for,
        service_for=host.service_for, audit=LocalReviewAudit(data["local_audit_file"]), clock=clock,
        review_scope=reader.request)
    return SecurityReviewApp(endpoint)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("A valid TLS listen port is required")
    try:
        import uvicorn
        app = app_from_config(args.config)
    except Exception:
        parser.exit(2, "Review service configuration is invalid or required extras are unavailable.\n")
    uvicorn.run(app, host=args.host, port=args.port, ssl_certfile=args.certificate, ssl_keyfile=args.private_key,
                ssl_version=ssl.PROTOCOL_TLS_SERVER, proxy_headers=False, access_log=False,
                server_header=False, workers=1, limit_concurrency=32, backlog=32,
                timeout_keep_alive=2, timeout_graceful_shutdown=5, h11_max_incomplete_event_size=20000)


if __name__ == "__main__":
    main()
