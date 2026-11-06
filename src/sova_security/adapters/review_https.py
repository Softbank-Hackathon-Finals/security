"""Fixed-origin TLS transport; no redirects, proxies, retries or remote URLs."""

from dataclasses import dataclass, field
from datetime import datetime
import http.client
import ssl
import time
from urllib.parse import urlsplit

from sova_security.contracts.commands import ContractError, utc


class ReviewTransportError(ContractError):
    pass


def bearer(value):
    if type(value) is not str or not 1 <= len(value) <= 16384 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ContractError("Bounded bearer credential required")
    return value


@dataclass(frozen=True, slots=True)
class BearerCredential:
    token: str = field(repr=False)
    valid_until: datetime

    def __post_init__(self):
        bearer(self.token)
        object.__setattr__(self, "valid_until", utc(self.valid_until))


class HTTPSJSONTransport:
    def __init__(self, origin, *, tls_context=None, timeout=2.0, max_response=262144):
        try:
            value = urlsplit(origin)
            if (value.scheme != "https" or not value.hostname or value.username or value.password
                    or value.path not in {"", "/"} or value.query or value.fragment
                    or any(ord(c) < 33 or ord(c) > 126 for c in origin)):
                raise ValueError()
            self.hostname, self.port = value.hostname, value.port or 443
        except (TypeError, ValueError):
            raise ContractError("Registered HTTPS origin required") from None
        if type(timeout) not in {int, float} or not 0 < timeout <= 5:
            raise ContractError("Bounded transport timeout required")
        if type(max_response) is not int or not 1024 <= max_response <= 1048576:
            raise ContractError("Bounded response size required")
        self.timeout, self.max_response = timeout, max_response
        self.context = tls_context or ssl.create_default_context()
        self._require_tls()

    def _require_tls(self):
        if not isinstance(self.context, ssl.SSLContext) or not self.context.check_hostname or self.context.verify_mode != ssl.CERT_REQUIRED:
            raise ContractError("Certificate and hostname verification required")
        if self.context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise ContractError("TLS 1.2 or later required")

    def post(self, path, raw, credential):
        if path not in {"/v1/program-reviews", "/apis/authentication.k8s.io/v1/tokenreviews"}:
            raise ContractError("Fixed service path required")
        if type(raw) is not bytes or not 0 < len(raw) <= 1048576 or type(credential) is not BearerCredential:
            raise ContractError("Bounded request and credential required")
        self._require_tls()
        connection = http.client.HTTPSConnection(self.hostname, self.port, context=self.context, timeout=self.timeout)
        started = time.monotonic()
        try:
            connection.request("POST", path, body=raw, headers={
                "Authorization": "Bearer " + credential.token, "Content-Type": "application/json",
                "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
            })
            response = connection.getresponse()
            headers = response.getheaders()
            for name in ("content-type", "content-length", "content-encoding", "transfer-encoding"):
                if sum(k.lower() == name for k, _v in headers) > 1:
                    raise ReviewTransportError("INVALID_SERVICE_RESPONSE")
            if (response.status not in {200, 201} or response.getheader("Content-Encoding") not in {None, "identity"}
                    or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"):
                raise ReviewTransportError("SERVICE_RESPONSE_REJECTED")
            length = response.getheader("Content-Length")
            if length is not None and response.getheader("Transfer-Encoding") is not None:
                raise ReviewTransportError("INVALID_SERVICE_RESPONSE")
            if length is not None and (not length.isascii() or not length.isdecimal() or int(length) > self.max_response):
                raise ReviewTransportError("INVALID_SERVICE_RESPONSE")
            result = bytearray()
            while True:
                remaining = self.timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise ReviewTransportError("SERVICE_DEADLINE_EXCEEDED")
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(16384, self.max_response + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > self.max_response:
                    raise ReviewTransportError("SERVICE_RESPONSE_TOO_LARGE")
            if time.monotonic() - started >= self.timeout:
                raise ReviewTransportError("SERVICE_DEADLINE_EXCEEDED")
            if length is not None and len(result) != int(length):
                raise ReviewTransportError("INCOMPLETE_SERVICE_RESPONSE")
            return bytes(result)
        except ReviewTransportError:
            raise
        except Exception:
            raise ReviewTransportError("SERVICE_TRANSPORT_UNAVAILABLE") from None
        finally:
            connection.close()
