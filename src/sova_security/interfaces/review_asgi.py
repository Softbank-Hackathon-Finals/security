"""Small bounded ASGI interface; serve with direct TLS and proxy headers disabled."""

import asyncio
import json
import threading

from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.review_https import bearer
from sova_security.application.review_service import ReviewServiceError, SecurityReviewEndpoint
from sova_security.domain.review_service import ReviewRequest


class SecurityReviewApp:
    def __init__(self, endpoint, *, concurrency=16, timeout=5.0):
        if type(endpoint) is not SecurityReviewEndpoint or type(concurrency) is not int or not 1 <= concurrency <= 64:
            raise ValueError("Explicit review endpoint and bounded concurrency required")
        if type(timeout) not in {int, float} or not 0 < timeout <= 10:
            raise ValueError("Bounded request deadline required")
        self.endpoint, self.timeout = endpoint, timeout
        self.permits = threading.BoundedSemaphore(concurrency)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return

        async def reply(status, code=None, raw=None):
            body = raw if raw is not None else json.dumps({"code": code}, separators=(",", ":")).encode()
            await send({"type": "http.response.start", "status": status, "headers": [
                (b"content-type", b"application/json"), (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"), (b"content-length", str(len(body)).encode()),
            ]})
            await send({"type": "http.response.body", "body": body})

        if scope.get("scheme") != "https":
            return await reply(403, "TLS_REQUIRED")
        if scope.get("query_string") or scope.get("path") != "/v1/program-reviews" or scope.get("method") != "POST":
            return await reply(404, "NOT_FOUND")
        headers = {}
        for name, value in scope.get("headers", []):
            name = name.lower()
            if name in headers:
                return await reply(400, "INVALID_HEADERS")
            headers[name] = value
        if (len(headers) > 32 or sum(len(k) + len(v) for k, v in headers.items()) > 20000
                or b"content-encoding" in headers or b"transfer-encoding" in headers):
            return await reply(400, "INVALID_HEADERS")
        try:
            if headers.get(b"content-type") != b"application/json":
                return await reply(415, "JSON_REQUIRED")
            length = headers.get(b"content-length", b"")
            if not length.isdigit() or not 0 < int(length) <= 16384:
                return await reply(413, "BOUNDED_BODY_REQUIRED")
            authorization = headers.get(b"authorization", b"").decode("ascii")
            if not authorization.startswith("Bearer "):
                return await reply(403, "ACCESS_DENIED")
            token = bearer(authorization[7:])
        except (ValueError, UnicodeError):
            return await reply(400, "INVALID_HEADERS")
        if not self.permits.acquire(blocking=False):
            return await reply(503, "SERVICE_BUSY")
        handed_off = False
        deadline = asyncio.get_running_loop().time() + self.timeout

        async def body():
            raw = bytearray()
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    raise ValueError()
                raw.extend(message.get("body", b""))
                if len(raw) > int(length):
                    raise ValueError()
                if not message.get("more_body", False):
                    if len(raw) != int(length):
                        raise ValueError()
                    return bytes(raw)

        try:
            raw = await asyncio.wait_for(body(), timeout=min(self.timeout, 3))
            request = decode(raw)
            if type(request) is not ReviewRequest:
                return await reply(422, "INVALID_REVIEW_REQUEST")
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError()

            def work():
                # A timed-out HTTP request does not cancel a blocking SDK call.
                # Keep its capacity reserved until the worker actually exits.
                try:
                    return encode(self.endpoint.review(token, request)).encode()
                finally:
                    self.permits.release()

            task = asyncio.create_task(asyncio.to_thread(work))
            handed_off = True
            # Retrieve late failures as well, without logging private exception strings.
            task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            response = await asyncio.wait_for(asyncio.shield(task), remaining)
            return await reply(200, raw=response)
        except ReviewServiceError as error:
            return await reply(403 if error.code == "ACCESS_DENIED" else 503, error.code)
        except TimeoutError:
            return await reply(503, "SERVICE_DEADLINE_EXCEEDED")
        except (ValueError, KeyError, TypeError):
            return await reply(422, "INVALID_REVIEW_REQUEST")
        except Exception:
            return await reply(503, "AUTHORITY_UNAVAILABLE")
        finally:
            if not handed_off:
                self.permits.release()
