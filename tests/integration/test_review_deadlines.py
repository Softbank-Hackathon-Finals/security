"""Owned raw TLS peer: slow metadata/body must share one transport deadline."""

from contextlib import contextmanager
from datetime import timedelta
import socket
import ssl
import threading
import time

import pytest

from tls_review_support import certificates
from sova_security.adapters.review_https import BearerCredential, HTTPSJSONTransport, ReviewTransportError


@contextmanager
def raw_tls_peer(directory, mode):
    ca, certificate, key = certificates(directory, name="deadline")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    port = listener.getsockname()[1]
    stop, requests = threading.Event(), []

    def peer():
        try:
            plain, _ = listener.accept()
            if mode == "handshake-and-body" and stop.wait(0.25):
                plain.close()
                return
            with context.wrap_socket(plain, server_side=True) as stream:
                stream.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 8192:
                    part = stream.recv(4096)
                    if not part:
                        return
                    request += part
                # Drain the fixed two-byte request body before closing the peer;
                # unread input can turn a graceful TLS close into a TCP reset.
                _headers, _, received_body = request.partition(b"\r\n\r\n")
                while len(received_body) < 2:
                    part = stream.recv(2 - len(received_body))
                    if not part:
                        return
                    received_body += part
                requests.append(True)
                head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                if mode in {"body", "handshake-and-body"}:
                    stream.sendall(head + b"Content-Length: 2\r\n\r\n")
                    for byte in (b"{", b"}"):
                        if stop.wait(0.35):
                            return
                        stream.sendall(byte)
                elif mode == "oversized-metadata":
                    stream.sendall(head + b"Content-Length: 2\r\nX-Padding: " + b"x" * 21000 + b"\r\n\r\n{}")
                elif mode == "interim-metadata":
                    interim = b"HTTP/1.1 100 Continue\r\nX-Padding: " + b"x" * 10000 + b"\r\n\r\n"
                    stream.sendall(interim * 3 + head + b"Content-Length: 2\r\n\r\n{}")
                elif mode == "truncated-trailer":
                    stream.sendall(head + b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n")
                elif mode == "trailers":
                    stream.sendall(head + b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX-Padding: " + b"x" * 21000 + b"\r\n\r\n")
                elif mode in {"chunked", "length", "close"}:
                    framed = {"chunked": b"Transfer-Encoding: chunked\r\n\r\n2;ext=ok\r\n{}\r\n0\r\nX-Test: done\r\n\r\n",
                              "length": b"Content-Length: 2\r\n\r\n{}", "close": b"\r\n{}"}
                    stream.sendall(head + framed[mode])
                else:
                    if mode == "headers":
                        stream.sendall(head + b"Content-Length: 2\r\nX-Slow: ")
                        end = b"\r\n\r\n{}"
                    else:
                        stream.sendall(head + b"Transfer-Encoding: chunked\r\n\r\n2;slow=")
                        end = b"\r\n{}\r\n0\r\n\r\n"
                    for _ in range(20):
                        if stop.wait(0.05):
                            return
                        stream.sendall(b"x")
                    stream.sendall(end)
        except (OSError, ssl.SSLError):
            pass  # Client refusal/timeout is expected; never log credentials.

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{port}", ca, requests
    finally:
        stop.set()
        listener.close()
        thread.join(4)
        assert not thread.is_alive(), "Owned TLS fixture did not stop"


@pytest.mark.parametrize("mode", ["headers", "body", "chunk-metadata", "handshake-and-body"])
def test_partial_progress_cannot_restart_request_budget(tmp_path, now, mode):
    with raw_tls_peer(tmp_path, mode) as (origin, ca, requests):
        transport = HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)), timeout=0.4)
        start = time.monotonic()
        with pytest.raises(ReviewTransportError):
            transport.post("/v1/program-reviews", b"{}", BearerCredential("owned-deadline-test", now + timedelta(minutes=1)))
        elapsed = time.monotonic() - start
        assert elapsed < 0.6, f"Partial response exceeded shared deadline: {elapsed:.3f}s"
        assert len(requests) == 1


@pytest.mark.parametrize("mode", ["oversized-metadata", "interim-metadata", "trailers", "truncated-trailer"])
def test_metadata_has_a_bound_independent_of_small_body(tmp_path, now, mode):
    with raw_tls_peer(tmp_path, mode) as (origin, ca, requests):
        transport = HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)))
        with pytest.raises(ReviewTransportError):
            transport.post("/v1/program-reviews", b"{}", BearerCredential("owned-metadata-test", now + timedelta(minutes=1)))
        assert len(requests) == 1


@pytest.mark.parametrize("mode", ["chunked", "length", "close"])
def test_valid_framing_within_budget_is_accepted_once(tmp_path, now, mode):
    with raw_tls_peer(tmp_path, mode) as (origin, ca, requests):
        transport = HTTPSJSONTransport(origin, tls_context=ssl.create_default_context(cafile=str(ca)))
        assert transport.post("/v1/program-reviews", b"{}", BearerCredential("owned-framing-test", now + timedelta(minutes=1))) == b"{}"
        assert len(requests) == 1


def test_late_resolver_cannot_open_socket_or_send_credential(monkeypatch, now):
    from sova_security.adapters import deadline_http

    def late_resolution(*_args):
        time.sleep(0.15)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9))]

    def no_socket(*_args):
        pytest.fail("Expired DNS budget opened a socket")

    monkeypatch.setattr(deadline_http.socket, "getaddrinfo", late_resolution)
    monkeypatch.setattr(deadline_http.socket, "socket", no_socket)
    transport = HTTPSJSONTransport("https://registered.invalid", timeout=0.1)
    with pytest.raises(ReviewTransportError):
        transport.post("/v1/program-reviews", b"{}", BearerCredential("owned-resolver-test", now + timedelta(minutes=1)))
