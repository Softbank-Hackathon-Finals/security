"""Private HTTP transport plumbing with one monotonic network deadline.

DNS resolution remains subject to the host resolver's own bounds. Its elapsed
time consumes this budget: no connection/request starts after late resolution.
"""

from functools import partial
import http.client
import io
import socket
import sys
import time


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("HTTP deadline exceeded")
    return value


class _DeadlineRaw(io.RawIOBase):
    def __init__(self, sock, deadline):
        super().__init__()
        self._socket, self._deadline = sock, deadline
        self._raw = sock.makefile("rb", buffering=0)

    def readable(self):
        return True

    def readinto(self, buffer):
        # HTTPResponse owns its socket file even when Connection: close has
        # already cleared HTTPConnection.sock. Update this live socket instead.
        self._socket.settimeout(remaining(self._deadline))
        return self._raw.readinto(buffer)

    def close(self):
        try:
            self._raw.close()
        finally:
            super().close()


class _MetadataBuffer(io.BufferedReader):
    def __init__(self, raw):
        super().__init__(raw)
        self._metadata_remaining = 20000

    def readline(self, size=-1):
        # http.client uses readline for status/headers/chunk framing/trailers;
        # body reads use read/read1 and have their own independent byte bound.
        limit = self._metadata_remaining + 1
        line = super().readline(limit if size < 0 else min(size, limit))
        self._metadata_remaining -= len(line)
        if self._metadata_remaining < 0:
            raise ValueError("HTTP metadata exceeds bound")
        return line


class _DeadlineResponse(http.client.HTTPResponse):
    def __init__(self, sock, *args, deadline, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.fp.close()
        self.fp = _MetadataBuffer(_DeadlineRaw(sock, deadline))

    def _read_and_discard_trailer(self):
        # The stdlib tolerates EOF here for legacy peers. A signed-service
        # response must finish its HTTP framing, including empty trailers.
        while True:
            line = self.fp.readline()
            if not line:
                raise http.client.IncompleteRead(b"")
            if line == b"\r\n":
                return
            if not line.endswith(b"\r\n"):
                raise http.client.IncompleteRead(b"")


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    """One direct TLS connection; no proxy, tunnel, reconnect or HTTP retry."""

    def __init__(self, host, port, *, context, deadline):
        super().__init__(host, port, context=context, timeout=remaining(deadline))
        self._tls_context, self._deadline = context, deadline
        self.response_class = partial(_DeadlineResponse, deadline=deadline)

    def connect(self):
        # No thread/watchdog can outlive the request or retain its credential.
        # Resolver delay is checked before opening any of the resolved sockets.
        sys.audit("http.client.connect", self, self.host, self.port)
        addresses = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
        for family, kind, protocol, _canonical, address in addresses:
            remaining(self._deadline)
            plain = socket.socket(family, kind, protocol)
            try:
                plain.settimeout(remaining(self._deadline))
                plain.connect(address)
                plain.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                plain.close()
                continue
            try:
                plain.settimeout(remaining(self._deadline))
                self.sock = self._tls_context.wrap_socket(plain, server_hostname=self.host)
                remaining(self._deadline)
                return
            except BaseException:
                plain.close()
                if self.sock is not None:
                    self.sock.close()
                    self.sock = None
                raise
        raise OSError("Registered origin unavailable")

    def send(self, data):
        if type(data) is not bytes:
            raise TypeError("Bounded bytes required")
        if self.sock is None:
            self.connect()
        self.sock.settimeout(remaining(self._deadline))
        super().send(data)
