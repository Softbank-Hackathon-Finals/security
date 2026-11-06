"""Local signed-token issuer simulator. Not Kubernetes qualification evidence."""

import base64
from datetime import timedelta
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class LocalTokenReview:
    def __init__(self, now, *, audience="security-review"):
        self.now, self.audience = now, audience
        self.key = Ed25519PrivateKey.generate()
        self.username, self.uid = "system:serviceaccount:security:test-worker", "test-uid"
        self.active = True
        self.calls = 0
        self.client_token = self.issue(self.username, audience)
        self.reviewer_token = self.issue("system:serviceaccount:security:reviewer", "api-server")

    def issue(self, subject, audience):
        claims = dict(sub=subject, aud=[audience], iat=int(self.now.timestamp()), nbf=int(self.now.timestamp()),
                      exp=int((self.now + timedelta(minutes=2)).timestamp()))
        body = b64(b'{"alg":"EdDSA","typ":"JWT"}') + "." + b64(json.dumps(claims).encode())
        return body + "." + b64(self.key.sign(body.encode()))

    async def __call__(self, scope, receive, send):
        self.calls += 1
        raw = bytearray()
        while True:
            chunk = await receive()
            raw.extend(chunk.get("body", b""))
            if not chunk.get("more_body"):
                break
        status = dict(authenticated=False)
        try:
            assert scope["path"] == "/apis/authentication.k8s.io/v1/tokenreviews"
            assert dict(scope["headers"])[b"authorization"] == ("Bearer " + self.reviewer_token).encode()
            spec = json.loads(raw)["spec"]
            body, signature = spec["token"].rsplit(".", 1)
            self.key.public_key().verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), body.encode())
            claims = json.loads(base64.urlsafe_b64decode(body.split(".")[1] + "=="))
            assert self.active and claims["sub"] == self.username
            assert claims["aud"] == spec["audiences"] == [self.audience]
            assert claims["nbf"] <= self.now.timestamp() < claims["exp"]
            status = dict(authenticated=True, audiences=[self.audience], user=dict(username=self.username, uid=self.uid))
        except Exception:
            pass
        raw = json.dumps(dict(apiVersion="authentication.k8s.io/v1", kind="TokenReview", status=status)).encode()
        await send(dict(type="http.response.start", status=200, headers=[(b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode())]))
        await send(dict(type="http.response.body", body=raw))
