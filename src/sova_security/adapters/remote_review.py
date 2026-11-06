"""Fresh, nonce-bound service consumption. Historical responses are never cached."""

from dataclasses import replace
import secrets

from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.review_https import BearerCredential
from sova_security.contracts.commands import ContractError, utc
from sova_security.domain.review_service import RemoteProgramReview, ReviewRegistration, ReviewRequest


class RemoteReviewClient:
    def __init__(self, *, transport, credential_for, current_registration, subject_id, clock):
        self.transport, self.credential_for = transport, credential_for
        self.current_registration, self.subject_id, self.clock = current_registration, subject_id, clock

    def review(self, *, scope, subject_digest, phase, mode="enforce", not_before=None):
        registration = self.current_registration(scope, subject_digest, phase)
        if (type(registration) is not ReviewRegistration or registration.scope != scope
                or registration.program.subject_digest != subject_digest or registration.phase != phase
                or registration.not_before != not_before):
            raise ContractError("Current authenticated local review registration required")
        started = utc(self.clock())
        registration.require_current(started)
        credential = self.credential_for()
        if type(credential) is not BearerCredential or started >= credential.valid_until:
            raise ContractError("Current host credential required")
        request = ReviewRequest(scope, registration.fingerprint, secrets.token_hex(32), mode)
        response = decode(self.transport.post("/v1/program-reviews", encode(request).encode(), credential))
        finished = utc(self.clock())
        if (finished < started or finished >= credential.valid_until
                or self.current_registration(scope, subject_digest, phase) != registration
                or type(response) is not RemoteProgramReview or response.issued_at < started):
            raise ContractError("Remote authority changed or is not fresh")
        response.require_for(request, registration, subject_id=self.subject_id, now=finished)
        # The caller's credential deadline must not be lost at the transport boundary.
        return replace(response, valid_until=min(response.valid_until, credential.valid_until))
