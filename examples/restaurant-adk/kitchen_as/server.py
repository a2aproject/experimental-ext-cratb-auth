# SPDX-License-Identifier: Apache-2.0
"""Kitchen x401 Authorization Server implementation.

Provides RFC 8693 token exchange for SD-JWT verifiable presentations.
Issues scoped Bearer tokens mapped to DCQL query satisfaction.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

import jwt
from pydantic import BaseModel, Field

from a2a_agentic_id.verifier import CredentialVerificationError, SDJWTVerifier
from restaurant_domain.x401 import (
    RESULT_ARTIFACT_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT_TYPE,
    decode_result_artifact,
    extract_vp_token,
)

from common.config import KITCHEN_AS_ISSUER, KITCHEN_AS_JWT_SECRET
from common.exchange_log import log
from common.identity import RESTAURANT_ISSUER, trusted_keys
from common.kitchen_scopes import DCQL_SCOPE_MAPPING, dcql_scope_mapping_json

_NONCE_TTL_SECONDS = 120.0


class TokenExchangeError(Exception):
    """Raised for token exchange errors."""

    def __init__(self, oauth_error: str, message: str) -> None:
        super().__init__(message)
        self.oauth_error = oauth_error
        self.message = message


class TokenExchangeRequest(BaseModel):
    """RFC 8693 Token Exchange request body."""

    grant_type: str = TOKEN_EXCHANGE_GRANT_TYPE
    subject_token_type: str = RESULT_ARTIFACT_TOKEN_TYPE
    subject_token: str
    nonce: str = Field(..., description="Single-use nonce bound to VP.")
    resource: Optional[str] = None


class KitchenOAuthAS:
    """RFC 8693 Token Exchange Authorization Server."""

    def __init__(
        self,
        issuer: str = KITCHEN_AS_ISSUER,
        jwt_signing_key: str = KITCHEN_AS_JWT_SECRET,
        verifier: Optional[SDJWTVerifier] = None,
    ) -> None:
        self.issuer = issuer
        self.jwt_signing_key = jwt_signing_key
        self.verifier = verifier or SDJWTVerifier(
            client_id=issuer,
            jwks_resolver=trusted_keys(RESTAURANT_ISSUER),
        )
        self._outstanding_nonces: Dict[str, float] = {}

    def get_server_metadata(self) -> Dict[str, Any]:
        """Return OAuth 2.0 authorization server metadata."""
        return {
            "issuer": self.issuer,
            "nonce_endpoint": f"{self.issuer}/nonce",
            "token_endpoint": f"{self.issuer}/token",
            "grant_types_supported": [TOKEN_EXCHANGE_GRANT_TYPE],
            "dcql_scope_mapping": dcql_scope_mapping_json(),
        }

    def issue_nonce(self) -> str:
        """Issue a single-use nonce."""
        import secrets

        self._prune_expired_nonces()
        nonce = secrets.token_urlsafe(16)
        self._outstanding_nonces[nonce] = time.time() + _NONCE_TTL_SECONDS
        log("kitchen_as", f"nonce issued: {nonce} (ttl={int(_NONCE_TTL_SECONDS)}s)")
        return nonce

    def _prune_expired_nonces(self) -> None:
        """Remove expired nonces from memory."""
        now = time.time()
        expired = [n for n, exp in self._outstanding_nonces.items() if exp < now]
        for n in expired:
            del self._outstanding_nonces[n]

    def _consume_nonce(self, nonce: str) -> None:
        """Validate and consume a single-use nonce."""
        self._prune_expired_nonces()
        if nonce not in self._outstanding_nonces:
            log("kitchen_as", f"nonce validation failed: {nonce!r} (unknown, expired, or reused)")
            raise TokenExchangeError(
                "invalid_grant", f"Unknown, expired, or consumed nonce: {nonce!r}"
            )
        del self._outstanding_nonces[nonce]

    def _scopes_granted(self, vp_token: Dict[str, Any], nonce: str) -> Tuple[List[str], Optional[str]]:
        """Evaluate presented VP against published DCQL scope requirements."""
        granted: List[str] = []
        subject: Optional[str] = None
        for scope, dcql_query in DCQL_SCOPE_MAPPING.items():
            cred_query = dcql_query.credentials[0]
            presentations = vp_token.get(cred_query.id, [])
            if not presentations:
                log("kitchen_as", f"scope {scope!r}: no presentations found -> not satisfied")
                continue
            try:
                result = self.verifier.verify_presentation(
                    presentation_str=presentations[0],
                    nonce=nonce,
                    dcql_query=dcql_query,
                )
            except CredentialVerificationError as exc:
                log("kitchen_as", f"scope {scope!r}: verification error ({exc}) -> not satisfied")
                continue
            granted.append(scope)
            log("kitchen_as", f"scope {scope!r}: DCQL satisfied -> GRANTED")
            subject = result.id_claim or subject
        return granted, subject

    def token_exchange(self, request: TokenExchangeRequest) -> Dict[str, Any]:
        """Validate token exchange request and issue scoped JWT."""
        if request.grant_type != TOKEN_EXCHANGE_GRANT_TYPE:
            log("kitchen_as", f"token exchange rejected: unsupported grant_type {request.grant_type!r}")
            raise TokenExchangeError("unsupported_grant_type", f"Unsupported grant_type: {request.grant_type!r}")
        if request.subject_token_type != RESULT_ARTIFACT_TOKEN_TYPE:
            log("kitchen_as", f"token exchange rejected: unsupported subject_token_type {request.subject_token_type!r}")
            raise TokenExchangeError(
                "invalid_request",
                f"Unsupported subject_token_type: {request.subject_token_type!r}; expected {RESULT_ARTIFACT_TOKEN_TYPE!r}",
            )

        try:
            vp_token = extract_vp_token(decode_result_artifact(request.subject_token))
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            log("kitchen_as", f"token exchange rejected: invalid Result Artifact: {exc}")
            raise TokenExchangeError("invalid_request", f"subject_token is not a valid Result Artifact: {exc}")

        self._consume_nonce(request.nonce)
        scopes, subject = self._scopes_granted(vp_token, request.nonce)
        if not scopes:
            log("kitchen_as", "token exchange rejected: no scopes satisfied by presented VP")
            raise TokenExchangeError(
                "invalid_grant", "Presented VP satisfies no published Kitchen scope DCQL requirement"
            )

        now = int(time.time())
        scope_str = " ".join(scopes)
        log("kitchen_as", f"token issued: sub={subject!r} scope={scope_str!r}")
        access_token_payload: Dict[str, Any] = {
            "iss": self.issuer,
            "iat": now,
            "exp": now + 3600,
            "scope": scope_str,
            "sub": subject,
        }
        if request.resource:
            access_token_payload["aud"] = request.resource

        access_token = jwt.encode(access_token_payload, key=self.jwt_signing_key, algorithm="HS256")
        return {
            "access_token": access_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope_str,
        }
