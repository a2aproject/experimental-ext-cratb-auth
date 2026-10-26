# SPDX-License-Identifier: Apache-2.0
import time
from typing import Any, Dict, Optional
import jwt
from pydantic import BaseModel

from a2a_agentic_id.models import DCQLQuery, ErrorCode
from a2a_agentic_id.verifier import CredentialVerificationError, SDJWTVerifier
from restaurant_domain.x401 import (
    RESULT_ARTIFACT_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT_TYPE,
    decode_result_artifact,
    extract_vp_token,
)


class TokenExchangeRequest(BaseModel):
    grant_type: str = TOKEN_EXCHANGE_GRANT_TYPE
    subject_token_type: str = RESULT_ARTIFACT_TOKEN_TYPE
    subject_token: str
    scope: str
    nonce: str
    resource: Optional[str] = None


class KitchenOAuthAS:
    """
    OAuth 2.0 Authorization Server supporting dcql_scope_mapping and OID4VP Token Exchange.
    """
    def __init__(
        self,
        issuer: str = "http://localhost:8081",
        # Dev-only demo secret. Real deployments MUST provision >=32 bytes and inject via config.
        jwt_signing_key: str = "dev-only-demo-secret-change-me-32bytes-min",
        verifier: Optional[SDJWTVerifier] = None,
        jwks_resolver: Optional[Any] = None,
        tsl_client: Optional[Any] = None,
        allow_unverified_status: bool = False,
    ) -> None:
        self.issuer = issuer
        self.jwt_signing_key = jwt_signing_key
        self.verifier = verifier or SDJWTVerifier(
            client_id=issuer,
            jwks_resolver=jwks_resolver,
            tsl_client=tsl_client,
            allow_unverified_status=allow_unverified_status,
        )
        self.dcql_scope_mapping: Dict[str, Dict[str, Any]] = {
            "kitchen:enter": {
                "credentials": [
                    {
                        "id": "agent_identity",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                        "claims": [{"path": ["name"]}, {"path": ["owner"]}],
                    }
                ]
            },
            "kitchen:appliances:use": {
                "credentials": [
                    {
                        "id": "emp_cred",
                        "format": "dc+sd-jwt",
                        "meta": {"vct_values": ["https://example.com/credentials/RestaurantEmployeeCredential/v1"]},
                        "claims": [{"path": ["role"], "values": ["chef"]}],
                    }
                ]
            },
        }

    def get_server_metadata(self) -> Dict[str, Any]:
        return {
            "issuer": self.issuer,
            "token_endpoint": f"{self.issuer}/token/exchange",
            "dcql_scope_mapping": self.dcql_scope_mapping,
        }

    def token_exchange(self, request: TokenExchangeRequest) -> Dict[str, Any]:
        """
        Validates vp_token against the DCQL queries mapped to requested scopes and issues a Bearer JWT.
        """
        if request.subject_token_type != RESULT_ARTIFACT_TOKEN_TYPE:
            raise ValueError(
                f"Unsupported subject_token_type: {request.subject_token_type!r}; "
                f"expected {RESULT_ARTIFACT_TOKEN_TYPE!r}"
            )

        if request.grant_type != TOKEN_EXCHANGE_GRANT_TYPE:
            raise ValueError(f"Unsupported grant_type: {request.grant_type!r}")

        try:
            vp_token = extract_vp_token(decode_result_artifact(request.subject_token))
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                f"subject_token is not a decodable x401 Result Artifact: {exc}",
            )

        requested_scopes = request.scope.split()
        for sc in requested_scopes:
            if sc not in self.dcql_scope_mapping:
                raise ValueError(f"Unknown or unmapped scope: {sc}")

            query_dict = {"credentials": []}
            query_dict["credentials"].extend(self.dcql_scope_mapping[sc].get("credentials", []))
            dcql_query = DCQLQuery.model_validate(query_dict)

            # Check that vp_token satisfies this query
            for cred_query in dcql_query.credentials:
                pres_list = vp_token.get(cred_query.id, [])
                if not pres_list:
                    raise CredentialVerificationError(
                        ErrorCode.VP_DCQL_UNSATISFIED,
                        f"Missing required credential presentation for query ID '{cred_query.id}'",
                    )

                vp_str = pres_list[0]
                self.verifier.verify_presentation(
                    presentation_str=vp_str,
                    nonce=request.nonce,
                    dcql_query=dcql_query,
                )

        now = int(time.time())
        access_token_payload = {
            "iss": self.issuer,
            "iat": now,
            "exp": now + 3600,
            "scope": request.scope,
            "sub": "verified-agent",
        }
        if request.resource:
            access_token_payload["aud"] = request.resource

        access_token = jwt.encode(
            access_token_payload,
            key=self.jwt_signing_key,
            algorithm="HS256",
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": request.scope,
        }
