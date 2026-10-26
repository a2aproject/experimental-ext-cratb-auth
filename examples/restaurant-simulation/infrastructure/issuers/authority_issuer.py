# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, Optional

from a2a_agentic_id import (
    SDJWTWallet,
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
)


class RestaurantAuthorityIssuerService:
    """
    Root Authority Issuer (Stage 3) responsible for issuing VerifiedRestaurantCredential SD-JWTs
    to legitimate restaurant establishments. Serves as the root of trust for Customer Agents.
    """
    def __init__(
        self,
        issuer_url: str = "https://authority.example.com",
    ) -> None:
        self.issuer_url = issuer_url
        priv_key, pub_key = generate_ec_p256_keypair()
        self.authority_priv_jwk = export_jwk_from_private_key(priv_key)
        self.authority_pub_jwk = export_jwk_from_public_key(pub_key)

    def get_public_jwk(self) -> Dict[str, Any]:
        return self.authority_pub_jwk

    def issue_restaurant_credential(
        self,
        restaurant_url: str,
        restaurant_id: str,
        legal_name: str,
        health_rating: str,
        licence_number: str,
        holder_pub_jwk: Dict[str, Any],
        expires_in_seconds: int = 31536000,  # 1 year default
    ) -> Dict[str, Any]:
        """
        Issues a VerifiedRestaurantCredential SD-JWT bound to the Restaurant Issuer's public key.
        """
        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.authority_priv_jwk,
            iss=self.issuer_url,
            vct="https://example.com/credentials/VerifiedRestaurantCredential/v1",
            id_claim=restaurant_url,
            plaintext_claims={
                "restaurant_id": restaurant_id,
            },
            sd_claims={
                "legal_name": legal_name,
                "health_rating": health_rating,
                "licence_number": licence_number,
            },
            holder_public_key_jwk=holder_pub_jwk,
            expires_in_seconds=expires_in_seconds,
        )

        return {
            "id": restaurant_url,
            "restaurant_id": restaurant_id,
            "sd_jwt_string": sd_jwt_str,
        }
