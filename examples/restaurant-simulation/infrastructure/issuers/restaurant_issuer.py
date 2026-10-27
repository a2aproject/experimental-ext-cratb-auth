# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, List, Optional
import time

from a2a_agentic_id import (
    SDJWTWallet,
    TokenStatusListClient,
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
)


class RestaurantIssuerService:
    """
    Enterprise Issuer responsible for issuing RestaurantEmployeeCredential SD-JWTs
    and maintaining a Token Status List (TSL) revocation service.
    """
    def __init__(
        self,
        issuer_url: str = "https://restaurant.example.com",
        restaurant_id: str = "rest-101",
    ) -> None:
        self.issuer_url = issuer_url
        self.restaurant_id = restaurant_id
        self.status_list_uri = f"{issuer_url}/status-list.jwt"

        priv_key, pub_key = generate_ec_p256_keypair()
        self.issuer_priv_jwk = export_jwk_from_private_key(priv_key)
        self.issuer_pub_jwk = export_jwk_from_public_key(pub_key)

        self.revoked_indices: List[int] = []
        self.next_status_idx: int = 0
        self.restaurant_credential: Optional[Dict[str, Any]] = None

    def set_restaurant_credential(self, cred_data: Dict[str, Any]) -> None:
        self.restaurant_credential = cred_data

    def get_restaurant_credential(self) -> Optional[Dict[str, Any]]:
        return self.restaurant_credential

    def get_public_jwk(self) -> Dict[str, Any]:
        return self.issuer_pub_jwk

    def get_status_list_jwt(self) -> str:
        """
        Returns a Token Status List JWT reflecting the current revoked_indices bit array.
        """
        return TokenStatusListClient.create_status_list_jwt(
            issuer_private_key_jwk=self.issuer_priv_jwk,
            iss=self.issuer_url,
            revoked_indices=self.revoked_indices,
        )

    def revoke_credential(self, idx: int) -> None:
        if idx not in self.revoked_indices:
            self.revoked_indices.append(idx)

    def issue_employee_credential(
        self,
        employee_id: str,
        name: str,
        role: str,  # "chef" or "foh"
        clearance_level: str,
        holder_pub_jwk: Dict[str, Any],
        expires_in_seconds: int = 86400,
    ) -> Dict[str, Any]:
        """
        Issues an EmployeeCredential SD-JWT and returns dict with sd_jwt_string and status_idx.
        """
        status_idx = self.next_status_idx
        self.next_status_idx += 1

        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.issuer_priv_jwk,
            iss=self.issuer_url,
            vct="https://example.com/credentials/RestaurantEmployeeCredential/v1",
            id_claim=employee_id,
            plaintext_claims={
                "restaurant_id": self.restaurant_id,
                "status": {
                    "status_list": {
                        "idx": status_idx,
                        "uri": self.status_list_uri,
                    }
                },
            },
            sd_claims={
                "name": name,
                "role": role,
                "clearance_level": clearance_level,
            },
            holder_public_key_jwk=holder_pub_jwk,
            expires_in_seconds=expires_in_seconds,
        )

        return {
            "id": employee_id,
            "role": role,
            "status_idx": status_idx,
            "sd_jwt_string": sd_jwt_str,
            "status_list_uri": self.status_list_uri,
        }
