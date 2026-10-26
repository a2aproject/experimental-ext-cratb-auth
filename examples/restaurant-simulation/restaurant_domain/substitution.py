# SPDX-License-Identifier: Apache-2.0
import time
from typing import Any, Dict, Optional
from pydantic import BaseModel

from a2a_agentic_id.wallet import SDJWTWallet


class IngredientSubstitutionApproval(BaseModel):
    """
    Dynamically issued SD-JWT credential authorizing an ingredient substitution (Stage 5).
    """
    order_id: str
    customer_id: str
    original_ingredient: str
    substitute_ingredient: str
    timestamp: int


class SubstitutionIssuer:
    """
    Utility for Customer Agents to dynamically issue conformant IngredientSubstitutionApproval SD-JWTs
    signed by their own holder private key (cnf.jwk).
    """
    @staticmethod
    def issue_approval_credential(
        customer_private_key_jwk: Dict[str, Any],
        customer_public_key_jwk: Dict[str, Any],
        customer_id: str,
        order_id: str,
        original_ingredient: str,
        substitute_ingredient: str,
        expires_in_seconds: int = 3600,
    ) -> str:
        """
        Issues an IngredientSubstitutionApproval SD-JWT where customer is both issuer and holder.
        """
        now = int(time.time())
        return SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=customer_private_key_jwk,
            iss=customer_id,
            vct="https://example.com/credentials/IngredientSubstitutionApproval/v1",
            id_claim=order_id,
            plaintext_claims={
                "order_id": order_id,
                "customer_id": customer_id,
            },
            sd_claims={
                "original_ingredient": original_ingredient,
                "substitute_ingredient": substitute_ingredient,
            },
            holder_public_key_jwk=customer_public_key_jwk,
            expires_in_seconds=expires_in_seconds,
        )
