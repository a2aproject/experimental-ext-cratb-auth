# SPDX-License-Identifier: Apache-2.0
import time
from enum import Enum
from typing import Any, Dict, Optional
import jwt
from pydantic import BaseModel

from a2a_agentic_id.crypto import (
    import_private_key_from_jwk,
    import_public_key_from_jwk,
)


class OrderState(str, Enum):
    CREATED = "CREATED"
    CONFIRMED = "CONFIRMED"
    PREPARING = "PREPARING"
    SERVED = "SERVED"
    PAID = "PAID"


class OrderPaymentCommitment(BaseModel):
    """
    Customer cryptographic payment commitment per Stage 4 specification.
    """
    order_id: str
    customer_id: str
    max_amount_cents: int = 1500
    currency: str = "USD"
    timestamp: int


class OrderCommitmentSigner:
    """
    Utility for signing and verifying OrderPaymentCommitments using holder EC P-256 keys (cnf.jwk).
    """
    @staticmethod
    def sign_commitment(
        commitment: OrderPaymentCommitment,
        holder_private_key_jwk: Dict[str, Any],
    ) -> str:
        """
        Signs the commitment as an ES256 compact JWS string.
        """
        priv_key = import_private_key_from_jwk(holder_private_key_jwk)
        from cryptography.hazmat.primitives import serialization
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        payload = commitment.model_dump()
        return jwt.encode(
            payload=payload,
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "order-commitment+jwt"},
        )

    @staticmethod
    def verify_commitment(
        signed_jwt_str: str,
        holder_public_key_jwk: Dict[str, Any],
        expected_order_id: Optional[str] = None,
        min_amount_cents: Optional[int] = None,
    ) -> OrderPaymentCommitment:
        """
        Verifies the ES256 signature on a signed commitment using the customer's holder public key (cnf.jwk).
        """
        pub_key = import_public_key_from_jwk(holder_public_key_jwk)
        from cryptography.hazmat.primitives import serialization
        pem_pub_key = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        try:
            payload = jwt.decode(
                signed_jwt_str,
                key=pem_pub_key,
                algorithms=["ES256"],
                options={"verify_aud": False},
            )
        except Exception as e:
            raise ValueError(f"Invalid OrderPaymentCommitment signature: {str(e)}")

        commitment = OrderPaymentCommitment.model_validate(payload)
        if expected_order_id and commitment.order_id != expected_order_id:
            raise ValueError(
                f"Commitment order_id '{commitment.order_id}' does not match expected '{expected_order_id}'"
            )
        if min_amount_cents is not None and commitment.max_amount_cents < min_amount_cents:
            raise ValueError(
                f"Commitment amount {commitment.max_amount_cents} cents is below required {min_amount_cents} cents"
            )

        return commitment
