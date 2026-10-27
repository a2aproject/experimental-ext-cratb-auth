# SPDX-License-Identifier: Apache-2.0
"""Shared rules for the signed substitution consent credential.

The agent set by CONSENT_VERIFIER (common/config.py) uses these rules to
request and validate the IngredientSubstitutionApproval presentation.
"""

from typing import Optional

from a2a_agentic_id import DCQLClaimQuery, DCQLCredentialQuery, DCQLQuery
from a2a_agentic_id.verifier import VerificationResult

from common.identity import SUBSTITUTION_APPROVAL_CREDENTIAL_ID, SUBSTITUTION_APPROVAL_CREDENTIAL_TYPE

CONSENT_DCQL_QUERY = DCQLQuery(
    credentials=[
        DCQLCredentialQuery(
            id=SUBSTITUTION_APPROVAL_CREDENTIAL_ID,
            format="dc+sd-jwt",
            meta={"vct_values": [SUBSTITUTION_APPROVAL_CREDENTIAL_TYPE]},
            claims=[
                DCQLClaimQuery(path=["order_id"]),
                DCQLClaimQuery(path=["original_ingredient"]),
                DCQLClaimQuery(path=["substitute_ingredient"]),
            ],
        )
    ]
)


def consent_mismatch(
    result: VerificationResult,
    *,
    order_id: str,
    original: str,
    substitute: str,
) -> Optional[str]:
    """Compare verified consent claims with the pending order.

    Returns an error message if a claim is different. Returns None if all claims agree.
    """
    # order_id is a plaintext claim. The other claims are selective disclosures.
    claims = {**result.raw_issuer_jwt_payload, **result.disclosed_claims}
    expected = {
        "order_id": order_id,
        "original_ingredient": original,
        "substitute_ingredient": substitute,
    }
    for name, value in expected.items():
        if claims.get(name) != value:
            return f"Consent claim '{name}' is '{claims.get(name)}', expected '{value}'."
    return None
