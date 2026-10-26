# SPDX-License-Identifier: Apache-2.0
"""Restaurant demo domain credentials (order commitment, ingredient substitution).

These are application-profile objects for the restaurant demos, not part of the
core `a2a_agentic_id` SDK protocol surface.
"""

from .order import OrderState, OrderPaymentCommitment, OrderCommitmentSigner
from .substitution import IngredientSubstitutionApproval, SubstitutionIssuer

__all__ = [
    "OrderState",
    "OrderPaymentCommitment",
    "OrderCommitmentSigner",
    "IngredientSubstitutionApproval",
    "SubstitutionIssuer",
]
