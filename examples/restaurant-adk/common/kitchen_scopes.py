# SPDX-License-Identifier: Apache-2.0
"""Mapping of kitchen OAuth scopes to DCQL credential requirements."""

from typing import Any, Dict

from a2a_agentic_id import DCQLClaimQuery, DCQLCredentialQuery, DCQLQuery

from common.identity import CHEF_ROLE, EMPLOYEE_CREDENTIAL_ID, EMPLOYEE_CREDENTIAL_TYPE, EMPLOYEE_ROLE_CLAIM, FOH_ROLE
from common.kitchen_api import KitchenScope

# DCQL query required to satisfy each Kitchen scope.
DCQL_SCOPE_MAPPING: Dict[str, DCQLQuery] = {
    KitchenScope.ENTER.value: DCQLQuery(
        credentials=[
            DCQLCredentialQuery(
                id=EMPLOYEE_CREDENTIAL_ID,
                format="dc+sd-jwt",
                meta={"vct_values": [EMPLOYEE_CREDENTIAL_TYPE]},
                claims=[DCQLClaimQuery(path=[EMPLOYEE_ROLE_CLAIM], values=[CHEF_ROLE, FOH_ROLE])],
            )
        ]
    ),
    KitchenScope.APPLIANCES_USE.value: DCQLQuery(
        credentials=[
            DCQLCredentialQuery(
                id=EMPLOYEE_CREDENTIAL_ID,
                format="dc+sd-jwt",
                meta={"vct_values": [EMPLOYEE_CREDENTIAL_TYPE]},
                claims=[DCQLClaimQuery(path=[EMPLOYEE_ROLE_CLAIM], values=[CHEF_ROLE])],
            )
        ]
    ),
}


def dcql_scope_mapping_json() -> Dict[str, Any]:
    """Return JSON serializable dictionary of DCQL scope mappings."""
    return {scope: query.model_dump() for scope, query in DCQL_SCOPE_MAPPING.items()}
