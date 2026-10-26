# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, Optional
import time

from a2a_agentic_id import (
    DCQLQuery,
    DCQLCredentialQuery,
    DCQLClaimQuery,
    ErrorCode,
    SDJWTWallet,
    SDJWTVerifier,
    CredentialItem,
    TokenStatusListClient,
)
from a2a_agentic_id.interceptor import (
    ServerAuthRequiredInterceptor,
    A2ATaskMessage,
    A2ATaskStatusResponse,
    EXTENSION_URI,
)
from a2a_agentic_id.verifier import VerificationResult

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure")))

from kitchen_mcp.server import KitchenMCPServer, KitchenError
from kitchen_oauth_as.server import KitchenOAuthAS, TokenExchangeRequest


class ChefAgent:
    """
    Chef Autonomous Agent (Stage 2).
    Acts as an A2A Server verifying employee credentials of calling agents (e.g. FoH),
    and as an OAuth client to the Kitchen MCP Server.
    """
    def __init__(
        self,
        agent_url: str = "https://chef.example.com/a2a",
        restaurant_issuer_pub_jwk: Optional[Dict[str, Any]] = None,
        tsl_client: Optional[TokenStatusListClient] = None,
        kitchen_oauth_as: Optional[KitchenOAuthAS] = None,
        kitchen_mcp_server: Optional[KitchenMCPServer] = None,
    ) -> None:
        self.agent_url = agent_url
        self.restaurant_issuer_pub_jwk = restaurant_issuer_pub_jwk or {}
        self.tsl_client = tsl_client or TokenStatusListClient()
        self.kitchen_oauth_as = kitchen_oauth_as
        self.kitchen_mcp_server = kitchen_mcp_server

        self.wallet = SDJWTWallet()

        # Requires caller to hold an employee credential (either foh or chef)
        dcql_query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="emp_cred",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://example.com/credentials/RestaurantEmployeeCredential/v1"]},
                    claims=[
                        DCQLClaimQuery(path=["name"]),
                        DCQLClaimQuery(path=["role"], values=["foh", "chef"]),
                    ],
                )
            ]
        )

        self.verifier = SDJWTVerifier(
            client_id=agent_url,
            jwks_resolver=lambda iss: self.restaurant_issuer_pub_jwk,
            tsl_client=self.tsl_client,
        )

        self.interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            dcql_query=dcql_query,
            issuer_public_key_jwk=self.restaurant_issuer_pub_jwk,
        )

    def set_own_credentials(
        self, agent_id_cred: CredentialItem, emp_cred: CredentialItem
    ) -> None:
        self.wallet.add_credential(agent_id_cred)
        self.wallet.add_credential(emp_cred)

    def handle_message(self, request: A2ATaskMessage) -> A2ATaskStatusResponse:
        """
        Entrypoint for incoming A2A message/send requests.
        """
        return self.interceptor.process_incoming_request(request, self._process_authenticated_order)

    def cancel_task(self, task_id: str) -> None:
        """Discards the Authenticated Task Session for a task canceled out-of-band (spec 5.5 item 4)."""
        self.interceptor.close_task_session(task_id)

    def _process_authenticated_order(
        self,
        request: A2ATaskMessage,
        verification_result: Optional[VerificationResult],
    ) -> A2ATaskStatusResponse:
        """
        Executes order processing after A2A AUTH_REQUIRED verification succeeds.
        """
        if not verification_result:
            return A2ATaskStatusResponse(
                id=request.id,
                context_id=request.context_id,
                state="TASK_STATE_FAILED",
                message={
                    "role": "ROLE_AGENT",
                    "parts": [{"text": "Missing verification result"}],
                    "metadata": {EXTENSION_URI: {"status": "failed", "error": ErrorCode.VP_MISSING.value}},
                },
            )

        # Extract order text from request parts
        order_text = ""
        for p in request.parts:
            if "text" in p:
                order_text += p.get("text", "")

        dish_name = order_text.replace("Order:", "").strip() if "Order:" in order_text else order_text.strip()
        if not dish_name:
            dish_name = "Grilled Cheese"

        # Stage 4: Verify OrderPaymentCommitment if present in metadata
        commitment_jwt = request.metadata.get("order_commitment_jwt")
        if commitment_jwt:
            from restaurant_domain import OrderCommitmentSigner
            customer_jwk = request.metadata.get("customer_pub_jwk")
            if not customer_jwk:
                return A2ATaskStatusResponse(
                    id=request.id,
                    context_id=request.context_id,
                    state="TASK_STATE_FAILED",
                    message={
                        "role": "ROLE_AGENT",
                        "parts": [{"text": "Missing customer_pub_jwk for order commitment verification"}],
                        "metadata": {EXTENSION_URI: {"status": "failed", "error": ErrorCode.VP_SIGNATURE_INVALID.value}},
                    },
                )
            try:
                OrderCommitmentSigner.verify_commitment(
                    signed_jwt_str=commitment_jwt,
                    holder_public_key_jwk=customer_jwk,
                    expected_order_id=request.metadata.get("order_id"),
                    min_amount_cents=1000,
                )
            except Exception as e:
                return A2ATaskStatusResponse(
                    id=request.id,
                    context_id=request.context_id,
                    state="TASK_STATE_FAILED",
                    message={
                        "role": "ROLE_AGENT",
                        "parts": [{"text": f"Payment commitment verification failed: {str(e)}"}],
                        "metadata": {EXTENSION_URI: {"status": "failed", "error": ErrorCode.VP_SIGNATURE_INVALID.value}},
                    },
                )

        # Determine ingredients for dish
        ingredients = ["cheese", "gluten_free_bread", "butter"]

        # Stage 5: Check if an approved substitution VP was presented
        # Spec 9.6 / 12.6.1: presentations arrive in the extension-namespaced vp_token,
        # keyed by DCQL credential id.
        ext_meta = request.metadata.get(EXTENSION_URI, {})
        vp_token = ext_meta.get("vp_token", {}) or {}
        sub_vp_token = {"sub_approval": vp_token["sub_approval"]} if "sub_approval" in vp_token else None
        if sub_vp_token:
            customer_jwk = request.metadata.get("customer_pub_jwk")
            if not customer_jwk:
                return A2ATaskStatusResponse(
                    id=request.id,
                    context_id=request.context_id,
                    state="TASK_STATE_FAILED",
                    message={
                        "role": "ROLE_AGENT",
                        "parts": [{"text": "Missing customer_pub_jwk for substitution verification"}],
                        "metadata": {EXTENSION_URI: {"status": "failed", "error": ErrorCode.VP_SIGNATURE_INVALID.value}},
                    },
                )
            sub_verifier = SDJWTVerifier(
                client_id=self.agent_url,
                jwks_resolver=lambda iss: customer_jwk,
                tsl_client=self.tsl_client,
            )
            try:
                sub_query = DCQLQuery(
                    credentials=[
                        DCQLCredentialQuery(
                            id="sub_approval",
                            meta={"vct_values": ["https://example.com/credentials/IngredientSubstitutionApproval/v1"]},
                            claims=[
                                DCQLClaimQuery(path=["original_ingredient"]),
                                DCQLClaimQuery(path=["substitute_ingredient"]),
                            ],
                        )
                    ]
                )
                vp_str = sub_vp_token["sub_approval"][0]
                # Verify against the fresh nonce this Chef issued via issue_step_up_challenge,
                # not a hardcoded literal (Section 12.1: distinct outstanding nonce per challenge).
                res_sub = self.interceptor.verify_step_up_response(
                    task_id=request.id,
                    context_id=request.context_id,
                    vp_str=vp_str,
                    dcql_query=sub_query,
                    issuer_public_key_jwk=customer_jwk,
                    verifier=sub_verifier,
                )
                if res_sub.disclosed_claims.get("substitute_ingredient") == "gluten_free_tortilla":
                    ingredients = ["cheese", "gluten_free_tortilla", "butter"]
                    dish_name = f"{dish_name} (GF Tortilla substitution)"
            except Exception as e:
                return A2ATaskStatusResponse(
                    id=request.id,
                    context_id=request.context_id,
                    state="TASK_STATE_FAILED",
                    message={
                        "role": "ROLE_AGENT",
                        "parts": [{"text": f"Substitution VC verification failed: {str(e)}"}],
                        "metadata": {EXTENSION_URI: {"status": "failed", "error": ErrorCode.VP_SIGNATURE_INVALID.value}},
                    },
                )

        # Call Kitchen MCP Server using Chef's own EmployeeCredential via OAuth AS
        try:
            if self.kitchen_oauth_as and self.kitchen_mcp_server:
                emp_cred_item = self.wallet.get_credential("emp_cred")
                if not emp_cred_item:
                    raise KitchenError("Chef agent is missing its own emp_cred in wallet")

                # Build VP token for Kitchen AS
                query = DCQLQuery(
                    credentials=[
                        DCQLCredentialQuery(
                            id="emp_cred",
                            meta={"vct_values": ["https://example.com/credentials/RestaurantEmployeeCredential/v1"]},
                            claims=[DCQLClaimQuery(path=["role"], values=["chef"])],
                        )
                    ]
                )
                vp_resp = self.wallet.create_vp_token(
                    dcql_query=query,
                    nonce="chef-oauth-nonce",
                    client_id=self.kitchen_oauth_as.issuer,
                )

                from restaurant_domain.x401 import build_result_artifact, encode_result_artifact

                token_resp = self.kitchen_oauth_as.token_exchange(
                    TokenExchangeRequest(
                        subject_token=encode_result_artifact(
                            build_result_artifact(vp_resp.vp_token)
                        ),
                        scope="kitchen:appliances:use",
                        nonce="chef-oauth-nonce",
                    )
                )

                auth_header = f"Bearer {token_resp['access_token']}"
                dish_result = self.kitchen_mcp_server.prepare_dish(
                    dish_name=dish_name,
                    ingredients=ingredients,
                    auth_header=auth_header,
                )
                status_text = f"Dish '{dish_name}' prepared successfully for verified employee '{verification_result.disclosed_claims.get('name')}'."
            else:
                status_text = f"Dish '{dish_name}' accepted for verified employee '{verification_result.disclosed_claims.get('name')}'."
        except KitchenError as ke:
            if ke.status_code == 409 and "depleted" in ke.message and not sub_vp_token:
                # Stage 5 / Spec 5.5 item 3: emit a step-up challenge (reusing task_id/context_id,
                # via the interceptor's own nonce store) asking for IngredientSubstitutionApproval.
                sub_query = DCQLQuery(
                    credentials=[
                        DCQLCredentialQuery(
                            id="sub_approval",
                            meta={"vct_values": ["https://example.com/credentials/IngredientSubstitutionApproval/v1"]},
                            claims=[
                                DCQLClaimQuery(path=["original_ingredient"]),
                                DCQLClaimQuery(path=["substitute_ingredient"]),
                            ],
                        )
                    ]
                )
                challenge = self.interceptor.issue_step_up_challenge(
                    task_id=request.id,
                    dcql_query=sub_query,
                    client_id=self.agent_url,
                )
                return A2ATaskStatusResponse(
                    id=request.id,
                    context_id=request.context_id,
                    state="TASK_STATE_AUTH_REQUIRED",
                    message={
                        "role": "ROLE_AGENT",
                        "parts": [{"text": "Out of stock on 'gluten_free_bread'. Please provide an IngredientSubstitutionApproval credential to substitute 'gluten_free_tortilla'."}],
                        "metadata": {
                            EXTENSION_URI: challenge.model_dump(by_alias=True)
                        },
                    },
                )
            return A2ATaskStatusResponse(
                id=request.id,
                context_id=request.context_id,
                state="TASK_STATE_FAILED",
                message={
                    "role": "ROLE_AGENT",
                    "parts": [{"text": f"Kitchen error: {ke.message}"}],
                    "metadata": {},
                },
            )

        return A2ATaskStatusResponse(
            id=request.id,
            context_id=request.context_id,
            state="TASK_STATE_COMPLETED",
            message={
                "role": "ROLE_AGENT",
                "parts": [{"text": status_text}],
                "metadata": {
                    EXTENSION_URI: {
                        "status": "verified",
                        "presenter_role": verification_result.disclosed_claims.get("role"),
                    }
                },
            },
        )
