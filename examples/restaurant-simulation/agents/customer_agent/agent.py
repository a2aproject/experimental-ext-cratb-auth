# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, Optional
import uuid

from a2a_agentic_id import (
    SDJWTWallet,
    SDJWTVerifier,
    TokenStatusListClient,
    CredentialItem,
    DCQLQuery,
    DCQLCredentialQuery,
    DCQLClaimQuery,
    ErrorCode,
)
from a2a_agentic_id.verifier import CredentialVerificationError, VerificationResult
from a2a_agentic_id.interceptor import A2ATaskMessage, A2ATaskStatusResponse, EXTENSION_URI


class CustomerError(Exception):
    def __init__(self, message: str, error_code: Optional[ErrorCode] = None) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class _TerminalAllowList:
    """Holder tunnel policy (spec 12.6.1): sign only for terminal verifiers named here."""

    def __init__(self, allowed) -> None:
        self.allowed = frozenset(allowed)

    def is_terminal_allowed(self, client_id: str) -> bool:
        return client_id in self.allowed


class CustomerAgent:
    """
    Customer Autonomous Agent (Stage 3).
    Verifies the Front-of-House (FoH) waitstaff through a transitive Chain of Trust
    (EmployeeCredential -> VerifiedRestaurantCredential -> Root Restaurant Authority).
    """
    def __init__(
        self,
        agent_url: str = "https://customer.example.com/a2a",
        authority_pub_jwk: Optional[Dict[str, Any]] = None,
        tsl_client: Optional[TokenStatusListClient] = None,
        allow_unverified_status: bool = False,
    ) -> None:
        self.agent_url = agent_url
        # Stands in for this client's authenticated transport connection (spec 5.5 item 2).
        self.channel_id = uuid.uuid4().hex
        self.authority_pub_jwk = authority_pub_jwk or {}
        self.tsl_client = tsl_client
        self.allow_unverified_status = allow_unverified_status
        self.wallet = SDJWTWallet()
        # Terminal verifiers this holder will sign for when a relay tunnels their challenge (12.6.1).
        self.trusted_terminals = {"https://chef.example.com/a2a"}

    def set_own_credential(self, agent_id_cred: CredentialItem) -> None:
        self.wallet.add_credential(agent_id_cred)

    def verify_restaurant_chain_of_trust(
        self,
        emp_presentation_str: str,
        restaurant_presentation_str: str,
        nonce: str,
        foh_client_id: str,
    ) -> Dict[str, Any]:
        """
        Executes chain-of-trust validation:
        1. Verifies VerifiedRestaurantCredential against Root Authority Public JWK.
        2. Extracts Restaurant Issuer public JWK from VerifiedRestaurantCredential cnf.jwk.
        3. Verifies RestaurantEmployeeCredential against extracted Restaurant Issuer JWK.
        4. Verifies restaurant_id alignment across both credentials.
        """
        # Step 1: Verify RestaurantCredential against Root Authority JWK
        auth_verifier = SDJWTVerifier(
            client_id=self.agent_url,
            jwks_resolver=lambda iss: self.authority_pub_jwk,
            tsl_client=self.tsl_client,
            allow_unverified_status=self.allow_unverified_status,
        )

        try:
            rest_res = auth_verifier.verify_presentation(
                presentation_str=restaurant_presentation_str,
                nonce=nonce,
                issuer_public_key_jwk=self.authority_pub_jwk,
            )
        except CredentialVerificationError as e:
            raise CustomerError(
                f"Restaurant legitimacy verification failed against Root Authority: {e.message}",
                error_code=e.error_code,
            )

        # Step 2: Extract Restaurant Issuer Public Key from cnf.jwk
        rest_cnf = rest_res.raw_issuer_jwt_payload.get("cnf", {})
        restaurant_issuer_jwk = rest_cnf.get("jwk")
        if not restaurant_issuer_jwk:
            raise CustomerError(
                "VerifiedRestaurantCredential missing issuer public key binding in cnf.jwk",
                error_code=ErrorCode.VP_FORMAT_UNSUPPORTED,
            )

        # Step 3: Verify EmployeeCredential against Restaurant Issuer JWK
        emp_verifier = SDJWTVerifier(
            client_id=self.agent_url,
            jwks_resolver=lambda iss: restaurant_issuer_jwk,
            tsl_client=self.tsl_client,
            allow_unverified_status=self.allow_unverified_status,
        )

        try:
            emp_res = emp_verifier.verify_presentation(
                presentation_str=emp_presentation_str,
                nonce=nonce,
                issuer_public_key_jwk=restaurant_issuer_jwk,
            )
        except CredentialVerificationError as e:
            raise CustomerError(
                f"Waitstaff EmployeeCredential verification failed against Restaurant key: {e.message}",
                error_code=e.error_code,
            )

        # Step 4: Verify restaurant_id alignment
        rest_id_root = rest_res.raw_issuer_jwt_payload.get("restaurant_id")
        emp_rest_id = emp_res.raw_issuer_jwt_payload.get("restaurant_id")
        if not rest_id_root or rest_id_root != emp_rest_id:
            raise CustomerError(
                f"Chain of trust mismatch: Restaurant ID '{rest_id_root}' does not match Employee Restaurant ID '{emp_rest_id}'",
                error_code=ErrorCode.VP_SIGNATURE_INVALID,
            )

        return {
            "chain_valid": True,
            "restaurant_name": rest_res.disclosed_claims.get("legal_name"),
            "health_rating": rest_res.disclosed_claims.get("health_rating"),
            "employee_name": emp_res.disclosed_claims.get("name"),
            "employee_role": emp_res.disclosed_claims.get("role"),
            "restaurant_id": rest_id_root,
        }

    def create_signed_payment_commitment(
        self,
        order_id: str,
        max_amount_cents: int = 1500,
        currency: str = "USD",
    ) -> str:
        """
        Signs an OrderPaymentCommitment using the customer's holder private key (cnf.jwk).
        """
        import time
        from restaurant_domain import OrderPaymentCommitment, OrderCommitmentSigner
        cred_item = self.wallet.get_credential("agent_identity")
        if not cred_item:
            raise CustomerError("Customer agent missing agent_identity credential in wallet")

        commitment = OrderPaymentCommitment(
            order_id=order_id,
            customer_id=self.agent_url,
            max_amount_cents=max_amount_cents,
            currency=currency,
            timestamp=int(time.time()),
        )
        return OrderCommitmentSigner.sign_commitment(
            commitment=commitment,
            holder_private_key_jwk=cred_item.holder_private_key_jwk,
        )

    def order_from_restaurant(
        self,
        foh_agent: Any,
        dish_name: str,
        task_id: Optional[str] = None,
        context_id: Optional[str] = None,
        order_commitment_jwt: Optional[str] = None,
        customer_pub_jwk: Optional[Dict[str, Any]] = None,
    ) -> A2ATaskStatusResponse:
        """
        Customer places an order with FoHAgent after verifying restaurant legitimacy.
        """
        t_id = task_id or str(uuid.uuid4())
        c_id = context_id or str(uuid.uuid4())

        # First obtain legitimacy attestation from FoHAgent
        nonce = "customer-challenge-nonce-001"
        attestation = foh_agent.provide_legitimacy_attestation(
            nonce=nonce,
            client_id=self.agent_url,
        )

        emp_vp = attestation.get("employee_presentation")
        rest_vp = attestation.get("restaurant_presentation")
        if not emp_vp or not rest_vp:
            raise CustomerError("Restaurant failed to provide both Employee and Restaurant credentials")

        trust_info = self.verify_restaurant_chain_of_trust(
            emp_presentation_str=emp_vp,
            restaurant_presentation_str=rest_vp,
            nonce=nonce,
            foh_client_id=foh_agent.agent_url,
        )

        # Transitive chain of trust verified! Send order to FoH Agent
        metadata_payload = {
            "customer_verified_restaurant": trust_info["restaurant_id"],
        }
        if order_commitment_jwt:
            metadata_payload["order_commitment_jwt"] = order_commitment_jwt
        if customer_pub_jwk:
            metadata_payload["customer_pub_jwk"] = customer_pub_jwk
        else:
            cred_item = self.wallet.get_credential("agent_identity")
            if cred_item and cred_item.holder_private_key_jwk:
                from a2a_agentic_id import export_jwk_from_public_key, import_private_key_from_jwk
                priv_key = import_private_key_from_jwk(cred_item.holder_private_key_jwk)
                metadata_payload["customer_pub_jwk"] = export_jwk_from_public_key(priv_key.public_key())

        # The business order reference travels in metadata. It is not the A2A task id: under A2A
        # v1.0.0 Section 3.4.2 task ids are server-generated, so the Chef allocates its own.
        metadata_payload["order_id"] = t_id
        order_req = A2ATaskMessage(
            channel_id=self.channel_id,
            context_id=c_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata=metadata_payload,
            parts=[{"text": f"Order: {dish_name}"}],
        )

        return foh_agent.handle_customer_order(order_req)

    def issue_substitution_approval_credential(
        self,
        order_id: str,
        original_ingredient: str,
        substitute_ingredient: str,
    ) -> str:
        """
        Dynamically issues an IngredientSubstitutionApproval SD-JWT signed by the customer's holder key.
        """
        from restaurant_domain import SubstitutionIssuer
        from a2a_agentic_id import export_jwk_from_private_key, export_jwk_from_public_key, import_private_key_from_jwk
        cred_item = self.wallet.get_credential("agent_identity")
        if not cred_item:
            raise CustomerError("Customer agent missing agent_identity credential in wallet")

        # Check dietary compliance rules
        allowed_substitutions = {
            "gluten_free_bread": ["gluten_free_tortilla", "lettuce_wrap"],
            "cheese": ["vegan_cheese"],
        }
        allowed = allowed_substitutions.get(original_ingredient, [])
        if substitute_ingredient not in allowed:
            raise CustomerError(
                f"Dietary restriction violation: cannot substitute '{substitute_ingredient}' for '{original_ingredient}'",
                error_code=ErrorCode.VP_DCQL_UNSATISFIED,
            )

        priv_key = import_private_key_from_jwk(cred_item.holder_private_key_jwk)
        pub_jwk = export_jwk_from_public_key(priv_key.public_key())

        sd_jwt_str = SubstitutionIssuer.issue_approval_credential(
            customer_private_key_jwk=cred_item.holder_private_key_jwk,
            customer_public_key_jwk=pub_jwk,
            customer_id=self.agent_url,
            order_id=order_id,
            original_ingredient=original_ingredient,
            substitute_ingredient=substitute_ingredient,
        )

        # Add dynamically issued credential to wallet
        self.wallet.add_credential(
            CredentialItem(
                id="sub_approval",
                sd_jwt_string=sd_jwt_str,
                holder_private_key_jwk=cred_item.holder_private_key_jwk,
            )
        )
        return sd_jwt_str

    def _parse_substitution_request(
        self, request: A2ATaskMessage, tunneled: Any
    ) -> tuple[str, str]:
        """
        Parses the ingredient substitution requested by the Terminal Verifier from message text parts.
        Matches against allowed substitutions policy table.
        """
        allowed_substitutions = {
            "gluten_free_bread": ["gluten_free_tortilla", "lettuce_wrap"],
            "cheese": ["vegan_cheese"],
        }
        text_content = ""
        for p in request.parts:
            if isinstance(p, dict) and "text" in p:
                text_content += p.get("text", "") + " "

        for orig, substitutes in allowed_substitutions.items():
            if orig in text_content:
                for sub in substitutes:
                    if sub in text_content:
                        return orig, sub

        raise CustomerError(
            f"Could not parse a valid supported ingredient substitution from challenge text: {text_content.strip()}",
            error_code=ErrorCode.VP_DCQL_UNSATISFIED,
        )

    def handle_tunneled_challenge(self, request: A2ATaskMessage) -> Dict[str, Any]:
        """
        Spec 12.6.1 Rules 2 & 3. Answers a challenge relayed by an Intermediate Agent, binding the
        KB-JWT to the Terminal Verifier's nonce and client_id from inside the envelope.
        Returns metadata carrying the tunneled_response.
        """
        from a2a_agentic_id import ClientAuthHandler, TunneledChallenge

        raw = request.metadata.get(EXTENSION_URI, {}).get("tunneled_challenge")
        if not raw:
            raise CustomerError("Message carries no tunneled_challenge envelope")
        tunneled = TunneledChallenge.model_validate(raw)

        # Derive the substitution from the challenge itself, not from the intermediate.
        original, substitute = self._parse_substitution_request(request, tunneled)
        self.issue_substitution_approval_credential(
            order_id=tunneled.origin_task_id,
            original_ingredient=original,
            substitute_ingredient=substitute,
        )

        handler = ClientAuthHandler(wallet=self.wallet)
        return handler.handle_tunneled_challenge(
            tunneled=tunneled,
            conversation_id=request.context_id,
            tunnel_policy=_TerminalAllowList(self.trusted_terminals),
        )

    def handle_substitution_request(
        self,
        dcql_query: Any,
        nonce: str,
        client_id: str,
        order_id: str,
        original_ingredient: str,
        substitute_ingredient: str,
    ) -> Dict[str, Any]:
        """
        Evaluates an ingredient substitution request, dynamically issues the approval VC,
        and generates an IdentityResponse vp_token.
        """
        self.issue_substitution_approval_credential(
            order_id=order_id,
            original_ingredient=original_ingredient,
            substitute_ingredient=substitute_ingredient,
        )

        vp_response = self.wallet.create_vp_token(
            dcql_query=dcql_query,
            nonce=nonce,
            client_id=client_id,
        )
        return {
            EXTENSION_URI: vp_response.model_dump(by_alias=True)
        }
