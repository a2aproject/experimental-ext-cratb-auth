# SPDX-License-Identifier: Apache-2.0
import unittest
import sys
import os
from typing import Any, Dict

from a2a_agentic_id import (
    SDJWTWallet,
    CredentialItem,
    TokenStatusListClient,
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    ErrorCode,
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../agents")))

from issuers.authority_issuer import RestaurantAuthorityIssuerService
from issuers.restaurant_issuer import RestaurantIssuerService
from kitchen_mcp.server import KitchenMCPServer
from kitchen_oauth_as.server import KitchenOAuthAS
from chef_agent.agent import ChefAgent
from foh_agent.agent import FoHAgent
from customer_agent.agent import CustomerAgent, CustomerError


class TestStage5DynamicSubstitutionIssuance(unittest.TestCase):
    def setUp(self) -> None:
        self.authority_issuer = RestaurantAuthorityIssuerService(
            issuer_url="https://authority.example.com",
        )
        self.restaurant_issuer = RestaurantIssuerService(
            issuer_url="https://restaurant.example.com",
            restaurant_id="rest-101",
        )
        self.rest_cred_data = self.authority_issuer.issue_restaurant_credential(
            restaurant_url="https://restaurant.example.com",
            restaurant_id="rest-101",
            legal_name="Google Gourmet Bistro",
            health_rating="A+",
            licence_number="LIC-2026-8890",
            holder_pub_jwk=self.restaurant_issuer.get_public_jwk(),
        )

        self.tsl_client = TokenStatusListClient()
        self.tsl_client.register_status_list_jwt(
            uri="https://restaurant.example.com/status-list.jwt",
            jwt_str=self.restaurant_issuer.get_status_list_jwt(),
            issuer_public_key_jwk=self.restaurant_issuer.get_public_jwk(),
        )

        self.kitchen_mcp = KitchenMCPServer()
        self.kitchen_as = KitchenOAuthAS(
            issuer="http://localhost:8081",
            jwks_resolver=lambda iss: self.restaurant_issuer.get_public_jwk(),
            tsl_client=self.tsl_client,
        )

        self.chef_agent = ChefAgent(
            agent_url="https://chef.example.com/a2a",
            restaurant_issuer_pub_jwk=self.restaurant_issuer.get_public_jwk(),
            tsl_client=self.tsl_client,
            kitchen_oauth_as=self.kitchen_as,
            kitchen_mcp_server=self.kitchen_mcp,
        )

        self.foh_agent = FoHAgent(
            agent_url="https://foh.example.com/a2a",
        )
        self.foh_agent.set_chef_agent(self.chef_agent)

        self.customer_agent = CustomerAgent(
            agent_url="https://customer.example.com/a2a",
            authority_pub_jwk=self.authority_issuer.get_public_jwk(),
            tsl_client=self.tsl_client,
        )
        self.foh_agent.set_customer_agent(self.customer_agent)

        # Generate holder keys
        self.chef_priv, self.chef_pub = generate_ec_p256_keypair()
        self.foh_priv, self.foh_pub = generate_ec_p256_keypair()
        self.cust_priv, self.cust_pub = generate_ec_p256_keypair()

        self.chef_holder_jwk = export_jwk_from_private_key(self.chef_priv)
        self.foh_holder_jwk = export_jwk_from_private_key(self.foh_priv)
        self.cust_holder_jwk = export_jwk_from_private_key(self.cust_priv)
        self.cust_pub_jwk = export_jwk_from_public_key(self.cust_pub)

        # Equip Customer Agent
        cust_sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.authority_issuer.authority_priv_jwk,
            iss="https://authority.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/customer-1",
            plaintext_claims={},
            sd_claims={"name": "Bob Diner", "description": "Customer dining bot"},
            holder_public_key_jwk=self.cust_pub_jwk,
        )
        self.customer_agent.set_own_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=cust_sd_jwt,
                holder_private_key_jwk=self.cust_holder_jwk,
            )
        )

        # Issue employee credentials
        self.chef_cred = self.restaurant_issuer.issue_employee_credential(
            employee_id="https://agents.example.com/chef-bot",
            name="Chef Bot 3000",
            role="chef",
            clearance_level="high",
            holder_pub_jwk=export_jwk_from_public_key(self.chef_pub),
        )

        self.foh_cred = self.restaurant_issuer.issue_employee_credential(
            employee_id="https://agents.example.com/foh-bot",
            name="Alice Waitstaff",
            role="foh",
            clearance_level="medium",
            holder_pub_jwk=export_jwk_from_public_key(self.foh_pub),
        )

        self.chef_agent.set_own_credentials(
            agent_id_cred=CredentialItem(
                id="agent_identity",
                sd_jwt_string=self.chef_cred["sd_jwt_string"],
                holder_private_key_jwk=self.chef_holder_jwk,
            ),
            emp_cred=CredentialItem(
                id="emp_cred",
                sd_jwt_string=self.chef_cred["sd_jwt_string"],
                holder_private_key_jwk=self.chef_holder_jwk,
            ),
        )

        self.foh_agent.set_own_credentials(
            agent_id_cred=CredentialItem(
                id="agent_identity",
                sd_jwt_string=self.foh_cred["sd_jwt_string"],
                holder_private_key_jwk=self.foh_holder_jwk,
            ),
            emp_cred=CredentialItem(
                id="emp_cred",
                sd_jwt_string=self.foh_cred["sd_jwt_string"],
                holder_private_key_jwk=self.foh_holder_jwk,
            ),
            rest_cred=CredentialItem(
                id="rest_cred",
                sd_jwt_string=self.rest_cred_data["sd_jwt_string"],
                holder_private_key_jwk=self.restaurant_issuer.issuer_priv_jwk,
            ),
        )

    def test_01_ingredient_depletion_triggers_dynamic_substitution_vc(self) -> None:
        # Simulate inventory depletion on gluten_free_bread
        self.kitchen_mcp.state.ingredients["gluten_free_bread"] = 0
        initial_tortillas = self.kitchen_mcp.state.ingredients["gluten_free_tortilla"]

        response = self.customer_agent.order_from_restaurant(
            foh_agent=self.foh_agent,
            dish_name="Grilled Cheese",
            task_id="sub-order-501",
            context_id="dining-session-5",
            customer_pub_jwk=self.cust_pub_jwk,
        )

        self.assertEqual(response.state, "TASK_STATE_COMPLETED")
        self.assertIn("GF Tortilla substitution", response.message["parts"][0]["text"])

        # Verify tortilla inventory decremented
        self.assertEqual(
            self.kitchen_mcp.state.ingredients["gluten_free_tortilla"],
            initial_tortillas - 1,
        )
        # Verify prepared_dishes recorded the substitution dish
        self.assertEqual(
            self.kitchen_mcp.state.prepared_dishes[-1]["dish_name"],
            "Grilled Cheese (GF Tortilla substitution)",
        )

    def test_02_unauthorized_dietary_substitution_rejected_by_customer(self) -> None:
        # Test dietary restriction rules in Customer Agent
        with self.assertRaises(CustomerError) as ctx:
            self.customer_agent.issue_substitution_approval_credential(
                order_id="sub-order-502",
                original_ingredient="gluten_free_bread",
                substitute_ingredient="regular_wheat_bread",
            )

        self.assertIn("Dietary restriction violation: cannot substitute 'regular_wheat_bread'", str(ctx.exception))
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)

    def test_tunneled_challenge_envelope_conformance(self) -> None:
        """Spec 12.6.1: the multi-hop substitution flow MUST use tunneled_challenge/tunneled_response."""
        import jwt as _jwt
        from a2a_agentic_id import TunneledChallenge, TunneledResponse, EXTENSION_URI

        captured = {}

        # Intercept the envelope the FoH hands to the Customer.
        original = self.customer_agent.handle_tunneled_challenge

        def spy(request):
            captured["challenge_msg"] = request
            out = original(request)
            captured["response_meta"] = out
            return out

        self.customer_agent.handle_tunneled_challenge = spy

        self.kitchen_mcp.state.ingredients["gluten_free_bread"] = 0
        response = self.customer_agent.order_from_restaurant(
            foh_agent=self.foh_agent,
            dish_name="Grilled Cheese",
            task_id="ord-tunnel-01",
        )

        # Rule 1: a well-formed tunneled_challenge reached the Holder.
        ext = captured["challenge_msg"].metadata[EXTENSION_URI]
        tunneled = TunneledChallenge.model_validate(ext["tunneled_challenge"])
        # origin_task_id is the Terminal Verifier's own Task2 id (spec 12.6.1 Rule 1). A2A v1.0.0
        # makes task ids server-generated, so it is the id the Chef allocated, not the business
        # order reference ("ord-tunnel-01") the customer used.
        origin_task_id = tunneled.origin_task_id
        self.assertNotEqual(origin_task_id, "ord-tunnel-01")
        self.assertRegex(origin_task_id, r"^[0-9a-f]{32}$")  # 128-bit server-allocated id (spec 5.5)
        self.assertEqual(tunneled.challenge.client_id, self.chef_agent.agent_url)

        # Rule 3: a well-formed tunneled_response came back, echoing origin_task_id.
        envelope = TunneledResponse.model_validate(
            captured["response_meta"][EXTENSION_URI]["tunneled_response"]
        )
        self.assertEqual(envelope.origin_task_id, origin_task_id)
        self.assertIn("sub_approval", envelope.response)

        # Rule 2: the KB-JWT is bound to the Terminal Verifier, not the Intermediate.
        kb = _jwt.decode(
            envelope.response["sub_approval"][0].split("~")[-1],
            options={"verify_signature": False},
        )
        self.assertEqual(kb["aud"], self.chef_agent.agent_url)
        self.assertNotEqual(kb["aud"], self.foh_agent.agent_url)
        self.assertEqual(kb["nonce"], tunneled.challenge.nonce)

        # End-to-end outcome is preserved.
        self.assertEqual(response.state, "TASK_STATE_COMPLETED")
        self.assertIn("substitution", response.message["parts"][0]["text"])


if __name__ == "__main__":
    unittest.main()
