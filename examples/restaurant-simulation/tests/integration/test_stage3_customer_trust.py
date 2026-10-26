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


class TestStage3CustomerChainOfTrust(unittest.TestCase):
    def setUp(self) -> None:
        # 1. Root of trust: Restaurant Authority Issuer
        self.authority_issuer = RestaurantAuthorityIssuerService(
            issuer_url="https://authority.example.com",
        )

        # 2. Enterprise Issuer: Restaurant Issuer
        self.restaurant_issuer = RestaurantIssuerService(
            issuer_url="https://restaurant.example.com",
            restaurant_id="rest-101",
        )

        # 3. Issue VerifiedRestaurantCredential from Authority -> Restaurant Issuer
        self.rest_cred_data = self.authority_issuer.issue_restaurant_credential(
            restaurant_url="https://restaurant.example.com",
            restaurant_id="rest-101",
            legal_name="Google Gourmet Bistro",
            health_rating="A+",
            licence_number="LIC-2026-8890",
            holder_pub_jwk=self.restaurant_issuer.get_public_jwk(),
        )

        # 4. Set up TSL, Kitchen MCP, Kitchen AS, and Agents
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

        # Generate holder keys
        self.chef_priv, self.chef_pub = generate_ec_p256_keypair()
        self.foh_priv, self.foh_pub = generate_ec_p256_keypair()
        self.cust_priv, self.cust_pub = generate_ec_p256_keypair()

        self.chef_holder_jwk = export_jwk_from_private_key(self.chef_priv)
        self.foh_holder_jwk = export_jwk_from_private_key(self.foh_priv)

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

        # Equip Chef Agent
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

        # Equip FoH Agent with Employee Credential AND Restaurant Credential
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

    def test_01_customer_verifies_restaurant_chain_of_trust_and_orders(self) -> None:
        response = self.customer_agent.order_from_restaurant(
            foh_agent=self.foh_agent,
            dish_name="Grilled Cheese",
            task_id="cust-order-001",
            context_id="dining-session-1",
        )

        self.assertEqual(response.state, "TASK_STATE_COMPLETED")
        self.assertIn("Grilled Cheese", response.message["parts"][0]["text"])
        self.assertIn("Alice Waitstaff", response.message["parts"][0]["text"])

    def test_02_untrusted_restaurant_establishment_rejected_by_customer(self) -> None:
        # Create a rogue restaurant that was not certified by self.authority_issuer
        rogue_auth = RestaurantAuthorityIssuerService(issuer_url="https://rogue-authority.example.com")
        rogue_rest_data = rogue_auth.issue_restaurant_credential(
            restaurant_url="https://restaurant.example.com",
            restaurant_id="rest-101",
            legal_name="Imposter Bistro",
            health_rating="D",
            licence_number="FAKE-LIC-999",
            holder_pub_jwk=self.restaurant_issuer.get_public_jwk(),
        )

        # Replace FoH Agent's rest_cred with the rogue credential
        self.foh_agent.wallet.add_credential(
            CredentialItem(
                id="rest_cred",
                sd_jwt_string=rogue_rest_data["sd_jwt_string"],
                holder_private_key_jwk=self.restaurant_issuer.issuer_priv_jwk,
            )
        )

        with self.assertRaises(CustomerError) as ctx:
            self.customer_agent.order_from_restaurant(
                foh_agent=self.foh_agent,
                dish_name="Grilled Cheese",
                task_id="cust-order-002",
            )

        self.assertIn("Restaurant legitimacy verification failed against Root Authority", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
