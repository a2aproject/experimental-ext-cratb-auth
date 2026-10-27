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
from a2a_agentic_id.interceptor import A2ATaskMessage, EXTENSION_URI

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../agents")))

from issuers.restaurant_issuer import RestaurantIssuerService
from kitchen_mcp.server import KitchenMCPServer
from kitchen_oauth_as.server import KitchenOAuthAS
from chef_agent.agent import ChefAgent
from foh_agent.agent import FoHAgent


class TestStage2FoHChefMediation(unittest.TestCase):
    def setUp(self) -> None:
        self.restaurant_issuer = RestaurantIssuerService(
            issuer_url="https://restaurant.example.com",
            restaurant_id="rest-101",
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

        # Generate holder keys
        self.chef_priv, self.chef_pub = generate_ec_p256_keypair()
        self.foh_priv, self.foh_pub = generate_ec_p256_keypair()

        self.chef_holder_jwk = export_jwk_from_private_key(self.chef_priv)
        self.foh_holder_jwk = export_jwk_from_private_key(self.foh_priv)

        # Issue credentials from Restaurant Issuer
        self.chef_cred_data = self.restaurant_issuer.issue_employee_credential(
            employee_id="https://agents.example.com/chef-bot",
            name="Chef Bot 3000",
            role="chef",
            clearance_level="high",
            holder_pub_jwk=export_jwk_from_public_key(self.chef_pub),
        )

        self.foh_cred_data = self.restaurant_issuer.issue_employee_credential(
            employee_id="https://agents.example.com/foh-bot",
            name="Alice Waitstaff",
            role="foh",
            clearance_level="medium",
            holder_pub_jwk=export_jwk_from_public_key(self.foh_pub),
        )

        self.chef_agent.set_own_credentials(
            agent_id_cred=CredentialItem(
                id="agent_identity",
                sd_jwt_string=self.chef_cred_data["sd_jwt_string"],
                holder_private_key_jwk=self.chef_holder_jwk,
            ),
            emp_cred=CredentialItem(
                id="emp_cred",
                sd_jwt_string=self.chef_cred_data["sd_jwt_string"],
                holder_private_key_jwk=self.chef_holder_jwk,
            ),
        )

        self.foh_agent.set_own_credentials(
            agent_id_cred=CredentialItem(
                id="agent_identity",
                sd_jwt_string=self.foh_cred_data["sd_jwt_string"],
                holder_private_key_jwk=self.foh_holder_jwk,
            ),
            emp_cred=CredentialItem(
                id="emp_cred",
                sd_jwt_string=self.foh_cred_data["sd_jwt_string"],
                holder_private_key_jwk=self.foh_holder_jwk,
            ),
        )

    def test_01_successful_order_handshake_and_kitchen_execution(self) -> None:
        initial_cheese = self.kitchen_mcp.state.ingredients["cheese"]
        initial_bread = self.kitchen_mcp.state.ingredients["gluten_free_bread"]
        initial_butter = self.kitchen_mcp.state.ingredients["butter"]

        response = self.foh_agent.place_order_with_chef(
            chef_agent=self.chef_agent,
            order_text="Grilled Cheese",
            task_id="order-101",
            context_id="table-4",
        )

        self.assertEqual(response.state, "TASK_STATE_COMPLETED")
        msg_text = response.message["parts"][0]["text"]
        self.assertIn("Grilled Cheese", msg_text)
        self.assertIn("Alice Waitstaff", msg_text)

        # Verify Kitchen MCP state was decremented by 1
        self.assertEqual(self.kitchen_mcp.state.ingredients["cheese"], initial_cheese - 1)
        self.assertEqual(self.kitchen_mcp.state.ingredients["gluten_free_bread"], initial_bread - 1)
        self.assertEqual(self.kitchen_mcp.state.ingredients["butter"], initial_butter - 1)

        # Verify dish was added to prepared_dishes
        self.assertEqual(len(self.kitchen_mcp.state.prepared_dishes), 1)
        self.assertEqual(self.kitchen_mcp.state.prepared_dishes[0]["dish_name"], "Grilled Cheese")

    def test_02_revoked_foh_credential_rejected_by_tsl(self) -> None:
        # Revoke Alice's credential index in Restaurant Issuer
        self.restaurant_issuer.revoke_credential(self.foh_cred_data["status_idx"])
        # Update TSL client cache with fresh status list JWT
        self.tsl_client.register_status_list_jwt(
            uri="https://restaurant.example.com/status-list.jwt",
            jwt_str=self.restaurant_issuer.get_status_list_jwt(),
            issuer_public_key_jwk=self.restaurant_issuer.get_public_jwk(),
        )

        response = self.foh_agent.place_order_with_chef(
            chef_agent=self.chef_agent,
            order_text="Grilled Cheese",
            task_id="order-102",
            context_id="table-5",
        )

        self.assertEqual(response.state, "TASK_STATE_FAILED")
        self.assertEqual(
            response.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_CREDENTIAL_REVOKED.value,
        )

    def test_03_unauthorized_external_caller_rejected(self) -> None:
        # Create an external caller who holds a credential from an untrusted issuer
        from issuers.restaurant_issuer import RestaurantIssuerService
        fake_issuer = RestaurantIssuerService(issuer_url="https://fake-restaurant.example.com")
        ext_priv, _ = generate_ec_p256_keypair()
        ext_cred = fake_issuer.issue_employee_credential(
            employee_id="https://agents.example.com/spy",
            name="Spy Bot",
            role="foh",
            clearance_level="high",
            holder_pub_jwk=export_jwk_from_public_key(self.foh_pub),
        )

        spy_agent = FoHAgent(agent_url="https://spy.example.com/a2a")
        spy_agent.set_own_credentials(
            agent_id_cred=CredentialItem(
                id="agent_identity",
                sd_jwt_string=ext_cred["sd_jwt_string"],
                holder_private_key_jwk=export_jwk_from_private_key(ext_priv),
            ),
            emp_cred=CredentialItem(
                id="emp_cred",
                sd_jwt_string=ext_cred["sd_jwt_string"],
                holder_private_key_jwk=export_jwk_from_private_key(ext_priv),
            ),
        )

        response = spy_agent.place_order_with_chef(
            chef_agent=self.chef_agent,
            order_text="Grilled Cheese",
            task_id="order-103",
        )

        self.assertEqual(response.state, "TASK_STATE_FAILED")
        self.assertEqual(
            response.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_SIGNATURE_INVALID.value,
        )


if __name__ == "__main__":
    unittest.main()
