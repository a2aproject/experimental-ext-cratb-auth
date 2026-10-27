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
from customer_agent.agent import CustomerAgent


class TestStage4OrderCommitment(unittest.TestCase):
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

        # Generate holder keys
        self.chef_priv, self.chef_pub = generate_ec_p256_keypair()
        self.foh_priv, self.foh_pub = generate_ec_p256_keypair()
        self.cust_priv, self.cust_pub = generate_ec_p256_keypair()

        self.chef_holder_jwk = export_jwk_from_private_key(self.chef_priv)
        self.foh_holder_jwk = export_jwk_from_private_key(self.foh_priv)
        self.cust_holder_jwk = export_jwk_from_private_key(self.cust_priv)
        self.cust_pub_jwk = export_jwk_from_public_key(self.cust_pub)

        # Equip Customer Agent with AIAgentIdentityCredential
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

    def test_01_valid_signed_payment_commitment_enables_meal_prep(self) -> None:
        commitment_jwt = self.customer_agent.create_signed_payment_commitment(
            order_id="ord-401",
            max_amount_cents=1500,
        )

        response = self.customer_agent.order_from_restaurant(
            foh_agent=self.foh_agent,
            dish_name="Grilled Cheese",
            task_id="ord-401",
            context_id="table-1",
            order_commitment_jwt=commitment_jwt,
            customer_pub_jwk=self.cust_pub_jwk,
        )

        self.assertEqual(response.state, "TASK_STATE_COMPLETED")
        self.assertIn("Grilled Cheese", response.message["parts"][0]["text"])
        # Verify FoH OrderState machine progressed to PAID
        self.assertEqual(self.foh_agent.orders["ord-401"]["state"], "PAID")

    def test_02_forged_or_tampered_payment_commitment_rejected(self) -> None:
        # Sign commitment with an unauthorized key (attacker key)
        attacker_priv, _ = generate_ec_p256_keypair()
        from restaurant_domain import OrderPaymentCommitment, OrderCommitmentSigner
        import time

        forged_comm = OrderPaymentCommitment(
            order_id="ord-402",
            customer_id=self.customer_agent.agent_url,
            max_amount_cents=1500,
            timestamp=int(time.time()),
        )
        forged_jwt = OrderCommitmentSigner.sign_commitment(
            commitment=forged_comm,
            holder_private_key_jwk=export_jwk_from_private_key(attacker_priv),
        )

        response = self.customer_agent.order_from_restaurant(
            foh_agent=self.foh_agent,
            dish_name="Grilled Cheese",
            task_id="ord-402",
            order_commitment_jwt=forged_jwt,
            customer_pub_jwk=self.cust_pub_jwk,  # Real customer pub key won't match attacker signature!
        )

        self.assertEqual(response.state, "TASK_STATE_FAILED")
        self.assertIn("Payment commitment verification failed", response.message["parts"][0]["text"])
        # Verify FoH OrderState did not reach PAID
        self.assertNotEqual(self.foh_agent.orders.get("ord-402", {}).get("state"), "PAID")


if __name__ == "__main__":
    unittest.main()
