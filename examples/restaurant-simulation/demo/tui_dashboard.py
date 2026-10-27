# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""
Interactive Terminal Simulation Dashboard for the Verifiable Credential Restaurant.
Allows interactive execution of dining orders, revocation triggers, and ingredient substitutions.
"""

import sys
import os

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sdk_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "sdk", "python"))
sys.path.insert(0, sdk_dir)
sys.path.insert(0, os.path.join(base_dir, "infrastructure"))
sys.path.insert(0, os.path.join(base_dir, "agents"))
sys.path.insert(0, base_dir)  # restaurant_domain

from a2a_agentic_id import SDJWTWallet, CredentialItem, TokenStatusListClient, generate_ec_p256_keypair, export_jwk_from_private_key, export_jwk_from_public_key, EXTENSION_URI
from issuers.authority_issuer import RestaurantAuthorityIssuerService
from issuers.restaurant_issuer import RestaurantIssuerService
from kitchen_mcp.server import KitchenMCPServer
from kitchen_oauth_as.server import KitchenOAuthAS
from chef_agent.agent import ChefAgent
from foh_agent.agent import FoHAgent
from customer_agent.agent import CustomerAgent, CustomerError


def interactive_dashboard() -> None:
    print("==========================================================================")
    print("      A2A AGENTIC ID (v0.1) - VC RESTAURANT INTERACTIVE TERMINAL")
    print("==========================================================================")
    print("Initializing simulation environment and agents...")

    authority_issuer = RestaurantAuthorityIssuerService("https://authority.example.com")
    restaurant_issuer = RestaurantIssuerService("https://restaurant.example.com", "rest-101")
    tsl_client = TokenStatusListClient()
    tsl_client.register_status_list_jwt(
        uri="https://restaurant.example.com/status-list.jwt",
        jwt_str=restaurant_issuer.get_status_list_jwt(),
        issuer_public_key_jwk=restaurant_issuer.get_public_jwk(),
    )

    kitchen_mcp = KitchenMCPServer()
    kitchen_as = KitchenOAuthAS("http://localhost:8081", jwks_resolver=lambda iss: restaurant_issuer.get_public_jwk(), tsl_client=tsl_client)

    chef_agent = ChefAgent(
        agent_url="https://chef.example.com/a2a",
        restaurant_issuer_pub_jwk=restaurant_issuer.get_public_jwk(),
        tsl_client=tsl_client,
        kitchen_oauth_as=kitchen_as,
        kitchen_mcp_server=kitchen_mcp,
    )
    foh_agent = FoHAgent("https://foh.example.com/a2a")
    foh_agent.set_chef_agent(chef_agent)
    customer_agent = CustomerAgent("https://customer.example.com/a2a", authority_pub_jwk=authority_issuer.get_public_jwk(), tsl_client=tsl_client)
    foh_agent.set_customer_agent(customer_agent)

    chef_priv, chef_pub = generate_ec_p256_keypair()
    foh_priv, foh_pub = generate_ec_p256_keypair()
    cust_priv, cust_pub = generate_ec_p256_keypair()

    chef_cred = restaurant_issuer.issue_employee_credential(
        "https://agents.example.com/chef-bot", "Chef Bot 3000", "chef", "high", export_jwk_from_public_key(chef_pub)
    )
    foh_cred = restaurant_issuer.issue_employee_credential(
        "https://agents.example.com/foh-bot", "Alice Waitstaff", "foh", "medium", export_jwk_from_public_key(foh_pub)
    )
    rest_cred = authority_issuer.issue_restaurant_credential(
        "https://restaurant.example.com", "rest-101", "Google Gourmet Bistro", "A+", "LIC-8890", restaurant_issuer.get_public_jwk()
    )

    chef_agent.set_own_credentials(
        CredentialItem(id="agent_identity", sd_jwt_string=chef_cred["sd_jwt_string"], holder_private_key_jwk=export_jwk_from_private_key(chef_priv)),
        CredentialItem(id="emp_cred", sd_jwt_string=chef_cred["sd_jwt_string"], holder_private_key_jwk=export_jwk_from_private_key(chef_priv)),
    )
    foh_agent.set_own_credentials(
        CredentialItem(id="agent_identity", sd_jwt_string=foh_cred["sd_jwt_string"], holder_private_key_jwk=export_jwk_from_private_key(foh_priv)),
        CredentialItem(id="emp_cred", sd_jwt_string=foh_cred["sd_jwt_string"], holder_private_key_jwk=export_jwk_from_private_key(foh_priv)),
        CredentialItem(id="rest_cred", sd_jwt_string=rest_cred["sd_jwt_string"], holder_private_key_jwk=restaurant_issuer.issuer_priv_jwk),
    )
    cust_sd_jwt = SDJWTWallet.issue_sd_jwt(
        issuer_private_key_jwk=authority_issuer.authority_priv_jwk,
        iss="https://authority.example.com",
        vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
        id_claim="https://agents.example.com/customer-1",
        plaintext_claims={},
        sd_claims={"name": "Bob Diner", "description": "Customer dining bot"},
        holder_public_key_jwk=export_jwk_from_public_key(cust_pub),
    )
    customer_agent.set_own_credential(
        CredentialItem(id="agent_identity", sd_jwt_string=cust_sd_jwt, holder_private_key_jwk=export_jwk_from_private_key(cust_priv))
    )

    print("Ready! Choose an interactive action:")
    print("  1. Place Order for 'Grilled Cheese' (Standard Flow with Chain-of-Trust)")
    print("  2. Simulate 'gluten_free_bread' Depletion & Trigger Dynamic Substitution VC")
    print("  3. Revoke Alice's Waitstaff Credential in TSL & Observe Order Rejection")
    print("  0. Exit")

    while True:
        try:
            choice = input("\nEnter option (0-3): ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "0":
            print("Exiting interactive dashboard.")
            break
        elif choice == "1":
            print("\n[ACTION] Customer placing order for Grilled Cheese...")
            comm_jwt = customer_agent.create_signed_payment_commitment("ord-int-01", 1500)
            res = customer_agent.order_from_restaurant(
                foh_agent=foh_agent,
                dish_name="Grilled Cheese",
                task_id="ord-int-01",
                order_commitment_jwt=comm_jwt,
                customer_pub_jwk=export_jwk_from_public_key(cust_pub),
            )
            print(f"  -> State: {res.state} | Message: {res.message['parts'][0]['text']}")
        elif choice == "2":
            print("\n[ACTION] Depleting gluten_free_bread and ordering Grilled Cheese...")
            kitchen_mcp.state.ingredients["gluten_free_bread"] = 0
            res = customer_agent.order_from_restaurant(
                foh_agent=foh_agent,
                dish_name="Grilled Cheese",
                task_id="ord-int-02",
                customer_pub_jwk=export_jwk_from_public_key(cust_pub),
            )
            print(f"  -> State: {res.state} | Message: {res.message['parts'][0]['text']}")
        elif choice == "3":
            print("\n[ACTION] Revoking Alice Waitstaff credential in TSL index...")
            restaurant_issuer.revoke_credential(foh_cred["status_idx"])
            tsl_client.register_status_list_jwt(
                uri="https://restaurant.example.com/status-list.jwt",
                jwt_str=restaurant_issuer.get_status_list_jwt(),
                issuer_public_key_jwk=restaurant_issuer.get_public_jwk(),
            )
            res = foh_agent.place_order_with_chef(chef_agent, "Grilled Cheese", task_id="ord-int-03")
            print(f"  -> State: {res.state} | Error: {res.message['metadata'][EXTENSION_URI]['error']}")
        else:
            print("Invalid option. Enter 0, 1, 2, or 3.")


if __name__ == "__main__":
    interactive_dashboard()
