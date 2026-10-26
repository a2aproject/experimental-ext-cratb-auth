# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""
Verifiable Credential Restaurant - Full Multi-Stage Simulation Demo Runner
Demonstrates Stages 1 through 5 of the A2A Agentic Identity Credentials Extension (v0.1, dc+sd-jwt).
"""

import sys
import os
import time

# Add SDK, infrastructure, and agents to sys.path
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sdk_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "sdk", "python"))
sys.path.insert(0, sdk_dir)
sys.path.insert(0, os.path.join(base_dir, "infrastructure"))
sys.path.insert(0, os.path.join(base_dir, "agents"))
sys.path.insert(0, base_dir)  # restaurant_domain

from a2a_agentic_id import (
    SDJWTWallet,
    CredentialItem,
    TokenStatusListClient,
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
)
from issuers.authority_issuer import RestaurantAuthorityIssuerService
from issuers.restaurant_issuer import RestaurantIssuerService
from kitchen_mcp.server import KitchenMCPServer
from kitchen_oauth_as.server import KitchenOAuthAS
from chef_agent.agent import ChefAgent
from foh_agent.agent import FoHAgent
from customer_agent.agent import CustomerAgent


def print_header(title: str) -> None:
    print("\n" + "=" * 76)
    print(f"  {title}")
    print("=" * 76)


def print_step(step_num: int, description: str) -> None:
    print(f"\n[Step {step_num}] {description}")


def run_all_stages() -> None:
    print_header("VERIFIABLE CREDENTIAL RESTAURANT SIMULATION (A2A Identity Extension v0.1)")

    # Initialize Trust Infrastructure
    print_step(1, "Initializing Trust Infrastructure & Crypto Keys...")
    authority_issuer = RestaurantAuthorityIssuerService("https://authority.example.com")
    restaurant_issuer = RestaurantIssuerService("https://restaurant.example.com", "rest-101")
    tsl_client = TokenStatusListClient()
    tsl_client.register_status_list_jwt(
        uri="https://restaurant.example.com/status-list.jwt",
        jwt_str=restaurant_issuer.get_status_list_jwt(),
        issuer_public_key_jwk=restaurant_issuer.get_public_jwk(),
    )
    print("  -> [OK] Root Restaurant Authority & Enterprise Restaurant Issuer running.")
    print("  -> [OK] Token Status List (TSL) bit-array service registered.")

    # Initialize Kitchen Backend
    print_step(2, "Initializing Kitchen MCP Server & OAuth 2.0 AS (dcql_scope_mapping)...")
    kitchen_mcp = KitchenMCPServer()
    kitchen_as = KitchenOAuthAS(
        issuer="http://localhost:8081",
        jwks_resolver=lambda iss: restaurant_issuer.get_public_jwk(),
        tsl_client=tsl_client,
    )
    print("  -> [OK] Kitchen MCP Server initialized with inventory & appliance guards.")
    print("  -> [OK] Kitchen Authorization Server advertising dcql_scope_mapping.")

    # Initialize Autonomous Agents
    print_step(3, "Provisioning Autonomous Agents (Chef, FoH Waitstaff, Customer)...")
    chef_agent = ChefAgent(
        agent_url="https://chef.example.com/a2a",
        restaurant_issuer_pub_jwk=restaurant_issuer.get_public_jwk(),
        tsl_client=tsl_client,
        kitchen_oauth_as=kitchen_as,
        kitchen_mcp_server=kitchen_mcp,
    )
    foh_agent = FoHAgent("https://foh.example.com/a2a")
    foh_agent.set_chef_agent(chef_agent)
    customer_agent = CustomerAgent(
        "https://customer.example.com/a2a",
        authority_pub_jwk=authority_issuer.get_public_jwk(),
        tsl_client=tsl_client,
    )
    foh_agent.set_customer_agent(customer_agent)

    # Key generation and SD-JWT issuance
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
        CredentialItem(
            id="agent_identity",
            sd_jwt_string=cust_sd_jwt,
            holder_private_key_jwk=export_jwk_from_private_key(cust_priv),
        )
    )
    print("  -> [OK] Chef & FoH issued RestaurantEmployeeCredential (cnf.jwk EC P-256 bound).")
    print("  -> [OK] Customer issued AIAgentIdentityCredential.")

    # STAGE 2 & 4: NORMAL ORDER WITH PAYMENT COMMITMENT
    print_header("STAGE 2 & 4: ORDER MEDIATION & HOLDER-SIGNED PAYMENT COMMITMENT")
    print_step(4, "Customer signs OrderPaymentCommitment ($15.00) using holder key (cnf.jwk)...")
    comm_jwt = customer_agent.create_signed_payment_commitment("ord-sim-01", 1500)
    print("  -> [OK] OrderPaymentCommitment signed (typ='order-commitment+jwt').")

    print_step(5, "Customer places order with FoHAgent after verifying Restaurant Chain of Trust...")
    resp1 = customer_agent.order_from_restaurant(
        foh_agent=foh_agent,
        dish_name="Grilled Cheese",
        task_id="ord-sim-01",
        order_commitment_jwt=comm_jwt,
        customer_pub_jwk=export_jwk_from_public_key(cust_pub),
    )
    print(f"  -> [OK] A2A Task State: {resp1.state}")
    print(f"  -> [OK] Chef Output: {resp1.message['parts'][0]['text']}")
    print(f"  -> [OK] FoH Order State: {foh_agent.orders['ord-sim-01']['state']}")
    print(f"  -> [OK] Kitchen MCP Inventory Remaining: cheese={kitchen_mcp.state.ingredients['cheese']}")

    # STAGE 5: INGREDIENT DEPLETION & DYNAMIC VC ISSUANCE
    print_header("STAGE 5: INGREDIENT DEPLETION & DYNAMIC ON-DEMAND VC ISSUANCE")
    print_step(6, "Simulating out-of-stock condition on 'gluten_free_bread'...")
    kitchen_mcp.state.ingredients["gluten_free_bread"] = 0
    print("  -> [OK] Kitchen MCP 'gluten_free_bread' inventory set to 0.")

    print_step(7, "Customer places order for Grilled Cheese (triggering dynamic substitution challenge)...")
    resp2 = customer_agent.order_from_restaurant(
        foh_agent=foh_agent,
        dish_name="Grilled Cheese",
        task_id="ord-sim-02",
        customer_pub_jwk=export_jwk_from_public_key(cust_pub),
    )
    print(f"  -> [OK] A2A Task State: {resp2.state}")
    print(f"  -> [OK] Chef Output: {resp2.message['parts'][0]['text']}")
    print(f"  -> [OK] Kitchen MCP Prepared Dish: {kitchen_mcp.state.prepared_dishes[-1]['dish_name']}")

    print_header("ALL SIMULATION STAGES COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    run_all_stages()
