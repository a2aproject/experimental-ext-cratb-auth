# SPDX-License-Identifier: Apache-2.0
import unittest
from typing import Any, Dict

from a2a_agentic_id import (
    DCQLQuery,
    DCQLCredentialQuery,
    DCQLClaimQuery,
    ErrorCode,
    SDJWTWallet,
    SDJWTVerifier,
    CredentialItem,
    TokenStatusListClient,
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
)
from a2a_agentic_id.verifier import CredentialVerificationError
from a2a_agentic_id.models import StatusListReference

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure")))

from kitchen_mcp.server import KitchenMCPServer, KitchenError
from kitchen_oauth_as.server import KitchenOAuthAS, TokenExchangeRequest


class TestA2AAgenticIDSDK(unittest.TestCase):
    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.keys: Dict[str, Any] = {
            "iss_priv_jwk": export_jwk_from_private_key(iss_priv),
            "iss_pub_jwk": export_jwk_from_public_key(iss_pub),
            "holder_priv_jwk": export_jwk_from_private_key(holder_priv),
            "holder_pub_jwk": export_jwk_from_public_key(holder_pub),
        }

    def test_sd_jwt_issuance_and_verification(self) -> None:
        iss = "https://issuer.example.com"
        client_id = "https://verifier.example.com"
        nonce = "test-nonce-12345"

        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss=iss,
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/chef-bot",
            plaintext_claims={"status": {"status_list": {"idx": 5, "uri": "https://issuer.example.com/status"}}},
            sd_claims={
                "name": "Chef Bot 3000",
                "description": "Autonomous restaurant chef agent",
                "owner": {"id": "org-1", "name": "Google Gourmet"},
            },
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt_str,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        query = DCQLQuery.default_agent_identity_query()
        vp_resp = wallet.create_vp_token(
            dcql_query=query,
            nonce=nonce,
            client_id=client_id,
            conversation_id="conv-001",
        )

        verifier = SDJWTVerifier(client_id=client_id, allow_unverified_status=True)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        res = verifier.verify_presentation(
            presentation_str=vp_str,
            nonce=nonce,
            expected_context_id="conv-001",
            dcql_query=query,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        self.assertTrue(res.is_valid)
        self.assertEqual(res.issuer, iss)
        self.assertEqual(res.id_claim, "https://agents.example.com/chef-bot")
        self.assertEqual(res.disclosed_claims["name"], "Chef Bot 3000")

    def test_error_code_nonce_mismatch(self) -> None:
        iss = "https://issuer.example.com"
        client_id = "https://verifier.example.com"

        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss=iss,
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/chef-bot",
            plaintext_claims={},
            sd_claims={"name": "Chef Bot 3000", "description": "chef", "owner": "org:chef"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt_str,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        query = DCQLQuery.default_agent_identity_query()
        vp_resp = wallet.create_vp_token(
            dcql_query=query,
            nonce="nonce-A",
            client_id=client_id,
        )

        verifier = SDJWTVerifier(client_id=client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            verifier.verify_presentation(
                presentation_str=vp_str,
                nonce="nonce-B",  # Wrong nonce
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_NONCE_MISMATCH)

    def _wallet_with(self, cred_id: str) -> SDJWTWallet:
        """Return a wallet that holds one credential with the given ID."""
        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            dct="https://example.com/credentials/EmployeeCredential/v1",
            id_claim="https://agents.example.com/foh-bot",
            plaintext_claims={},
            sd_claims={"role": "foh"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id=cred_id,
                sd_jwt_string=sd_jwt_str,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        return wallet

    def test_wallet_rejects_credential_id_not_held(self) -> None:
        # The wallet must not present a different credential of the same format.
        wallet = self._wallet_with("emp_cred")
        query = DCQLQuery(
            credentials=[DCQLCredentialQuery(id="sub_approval", format="dc+sd-jwt", meta={"vct_values": ["https://example.com/credentials/IngredientSubstitutionApproval/v1"]})]
        )
        with self.assertRaises(ValueError):
            wallet.create_vp_token(dcql_query=query, nonce="n", client_id="https://verifier.example.com")

    def test_wallet_rejects_format_mismatch(self) -> None:
        wallet = self._wallet_with("emp_cred")
        query = DCQLQuery(
            credentials=[DCQLCredentialQuery(id="emp_cred", format="jwt_vc_json")]
        )
        with self.assertRaises(ValueError):
            wallet.create_vp_token(dcql_query=query, nonce="n", client_id="https://verifier.example.com")

    def test_tsl_revocation_check(self) -> None:
        iss = "https://issuer.example.com"
        tsl_jwt = TokenStatusListClient.create_status_list_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss=iss,
            revoked_indices=[0, 5, 42],
            sub="https://issuer.example.com/status-list",
        )

        client = TokenStatusListClient()
        uri = "https://issuer.example.com/status-list"
        client.register_status_list_jwt(uri, tsl_jwt, issuer_public_key_jwk=self.keys["iss_pub_jwk"])

        self.assertTrue(client.is_revoked(StatusListReference(idx=0, uri=uri)))
        self.assertTrue(client.is_revoked(StatusListReference(idx=5, uri=uri)))
        self.assertFalse(client.is_revoked(StatusListReference(idx=1, uri=uri)))

    def test_kitchen_oauth_exchange_and_mcp_invocation(self) -> None:
        iss = "https://issuer.example.com"
        as_issuer = "http://localhost:8081"
        nonce = "oauth-nonce-789"

        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss=iss,
            dct="https://example.com/credentials/RestaurantEmployeeCredential/v1",
            id_claim="https://agents.example.com/chef-bot",
            plaintext_claims={"restaurant_id": "rest-101"},
            sd_claims={"name": "Chef Bot", "role": "chef"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="emp_cred",
                sd_jwt_string=sd_jwt_str,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="emp_cred",
                    meta={"vct_values": ["https://example.com/credentials/RestaurantEmployeeCredential/v1"]},
                    claims=[DCQLClaimQuery(path=["role"], values=["chef"])],
                )
            ]
        )

        vp_resp = wallet.create_vp_token(
            dcql_query=query,
            nonce=nonce,
            client_id=as_issuer,
        )

        verifier = SDJWTVerifier(
            client_id=as_issuer,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
        )
        auth_server = KitchenOAuthAS(issuer=as_issuer, verifier=verifier)

        from restaurant_domain.x401 import build_result_artifact, encode_result_artifact

        token_resp = auth_server.token_exchange(
            TokenExchangeRequest(
                subject_token=encode_result_artifact(build_result_artifact(vp_resp.vp_token)),
                scope="kitchen:appliances:use",
                nonce=nonce,
            )
        )

        access_token = token_resp["access_token"]
        self.assertIsNotNone(access_token)

        mcp_server = KitchenMCPServer()
        auth_header = f"Bearer {access_token}"

        res = mcp_server.use_appliance("oven", "preheating", temp_f=350, auth_header=auth_header)
        self.assertEqual(res["status"]["state"], "preheating")
        self.assertEqual(res["status"]["temp_f"], 350)

    def test_owner_claim_type_field(self) -> None:
        """Section 5.2: owner.type is optional and restricted to legal_person / natural_person."""
        import pydantic

        from a2a_agentic_id import AIAgentIdentityCredential, OwnerClaim, OwnerType

        # Both allowed values validate.
        legal = OwnerClaim(id="did:example:acme", name="Acme Corp", type="legal_person")
        natural = OwnerClaim(id="did:example:bob", name="Bob", type=OwnerType.NATURAL_PERSON)
        self.assertEqual(legal.type, OwnerType.LEGAL_PERSON)
        self.assertEqual(natural.type, "natural_person")

        # Optional: omission is conformant.
        self.assertIsNone(OwnerClaim(id="o", name="n").type)

        # Out-of-vocabulary values are rejected.
        with self.assertRaises(pydantic.ValidationError):
            OwnerClaim(id="o", name="n", type="corporation")

        # The value survives validation instead of being silently dropped.
        parsed = OwnerClaim.model_validate(
            {"id": "did:example:acme", "name": "Acme Corp", "type": "legal_person"}
        )
        self.assertEqual(parsed.type, "legal_person")
        self.assertEqual(parsed.model_dump()["type"], "legal_person")

        # And round-trips through the composed credential model.
        cred = AIAgentIdentityCredential.model_validate(
            {
                "iss": "https://issuer.example.com",
                "iat": 0,
                "exp": 1,
                "vct": "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
                "id": "https://agents.example.com/a1",
                "owner": {"id": "did:example:acme", "name": "Acme Corp", "type": "legal_person"},
            }
        )
        self.assertEqual(cred.owner.type, "legal_person")

    def test_key_protection_level_vocabulary(self) -> None:
        """Section 5.2: key_protection_level is optional and restricted to a three-value vocabulary."""
        import pydantic

        from a2a_agentic_id import AIAgentIdentityCredential, KeyProtectionLevel

        base = {
            "iss": "https://issuer.example.com",
            "iat": 0,
            "exp": 1,
            "vct": "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            "id": "https://agents.example.com/a1",
        }

        # The vocabulary is exactly the three values in the spec table.
        self.assertEqual(
            {m.value for m in KeyProtectionLevel},
            {"software", "hardware_tee", "hardware_hsm"},
        )

        # Each allowed value validates and coerces from a plain string.
        for value in ("software", "hardware_tee", "hardware_hsm"):
            cred = AIAgentIdentityCredential(**base, key_protection_level=value)
            self.assertEqual(cred.key_protection_level, value)
            self.assertEqual(cred.model_dump()["key_protection_level"], value)

        # Optional: omission is conformant.
        self.assertIsNone(AIAgentIdentityCredential(**base).key_protection_level)

        # Out-of-vocabulary and wrong-case values are rejected.
        for bad in ("high", "medium", "HARDWARE_HSM", "tee", "hsm", ""):
            with self.assertRaises(pydantic.ValidationError, msg=f"accepted {bad!r}"):
                AIAgentIdentityCredential(**base, key_protection_level=bad)

        # Existing plain-string comparisons still work.
        hsm = AIAgentIdentityCredential(**base, key_protection_level="hardware_hsm")
        self.assertTrue(hsm.key_protection_level == "hardware_hsm")
        self.assertIs(hsm.key_protection_level, KeyProtectionLevel.HARDWARE_HSM)



if __name__ == "__main__":
    unittest.main()
