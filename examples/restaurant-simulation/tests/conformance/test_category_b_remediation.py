# SPDX-License-Identifier: Apache-2.0
import unittest
from typing import Any, Dict
import jwt
import time
from cryptography.hazmat.primitives import serialization

from a2a_agentic_id import (
    SDJWTWallet,
    SDJWTVerifier,
    TokenStatusListClient,
    CredentialItem,
    DCQLQuery,
    ErrorCode,
    ClientAuthHandler,
)
from a2a_agentic_id.crypto import (
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    import_private_key_from_jwk,
)
from a2a_agentic_id.interceptor import (
    ServerAuthRequiredInterceptor,
    A2ATaskMessage,
    A2ATaskStatusResponse,
    EXTENSION_URI,
)
from a2a_agentic_id.models import StatusListReference
from a2a_agentic_id.verifier import CredentialVerificationError


class TestCategoryBRemediation(unittest.TestCase):
    """
    Dedicated test suite verifying the 5 quick-win SDK defect fixes (Category B):
    - K2: Cryptographic signature precedes exp/iat checks; missing exp rejected.
    - K3: TSL fail-closed when status_list reference is present without tsl_client.
    - K4: TSL LSB-first bit ordering and width support (1, 2, 4, 8) per IETF draft-21.
    - K7: Context ID association checked against server-retained challenge context.
    - K16: Holder validates expected client_id and response_mode before signing.
    """

    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.keys: Dict[str, Any] = {
            "iss_priv_jwk": export_jwk_from_private_key(iss_priv),
            "iss_pub_jwk": export_jwk_from_public_key(iss_pub),
            "holder_priv_jwk": export_jwk_from_private_key(holder_priv),
            "holder_pub_jwk": export_jwk_from_public_key(holder_pub),
        }
        self.client_id = "https://verifier.example.com"
        self.verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
        )

    def test_k2_missing_exp_rejected(self) -> None:
        """K2: An Issuer JWT missing the required 'exp' claim MUST be rejected."""
        # Forge credential without 'exp' claim
        now = int(time.time())
        priv_key = import_private_key_from_jwk(self.keys["iss_priv_jwk"])
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        issuer_jwt = jwt.encode(
            payload={
                "iss": "https://issuer.example.com",
                "iat": now,
                # 'exp' omitted intentionally
                "dct": "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
                "id": "https://agents.example.com/bot",
                "cnf": {"jwk": self.keys["holder_pub_jwk"]},
                "_sd": [],
                "_sd_alg": "sha-256",
            },
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "dc+sd-jwt"},
        )
        raw_sd_jwt = issuer_jwt + "~"

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=raw_sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        vp_str = wallet.create_presentation(
            wallet.get_credential("agent_identity"), [], nonce="nonce-k2", client_id=self.client_id
        )

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                vp_str,
                nonce="nonce-k2",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)
        self.assertIn("missing required temporal claim", str(ctx.exception).lower())

    def test_k2_signature_checked_before_expiration(self) -> None:
        """K2: Tampered/forged token with expired timestamp fails signature check, not expired check."""
        # Generate credential signed with forged/untrusted key but expired timestamp
        attacker_priv, _ = generate_ec_p256_keypair()
        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=export_jwk_from_private_key(attacker_priv),
            iss="https://issuer.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/attacker",
            plaintext_claims={},
            sd_claims={"name": "Attacker"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
            expires_in_seconds=-100,  # Expired
        )
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt_str,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        vp_str = wallet.create_presentation(
            wallet.get_credential("agent_identity"), [], nonce="nonce-k2", client_id=self.client_id
        )

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                vp_str,
                nonce="nonce-k2",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        # Must fail signature verification FIRST
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)

    def test_k3_tsl_fail_closed_without_client(self) -> None:
        """K3: A credential referencing status_list must fail-closed if no TSL client is configured."""
        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/agent-1",
            plaintext_claims={
                "status": {"status_list": {"idx": 10, "uri": "https://issuer.example.com/status.jwt"}}
            },
            sd_claims={"name": "Agent 1"},
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
        vp_str = wallet.create_presentation(
            wallet.get_credential("agent_identity"), [], nonce="nonce-k3", client_id=self.client_id
        )

        # Default verifier has tsl_client=None and allow_unverified_status=False
        strict_verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            strict_verifier.verify_presentation(
                vp_str,
                nonce="nonce-k3",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_CREDENTIAL_REVOKED)
        self.assertIn("fail-closed", str(ctx.exception).lower())

        # Explicit opt-out allows verification to proceed
        lenient_verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
            allow_unverified_status=True,
        )
        res = lenient_verifier.verify_presentation(
            vp_str,
            nonce="nonce-k3",
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        self.assertTrue(res.is_valid)

    def test_k4_tsl_lsb_first_bit_ordering_and_widths(self) -> None:
        """K4: TSL bit extraction must follow LSB-first ordering and support bits=1, 2."""
        # 1-bit list: revoke idx=0 and idx=7
        jwt_1bit = TokenStatusListClient.create_status_list_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            revoked_indices=[0, 7],
            total_bits=64,
            bits=1,
            sub="https://issuer.example.com/status-1bit.jwt",
        )
        tsl_client = TokenStatusListClient()
        uri_1bit = "https://issuer.example.com/status-1bit.jwt"
        tsl_client.register_status_list_jwt(
            uri=uri_1bit,
            jwt_str=jwt_1bit,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        # LSB-first: idx 0 is bit 0 (0x01), idx 7 is bit 7 (0x80)
        self.assertTrue(tsl_client.is_revoked(StatusListReference(idx=0, uri=uri_1bit)))
        self.assertTrue(tsl_client.is_revoked(StatusListReference(idx=7, uri=uri_1bit)))
        self.assertFalse(tsl_client.is_revoked(StatusListReference(idx=1, uri=uri_1bit)))
        self.assertFalse(tsl_client.is_revoked(StatusListReference(idx=6, uri=uri_1bit)))

        # 2-bit list: idx 0 is revoked (value 1), idx 1 is suspended (value 2), idx 2 is valid (value 0)
        total_bits = 32
        bit_array = bytearray((total_bits * 2 + 7) // 8)
        # idx 0: value 1 (revoked) -> bits 0..1 = 0b01
        bit_array[0] |= (1 << 0)
        # idx 1: value 2 (suspended) -> bits 2..3 = 0b10
        bit_array[0] |= (2 << 2)

        import zlib
        from a2a_agentic_id.crypto import base64url_encode
        lst_b64 = base64url_encode(zlib.compress(bytes(bit_array)))
        priv_key = import_private_key_from_jwk(self.keys["iss_priv_jwk"])
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        jwt_2bit = jwt.encode(
            payload={
                "iss": "https://issuer.example.com",
                "sub": "https://issuer.example.com/status-2bit.jwt",
                "iat": int(time.time()),
                "status_list": {"bits": 2, "lst": lst_b64},
            },
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "statuslist+jwt"},
        )
        uri_2bit = "https://issuer.example.com/status-2bit.jwt"
        tsl_client.register_status_list_jwt(
            uri=uri_2bit, jwt_str=jwt_2bit, issuer_public_key_jwk=self.keys["iss_pub_jwk"]
        )

        # 1=revoked -> True, 2=suspended -> True, 0=valid -> False
        self.assertTrue(tsl_client.is_revoked(StatusListReference(idx=0, uri=uri_2bit)))
        self.assertTrue(tsl_client.is_revoked(StatusListReference(idx=1, uri=uri_2bit)))
        self.assertFalse(tsl_client.is_revoked(StatusListReference(idx=2, uri=uri_2bit)))

    def test_k7_context_id_association_enforced(self) -> None:
        """K7: Response contextId must match the task's contextId established at challenge time."""
        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        task_id = "task-session-k7"
        established_ctx = "context-established-origin"
        attacker_ctx = "context-attacker-modified"

        # 1. Initial Request generates challenge and associates task_id -> established_ctx
        init_req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=established_ctx,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={},
        )
        resp1 = interceptor.process_incoming_request(
            init_req,
            lambda r, v: A2ATaskStatusResponse(id=r.id, context_id=r.context_id, state="TASK_STATE_WORKING", message={}),
        )
        self.assertEqual(resp1.state, "TASK_STATE_AUTH_REQUIRED")

        # 2. Holder builds valid VP token
        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/agent-k7",
            plaintext_claims={},
            sd_claims={"name": "Agent K7", "description": "k7 agent", "owner": "org:k7"},
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
        challenge_meta = resp1.message["metadata"][EXTENSION_URI]
        nonce = challenge_meta["nonce"]
        vp_resp = wallet.create_vp_token(
            DCQLQuery.default_agent_identity_query(),
            nonce=nonce,
            client_id=self.client_id,
            conversation_id=established_ctx,
        )

        # 3. Follow-up response sent with altered context_id
        tampered_req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=attacker_ctx,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp_resp.vp_token}},
        )
        resp2 = interceptor.process_incoming_request(
            tampered_req,
            lambda r, v: A2ATaskStatusResponse(id=r.id, context_id=r.context_id, state="TASK_STATE_WORKING", message={}),
        )
        self.assertEqual(resp2.state, "TASK_STATE_FAILED")
        self.assertEqual(
            resp2.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_CONVERSATION_MISMATCH.value,
        )

    def test_s1_tunneled_challenge_refused_without_policy(self) -> None:
        """S1 / spec 12.6.1: a missing or denying tunnel policy refuses before any signing."""
        from a2a_agentic_id import ClientAuthHandler, TunneledChallenge, IdentityChallenge

        challenge = IdentityChallenge(
            nonce="n", client_id="https://terminal.example.com/a2a",
            response_uri="https://terminal.example.com/a2a", response_mode="a2a_metadata",
            dcql_query=DCQLQuery.default_agent_identity_query(),
        )
        tunneled = TunneledChallenge(origin_task_id="t2", challenge=challenge)
        handler = ClientAuthHandler(wallet=SDJWTWallet())

        with self.assertRaises(ValueError) as ctx:
            handler.handle_tunneled_challenge(tunneled)
        self.assertIn("tunnel_policy", str(ctx.exception))

        class Deny:
            def is_terminal_allowed(self, client_id):
                return False

        with self.assertRaises(ValueError) as ctx:
            handler.handle_tunneled_challenge(tunneled, tunnel_policy=Deny())
        self.assertIn("not permitted", str(ctx.exception))

    def test_k16_holder_validates_client_id_and_response_mode(self) -> None:
        """K16: ClientAuthHandler must validate challenge client_id and response_mode before signing."""
        sd_jwt_str = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/agent-k16",
            plaintext_claims={},
            sd_claims={"name": "Agent K16"},
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

        handler = ClientAuthHandler(wallet=wallet)
        contacted = "https://legitimate-verifier.example.com/a2a"

        challenge_payload = {
            "status": "identity_required",
            "nonce": "test-nonce-k16",
            "client_id": "https://malicious-relay.example.com",  # Mismatch
            "response_uri": "https://malicious-relay.example.com/a2a",
            "response_mode": "a2a_metadata",
            "dcql_query": DCQLQuery.default_agent_identity_query().model_dump(),
        }
        task_resp = {
            "state": "auth-required",
            "message": {"metadata": {EXTENSION_URI: challenge_payload}},
        }

        # Mismatched client_id must be rejected
        with self.assertRaises(ValueError) as ctx:
            handler.handle_auth_challenge(task_resp, contacted_url=contacted)
        self.assertIn("does not match the contacted verifier", str(ctx.exception))

        # No contacted_url: nothing is signed (spec 8.1.1, missing trusted context)
        with self.assertRaises((ValueError, TypeError)):
            handler.handle_auth_challenge(task_resp, contacted_url=None)

        # Prefixed identifier with a different origin is also rejected
        challenge_payload["client_id"] = "a2a_agent_card:https://malicious-relay.example.com/.well-known/agent-card.json"
        with self.assertRaises(ValueError):
            handler.handle_auth_challenge(task_resp, contacted_url=contacted)

        # Prefixed identifier with the same origin is accepted
        challenge_payload["client_id"] = "a2a_agent_card:https://legitimate-verifier.example.com/.well-known/agent-card.json"
        # The origin check passes; this fixture wallet lacks the claims the default query asks for,
        # so the call fails later, at credential selection, not at the verifier-binding check.
        with self.assertRaises(ValueError) as ok_ctx:
            handler.handle_auth_challenge(task_resp, contacted_url=contacted)
        self.assertNotIn("contacted", str(ok_ctx.exception))
        self.assertIn("not found in wallet", str(ok_ctx.exception))

        # Unsupported response_mode must be rejected
        challenge_payload["client_id"] = "https://legitimate-verifier.example.com"
        challenge_payload["response_mode"] = "direct_post"
        with self.assertRaises(ValueError) as ctx:
            handler.handle_auth_challenge(task_resp, contacted_url=contacted)
        self.assertIn("Unsupported response_mode", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
