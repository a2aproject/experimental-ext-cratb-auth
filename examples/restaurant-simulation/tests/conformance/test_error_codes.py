# SPDX-License-Identifier: Apache-2.0
import unittest
import time
from typing import Any, Dict

from a2a_agentic_id import (
    DCQLQuery,
    DCQLCredentialQuery,
    DCQLClaimQuery,
    ErrorCode,
    ExtensionSupportRequiredError,
    SDJWTWallet,
    SDJWTVerifier,
    CredentialItem,
    generate_ec_p256_keypair,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
)
from a2a_agentic_id.verifier import CredentialVerificationError
from a2a_agentic_id.interceptor import (
    ServerAuthRequiredInterceptor,
    A2ATaskMessage,
    A2ATaskStatusResponse,
    EXTENSION_URI,
)


class TestA2AErrorCodesConformance(unittest.TestCase):
    """
    Conformance test suite verifying all 12 error codes defined in Specification Section 11.1.
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
        self.interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

    def _create_base_credential(self, expires_in: int = 86400) -> str:
        return SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/test-agent",
            plaintext_claims={},
            sd_claims={
                "name": "Test Agent",
                "description": "Conformance test agent",
                "owner": {"id": "org:example", "name": "Example Corp"},
            },
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
            expires_in_seconds=expires_in,
        )

    def test_01_auth_extension_required(self) -> None:
        req = A2ATaskMessage(
            channel_id="test-channel",
            id="task-01",
            context_id="ctx-01",
            headers={"A2A-Version": "1.0"},  # Missing A2A-Extensions header
            parts=[{"text": "Hello"}],
        )
        # Spec 6.2: a protocol error (-32008), not a failed Task and not a 11.1 task error code.
        with self.assertRaises(ExtensionSupportRequiredError) as ctx:
            self.interceptor.process_incoming_request(req, lambda r, v: A2ATaskStatusResponse(id="t", context_id="c", state="TASK_STATE_WORKING", message={}))
        self.assertEqual(ctx.exception.JSON_RPC_CODE, -32008)
        self.assertEqual(ctx.exception.extension_uri, EXTENSION_URI)

    def test_02_vp_malformed(self) -> None:
        """Spec 7.3.4 step 1: a presentation that cannot be parsed is VP_MALFORMED."""
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                presentation_str="malformed-string-without-tildes",
                nonce="nonce-test",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_MALFORMED)

    def test_03_vp_nonce_mismatch(self) -> None:
        sd_jwt_str = self._create_base_credential()
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=self.keys["holder_priv_jwk"]))
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-expected", client_id=self.client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-wrong", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_NONCE_MISMATCH)

    def test_04_vp_audience_mismatch(self) -> None:
        sd_jwt_str = self._create_base_credential()
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=self.keys["holder_priv_jwk"]))
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-test", client_id="https://other-verifier.example.com")
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-test", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_AUDIENCE_MISMATCH)

    def test_05_vp_signature_invalid(self) -> None:
        sd_jwt_str = self._create_base_credential()
        # Sign KB-JWT with a different private key than cnf.jwk
        other_priv, _ = generate_ec_p256_keypair()
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=export_jwk_from_private_key(other_priv)))
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-test", client_id=self.client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-test", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)

    def test_06_vp_credential_expired(self) -> None:
        sd_jwt_str = self._create_base_credential(expires_in=-10)  # Expired 10 seconds ago
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=self.keys["holder_priv_jwk"]))
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-test", client_id=self.client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-test", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_CREDENTIAL_EXPIRED)

    def test_07_vp_dcql_unsatisfied(self) -> None:
        sd_jwt_str = self._create_base_credential()
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=self.keys["holder_priv_jwk"]))
        # Query requesting a claim that does not exist in the credential ("clearance_level")
        query = DCQLQuery(credentials=[DCQLCredentialQuery(id="agent_identity", meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]}, claims=[DCQLClaimQuery(path=["clearance_level"])])])
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-test", client_id=self.client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-test", dcql_query=query, issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)

    def test_08_vp_key_binding_missing(self) -> None:
        # Recognized presentation whose final (KB-JWT) segment is empty
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation("eyJhbGci...~", nonce="nonce-test", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_KEY_BINDING_MISSING)

    def test_09_vp_nonce_expired(self) -> None:
        # Send IdentityResponse to interceptor for a task_id that has no active nonce stored
        req = A2ATaskMessage(
            channel_id="test-channel",
            id="unknown-task-999",
            context_id="ctx-09",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": {"agent_identity": ["some-vp-string"]}}},
        )
        res = self.interceptor.process_incoming_request(req, lambda r, v: A2ATaskStatusResponse(id="t", context_id="c", state="TASK_STATE_WORKING", message={}))
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertEqual(res.message["metadata"][EXTENSION_URI]["error"], ErrorCode.VP_NONCE_EXPIRED.value)

    def test_10_vp_conversation_mismatch(self) -> None:
        sd_jwt_str = self._create_base_credential()
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=self.keys["holder_priv_jwk"]))
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-test", client_id=self.client_id, conversation_id="conv-A")
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-test", expected_context_id="conv-B", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_CONVERSATION_MISMATCH)

    def test_11_vp_domain_not_allowed(self) -> None:
        sd_jwt_str = self._create_base_credential()
        wallet = SDJWTWallet()
        wallet.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=sd_jwt_str, holder_private_key_jwk=self.keys["holder_priv_jwk"]))
        vp_resp = wallet.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="nonce-test", client_id=self.client_id, domains=["https://authorized-domain.com"])
        vp_str = vp_resp.vp_token["agent_identity"][0]

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp_str, nonce="nonce-test", issuer_public_key_jwk=self.keys["iss_pub_jwk"])
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DOMAIN_NOT_ALLOWED)

    def test_12_vp_credential_revoked(self) -> None:
        """Section 11.1: a credential whose TSL entry is set MUST yield VP_CREDENTIAL_REVOKED."""
        from a2a_agentic_id import TokenStatusListClient
        from a2a_agentic_id.models import StatusListReference

        status_uri = "https://issuer.example.com/status-list.jwt"
        revoked_idx = 3

        status_jwt = TokenStatusListClient.create_status_list_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            revoked_indices=[revoked_idx],
        )
        tsl_client = TokenStatusListClient()
        tsl_client.register_status_list_jwt(
            uri=status_uri, jwt_str=status_jwt, issuer_public_key_jwk=self.keys["iss_pub_jwk"]
        )

        self.assertTrue(
            tsl_client.is_revoked(StatusListReference(idx=revoked_idx, uri=status_uri))
        )
        # The code exists and is distinct from the expiry code.
        self.assertEqual(ErrorCode.VP_CREDENTIAL_REVOKED.value, "VP_CREDENTIAL_REVOKED")
        self.assertNotEqual(
            ErrorCode.VP_CREDENTIAL_REVOKED, ErrorCode.VP_CREDENTIAL_EXPIRED
        )

    def test_13_tsl_revocation_enforced_by_verifier(self) -> None:
        """Section 7.3.4 step 4: SDJWTVerifier itself MUST reject a TSL-revoked credential."""
        from a2a_agentic_id import TokenStatusListClient

        status_uri = "https://issuer.example.com/status-list.jwt"
        revoked_idx, valid_idx = 5, 6

        tsl_client = TokenStatusListClient()
        tsl_client.register_status_list_jwt(
            uri=status_uri,
            jwt_str=TokenStatusListClient.create_status_list_jwt(
                issuer_private_key_jwk=self.keys["iss_priv_jwk"],
                iss="https://issuer.example.com",
                revoked_indices=[revoked_idx],
            ),
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        def issue(idx: int) -> str:
            return SDJWTWallet.issue_sd_jwt(
                issuer_private_key_jwk=self.keys["iss_priv_jwk"],
                iss="https://issuer.example.com",
                dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
                id_claim="https://agents.example.com/test-agent",
                plaintext_claims={},
                sd_claims={"name": "Test Agent"},
                holder_public_key_jwk=self.keys["holder_pub_jwk"],
                status_list_ref={"idx": idx, "uri": status_uri},
            )

        def present(sd_jwt: str) -> str:
            wallet = SDJWTWallet()
            item = CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
            wallet.add_credential(item)
            return wallet.create_presentation(
                cred_item=item,
                requested_claims=["name"],
                nonce="tsl-nonce",
                client_id=self.client_id,
            )

        verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
            tsl_client=tsl_client,
        )

        # Revoked index -> VP_CREDENTIAL_REVOKED
        with self.assertRaises(CredentialVerificationError) as ctx:
            verifier.verify_presentation(
                presentation_str=present(issue(revoked_idx)),
                nonce="tsl-nonce",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_CREDENTIAL_REVOKED)

        # Clear index -> success
        res = verifier.verify_presentation(
            presentation_str=present(issue(valid_idx)),
            nonce="tsl-nonce",
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        self.assertTrue(res.is_valid)

        # No tsl_client -> fail-closed by default (VP_CREDENTIAL_REVOKED)
        strict_default = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            strict_default.verify_presentation(
                presentation_str=present(issue(revoked_idx)),
                nonce="tsl-nonce",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_CREDENTIAL_REVOKED)

        # Explicit allow_unverified_status opt-out -> check skipped, credential verifies
        lenient = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda i: self.keys["iss_pub_jwk"],
            allow_unverified_status=True,
        )
        self.assertTrue(
            lenient.verify_presentation(
                presentation_str=present(issue(revoked_idx)),
                nonce="tsl-nonce",
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            ).is_valid
        )

    def test_14_authenticated_task_session_discarded_on_terminal_state(self) -> None:
        """Section 5.5 item 4: the session record MUST be discarded at COMPLETED / FAILED / CANCELED."""
        task_id, ctx_id = "task-session-01", "ctx-session-01"

        def terminal_handler(r, v):
            return A2ATaskStatusResponse(
                id=r.id, context_id=r.context_id, state="TASK_STATE_COMPLETED", message={}
            )

        def working_handler(r, v):
            return A2ATaskStatusResponse(
                id=r.id, context_id=r.context_id, state="TASK_STATE_INPUT_REQUIRED", message={}
            )

        # 1. Initial request -> auth-required, nonce is retained.
        challenge_res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                parts=[{"text": "hello"}],
            ),
            working_handler,
        )
        self.assertEqual(challenge_res.state, "TASK_STATE_AUTH_REQUIRED")
        self.assertIn(task_id, self.interceptor.active_nonces)

        nonce = challenge_res.message["metadata"][EXTENSION_URI]["nonce"]

        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=self._create_base_credential(),
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        wallet.add_credential(item)
        vp = wallet.create_vp_token(
            dcql_query=self.interceptor.dcql_query, nonce=nonce, client_id=self.client_id
        )

        def identity_response():
            return A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
                parts=[{"text": "identity response"}],
            )

        # 2. Non-terminal outcome -> session survives (Section 5.5 item 2).
        res = self.interceptor.process_incoming_request(identity_response(), working_handler)
        self.assertEqual(res.state, "TASK_STATE_INPUT_REQUIRED")
        self.assertIn(task_id, self.interceptor.authenticated_tasks)

        # 3. Terminal outcome -> session discarded (Section 5.5 item 4). A routine follow-up on
        #    an authenticated task carries no vp_token (an unsolicited one is rejected, see
        #    test_phase6_defect_fixes.py).
        res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                parts=[{"text": "next turn"}],
            ),
            terminal_handler,
        )
        self.assertEqual(res.state, "TASK_STATE_COMPLETED")
        self.assertNotIn(task_id, self.interceptor.authenticated_tasks)
        self.assertNotIn(task_id, self.interceptor.authenticated_results)
        self.assertNotIn(task_id, self.interceptor.active_nonces)

        # 4. Reusing the task_id no longer bypasses authentication.
        replay = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                parts=[{"text": "replay"}],
            ),
            terminal_handler,
        )
        self.assertEqual(replay.state, "TASK_STATE_AUTH_REQUIRED")

        # 5. close_task_session is idempotent.
        self.interceptor.close_task_session(task_id)
        self.interceptor.close_task_session("never-seen")

    def test_15_step_up_challenge_coexists_with_original_nonce(self) -> None:
        """
        Section 5.5 item 3 / 12.1: a step-up challenge issued mid-task must not disturb the
        existing Authenticated Task Session, nor invalidate any other nonce outstanding for
        the same task_id. Exercises issue_step_up_challenge/verify_step_up_response directly
        against a real generated nonce (never a hardcoded literal).
        """
        task_id, ctx_id = "task-stepup-01", "ctx-stepup-01"

        def working_handler(r, v):
            return A2ATaskStatusResponse(
                id=r.id, context_id=r.context_id, state="TASK_STATE_WORKING", message={}
            )

        # 1. Initial challenge/response authenticates the task normally.
        challenge_res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                parts=[{"text": "hello"}],
            ),
            working_handler,
        )
        self.assertEqual(challenge_res.state, "TASK_STATE_AUTH_REQUIRED")
        initial_nonce = challenge_res.message["metadata"][EXTENSION_URI]["nonce"]

        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=self._create_base_credential(),
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        wallet.add_credential(item)
        vp = wallet.create_vp_token(
            dcql_query=self.interceptor.dcql_query, nonce=initial_nonce, client_id=self.client_id
        )
        res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
                parts=[{"text": "identity response"}],
            ),
            working_handler,
        )
        self.assertEqual(res.state, "TASK_STATE_WORKING")
        self.assertIn(task_id, self.interceptor.authenticated_tasks)
        self.assertNotIn(task_id, self.interceptor.active_nonces)

        # 2. Later in the same task, a second nonce is manually left outstanding to simulate
        #    an unrelated challenge that must NOT be affected by the step-up below.
        self.interceptor.active_nonces.setdefault(task_id, set()).add("unrelated-outstanding-nonce")

        # 3. Issue a genuine step-up challenge (fresh generated nonce, not a hardcoded literal).
        sub_query = DCQLQuery(
            credentials=[DCQLCredentialQuery(id="sub_approval", meta={"vct_values": ["https://example.com/credentials/IngredientSubstitutionApproval/v1"]}, claims=[DCQLClaimQuery(path=["substitute_ingredient"])])]
        )
        step_up_challenge = self.interceptor.issue_step_up_challenge(
            task_id=task_id, dcql_query=sub_query, client_id=self.client_id
        )
        self.assertNotEqual(step_up_challenge.nonce, initial_nonce)
        self.assertIn(step_up_challenge.nonce, self.interceptor.active_nonces[task_id])
        self.assertIn("unrelated-outstanding-nonce", self.interceptor.active_nonces[task_id])

        # 4. Answer the step-up challenge against its own freshly generated nonce.
        sub_wallet = SDJWTWallet()
        sub_item = CredentialItem(
            id="sub_approval",
            sd_jwt_string=SDJWTWallet.issue_sd_jwt(
                issuer_private_key_jwk=self.keys["iss_priv_jwk"],
                iss="https://issuer.example.com",
                dct="https://example.com/credentials/IngredientSubstitutionApproval/v1",
                id_claim="https://example.com/approvals/1",
                plaintext_claims={},
                sd_claims={"substitute_ingredient": "gluten_free_tortilla"},
                holder_public_key_jwk=self.keys["holder_pub_jwk"],
            ),
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        sub_wallet.add_credential(sub_item)
        sub_vp_str = sub_wallet.create_presentation(
            cred_item=sub_item,
            requested_claims=["substitute_ingredient"],
            nonce=step_up_challenge.nonce,
            client_id=self.client_id,
        )

        result = self.interceptor.verify_step_up_response(
            task_id=task_id,
            context_id=ctx_id,
            vp_str=sub_vp_str,
            dcql_query=sub_query,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.disclosed_claims.get("substitute_ingredient"), "gluten_free_tortilla")

        # 5. Consuming the step-up nonce must not affect the unrelated outstanding nonce, nor
        #    the original Authenticated Task Session.
        self.assertIn(task_id, self.interceptor.active_nonces)
        self.assertIn("unrelated-outstanding-nonce", self.interceptor.active_nonces[task_id])
        self.assertNotIn(step_up_challenge.nonce, self.interceptor.active_nonces[task_id])
        self.assertIn(task_id, self.interceptor.authenticated_tasks)
        self.assertIn(task_id, self.interceptor.authenticated_results)

    def test_16_step_up_response_no_active_nonce_raises_vp_nonce_expired(self) -> None:
        """verify_step_up_response with no outstanding nonce for the task must raise VP_NONCE_EXPIRED."""
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.interceptor.verify_step_up_response(
                task_id="never-challenged-task",
                context_id="ctx-16",
                vp_str="irrelevant",
                dcql_query=DCQLQuery(credentials=[DCQLCredentialQuery(id="sub_approval", meta={"vct_values": ["https://example.com/credentials/IngredientSubstitutionApproval/v1"]})]),
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_NONCE_EXPIRED)

    def test_17_nonce_consumed_on_failed_verification_regardless_of_outcome(self) -> None:
        """
        Section 12.1's closing sentence: the nonce MUST be consumed (deleted) after the
        Identity Response is validated, regardless of outcome - including a FAILED
        verification, not only a successful one. A retry using the same (now-expired)
        nonce must be rejected as VP_NONCE_MISMATCH (spec 12.1: a previously used nonce)
        rather than re-attempted.
        """
        task_id, ctx_id = "task-failure-consume-01", "ctx-failure-consume-01"

        def working_handler(r, v):
            return A2ATaskStatusResponse(
                id=r.id, context_id=r.context_id, state="TASK_STATE_WORKING", message={}
            )

        # 1. Initial request -> auth-required, nonce retained.
        challenge_res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                parts=[{"text": "hello"}],
            ),
            working_handler,
        )
        self.assertEqual(challenge_res.state, "TASK_STATE_AUTH_REQUIRED")
        nonce = challenge_res.message["metadata"][EXTENSION_URI]["nonce"]
        self.assertIn(nonce, self.interceptor.active_nonces[task_id])

        # 2. Present a VP whose KB-JWT is signed by a key other than cnf.jwk, so
        #    verify_presentation raises CredentialVerificationError(VP_SIGNATURE_INVALID).
        other_priv, _ = generate_ec_p256_keypair()
        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=self._create_base_credential(),
            holder_private_key_jwk=export_jwk_from_private_key(other_priv),
        )
        wallet.add_credential(item)
        vp = wallet.create_vp_token(
            dcql_query=self.interceptor.dcql_query, nonce=nonce, client_id=self.client_id
        )

        fail_res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
                parts=[{"text": "identity response"}],
            ),
            working_handler,
        )
        self.assertEqual(fail_res.state, "TASK_STATE_FAILED")
        self.assertEqual(
            fail_res.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_SIGNATURE_INVALID.value,
        )

        # 3. The failed nonce MUST be gone - not left outstanding for a retry.
        self.assertNotIn(task_id, self.interceptor.active_nonces)
        self.assertNotIn(task_id, self.interceptor.authenticated_tasks)

        # 4. Retrying with the same (now-consumed) nonce is rejected, not re-verified.
        retry_res = self.interceptor.process_incoming_request(
            A2ATaskMessage(
                channel_id="test-channel",
                id=task_id,
                context_id=ctx_id,
                headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
                metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
                parts=[{"text": "identity response retry"}],
            ),
            working_handler,
        )
        self.assertEqual(retry_res.state, "TASK_STATE_FAILED")
        self.assertEqual(
            retry_res.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_NONCE_MISMATCH.value,
        )


if __name__ == "__main__":
    unittest.main()
