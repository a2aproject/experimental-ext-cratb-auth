# SPDX-License-Identifier: Apache-2.0
"""
Conformance Test Suite for Phase 1 Remediation Tasks:
- TASK-1.1 (K1): Enforce Credential Type (vct/dct) in Verifier
- TASK-1.2 (K6): Wallet Candidate Selection by DCQL Query
- TASK-1.3 (K9): Pre-Auth Request Buffering in Verifier Interceptor
- TASK-1.4 (K12): Multi-Credential DCQL Verification
"""

import time
import unittest
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization

from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    CredentialItem,
    CredentialVerificationError,
    DCQLClaimQuery,
    DCQLCredentialQuery,
    DCQLQuery,
    ErrorCode,
    SDJWTVerifier,
    SDJWTWallet,
    ServerAuthRequiredInterceptor,
    VerificationResult,
)
from a2a_agentic_id.crypto import (
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
    import_private_key_from_jwk,
)

EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"


def _dummy_handler(request: A2ATaskMessage, _v: Any) -> A2ATaskStatusResponse:
    return A2ATaskStatusResponse(
        id=request.id,
        context_id=request.context_id,
        state="TASK_STATE_COMPLETED",
        message={},
    )


class TestPhase1Remediation(unittest.TestCase):
    def setUp(self) -> None:
        # Generate Issuer and Holder keys
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()

        self.keys = {
            "iss_priv_jwk": export_jwk_from_private_key(iss_priv),
            "iss_pub_jwk": export_jwk_from_public_key(iss_pub),
            "holder_priv_jwk": export_jwk_from_private_key(holder_priv),
            "holder_pub_jwk": export_jwk_from_public_key(holder_pub),
        }
        self.client_id = "https://verifier.example.com"
        self.verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda _iss: self.keys["iss_pub_jwk"],
            allow_unverified_status=True,
        )

    # -------------------------------------------------------------------------
    # TASK-1.1 (K1): Enforce Credential Type in Verifier
    # -------------------------------------------------------------------------

    def test_k1_credential_type_vct_matching_meta_vct_values(self) -> None:
        """K1: Presentation with valid vct matching meta.vct_values succeeds."""
        vct_uri = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct=vct_uri,
            id_claim="https://agents.example.com/agent-1",
            sd_claims={"name": "Agent One"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=sd_jwt,
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        wallet.add_credential(item)

        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": [vct_uri]},
                    claims=[DCQLClaimQuery(path=["name"])],
                )
            ]
        )
        vp_resp = wallet.create_vp_token(query, nonce="nonce-k1-1", client_id=self.client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        res = self.verifier.verify_presentation(
            presentation_str=vp_str,
            nonce="nonce-k1-1",
            dcql_query=query,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        self.assertTrue(res.is_valid)
        self.assertEqual(res.credential_type, vct_uri)

    def test_k1_credential_type_mismatch_rejected(self) -> None:
        """K1: Presentation with vct that does not match meta.vct_values raises VP_DCQL_UNSATISFIED."""
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://example.com/credentials/WrongCredentialType/v1",
            id_claim="https://agents.example.com/agent-wrong",
            sd_claims={"name": "Wrong Type Agent"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=sd_jwt,
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        wallet.add_credential(item)

        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                    claims=[DCQLClaimQuery(path=["name"])],
                )
            ]
        )
        # The wallet now refuses to present a wrong-type credential (K6), so build the
        # presentation directly to exercise the verifier's own type check.
        vp_str = wallet.create_presentation(item, [], nonce="nonce-k1-2", client_id=self.client_id)

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                presentation_str=vp_str,
                nonce="nonce-k1-2",
                dcql_query=query,
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)
        self.assertIn("does not satisfy requested vct_values", ctx.exception.message)

    def test_k1_credential_missing_vct_and_dct_rejected(self) -> None:
        """K1: Token missing both vct and dct when meta.vct_values is specified raises VP_DCQL_UNSATISFIED."""
        now = int(time.time())
        priv_key = import_private_key_from_jwk(self.keys["iss_priv_jwk"])
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Omit both vct and dct
        issuer_jwt = jwt.encode(
            payload={
                "iss": "https://issuer.example.com",
                "iat": now,
                "exp": now + 3600,
                "id": "https://agents.example.com/notype",
                "cnf": {"jwk": self.keys["holder_pub_jwk"]},
                "_sd": [],
                "_sd_alg": "sha-256",
            },
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "dc+sd-jwt"},
        )
        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=issuer_jwt + "~",
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        wallet.add_credential(item)

        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                )
            ]
        )
        vp_str = wallet.create_presentation(item, [], nonce="nonce-k1-3", client_id=self.client_id)

        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                presentation_str=vp_str,
                nonce="nonce-k1-3",
                dcql_query=query,
                issuer_public_key_jwk=self.keys["iss_pub_jwk"],
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)
        self.assertIn("missing the required 'vct'", ctx.exception.message.lower())

    def test_k1_dct_parameter_is_a_deprecated_alias_that_sets_vct(self) -> None:
        """S28: the issuer helper's `dct` argument sets `vct`; no `dct` claim is written."""
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            dct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/legacy-bot",
            sd_claims={"name": "Legacy Bot"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        item = CredentialItem(
            id="agent_identity",
            sd_jwt_string=sd_jwt,
            holder_private_key_jwk=self.keys["holder_priv_jwk"],
        )
        wallet.add_credential(item)

        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                    claims=[DCQLClaimQuery(path=["name"])],
                )
            ]
        )
        vp_resp = wallet.create_vp_token(query, nonce="nonce-k1-4", client_id=self.client_id)
        vp_str = vp_resp.vp_token["agent_identity"][0]

        res = self.verifier.verify_presentation(
            presentation_str=vp_str,
            nonce="nonce-k1-4",
            dcql_query=query,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        self.assertTrue(res.is_valid)
        self.assertEqual(res.credential_type, "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1")
        payload = jwt.decode(sd_jwt.split("~")[0], options={"verify_signature": False})
        self.assertEqual(payload["vct"], "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1")
        self.assertNotIn("dct", payload)

    # -------------------------------------------------------------------------
    # TASK-1.2 (K6): Wallet Candidate Selection by DCQL Query
    # -------------------------------------------------------------------------

    def test_k6_wallet_candidate_selection_arbitrary_query_id(self) -> None:
        """K6: Wallet candidate discovery fulfills query with arbitrary query ID."""
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/candidate-agent",
            sd_claims={"name": "Candidate Agent"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        # Stored under internal wallet ID 'my_internal_storage_key_42'
        wallet.add_credential(
            CredentialItem(
                id="my_internal_storage_key_42",
                sd_jwt_string=sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        # Verifier asks for arbitrary query ID 'query_xyz_99'
        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="query_xyz_99",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                    claims=[DCQLClaimQuery(path=["name"])],
                )
            ]
        )
        vp_resp = wallet.create_vp_token(query, nonce="nonce-k6-1", client_id=self.client_id)
        self.assertIn("query_xyz_99", vp_resp.vp_token)
        self.assertEqual(len(vp_resp.vp_token["query_xyz_99"]), 1)

    def test_k6_wallet_candidate_selection_by_claims_availability(self) -> None:
        """K6: Candidate selection chooses credential containing requested claims."""
        # Credential A: has 'name' only
        cred_a = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://example.com/credentials/EmployeeCredential/v1",
            id_claim="https://agents.example.com/emp-a",
            sd_claims={"name": "Emp A"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        # Credential B: has 'name' and 'role'
        cred_b = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://example.com/credentials/EmployeeCredential/v1",
            id_claim="https://agents.example.com/emp-b",
            sd_claims={"name": "Emp B", "role": "senior_chef"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="storage_a",
                sd_jwt_string=cred_a,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        wallet.add_credential(
            CredentialItem(
                id="storage_b",
                sd_jwt_string=cred_b,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        # Query requires 'role'
        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="chef_query",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://example.com/credentials/EmployeeCredential/v1"]},
                    claims=[DCQLClaimQuery(path=["role"])],
                )
            ]
        )
        vp_resp = wallet.create_vp_token(query, nonce="nonce-k6-2", client_id=self.client_id)
        vp_str = vp_resp.vp_token["chef_query"][0]

        res = self.verifier.verify_presentation(
            presentation_str=vp_str,
            nonce="nonce-k6-2",
            single_cred_query=query.credentials[0],
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        self.assertEqual(res.disclosed_claims["role"], "senior_chef")

    def test_k6_wallet_candidate_selection_fails_when_unmatched(self) -> None:
        """K6: Wallet raises ValueError when no stored credential can satisfy query."""
        wallet = SDJWTWallet()
        # Holds credential with format 'dc+sd-jwt', but with claims that do not include 'clearance'
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://example.com/credentials/EmployeeCredential/v1",
            id_claim="https://agents.example.com/emp-1",
            sd_claims={"name": "Emp 1"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet.add_credential(
            CredentialItem(
                id="emp_basic",
                sd_jwt_string=sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        query = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="secure_query",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://example.com/credentials/EmployeeCredential/v1"]},
                    claims=[DCQLClaimQuery(path=["clearance_level"])],
                )
            ]
        )
        with self.assertRaises(ValueError) as ctx:
            wallet.create_vp_token(query, nonce="nonce-k6-3", client_id=self.client_id)
        self.assertIn("secure_query", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TASK-1.3 (K9): Pre-Auth Request Buffering in Verifier Interceptor
    # -------------------------------------------------------------------------

    def test_k9_business_handler_receives_buffered_original_request(self) -> None:
        """K9: Downstream handler receives original request payload, not 'Identity response.'."""
        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        task_id = "task-k9-order-001"
        context_id = "ctx-k9-001"
        dispatched_payloads = []

        def business_handler(request: A2ATaskMessage, v_res: VerificationResult) -> A2ATaskStatusResponse:
            dispatched_payloads.append(request)
            return A2ATaskStatusResponse(
                id=request.id,
                context_id=request.context_id,
                state="TASK_STATE_COMPLETED",
                message={"role": "ROLE_AGENT", "parts": [{"text": "Order Accepted"}]},
            )

        # 1. Initial Request with actual user order text
        initial_order_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "Prepare 2x Espresso and 1x Croissant"}],
            metadata={"user_order_id": "ord-777"},
        )

        resp1 = interceptor.process_incoming_request(initial_order_msg, business_handler)
        self.assertEqual(resp1.state, "TASK_STATE_AUTH_REQUIRED")
        self.assertEqual(len(dispatched_payloads), 0, "Business handler must NOT be invoked pre-auth")
        self.assertIn(task_id, interceptor.buffered_requests)

        # 2. Holder builds valid VP
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/customer-agent",
            sd_claims={
                "name": "Customer Bot",
                "description": "Automated ordering agent",
                "owner": {"id": "user-123", "name": "Alice"},
            },
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        challenge_meta = resp1.message["metadata"][EXTENSION_URI]
        nonce = challenge_meta["nonce"]
        vp_resp = wallet.create_vp_token(
            interceptor.dcql_query,
            nonce=nonce,
            client_id=self.client_id,
            conversation_id=context_id,
        )

        # 3. Follow-up Identity Response containing 'Identity response.'
        identity_resp_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "Identity response."}],
            metadata={
                EXTENSION_URI: {"vp_token": vp_resp.vp_token},
                "payment_token": "pay_tok_xyz",
            },
        )

        resp2 = interceptor.process_incoming_request(identity_resp_msg, business_handler)
        self.assertEqual(resp2.state, "TASK_STATE_COMPLETED")
        self.assertEqual(len(dispatched_payloads), 1, "Business handler must be invoked exactly once")

        # Verify the dispatched request payload
        dispatched_req = dispatched_payloads[0]
        self.assertEqual(dispatched_req.id, task_id)
        # Crucial K9 verification: the text parts must be the original prompt, NOT "Identity response."
        self.assertEqual(
            dispatched_req.parts,
            [{"text": "Prepare 2x Espresso and 1x Croissant"}],
        )
        # The released request is the immutable original snapshot: the Identity Response's
        # metadata (vp_token, payment_token) is never merged into it (spec 7.3.5).
        self.assertEqual(dispatched_req.metadata["user_order_id"], "ord-777")
        self.assertNotIn("payment_token", dispatched_req.metadata)
        self.assertNotIn(EXTENSION_URI, dispatched_req.metadata)
        # Buffer was popped
        self.assertNotIn(task_id, interceptor.buffered_requests)

    def test_k9_fail_closed_when_buffered_request_missing(self) -> None:
        """K9: Identity Response without buffered request fails closed with VP_MISSING."""
        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        task_id = "task-k9-missing-buf"
        context_id = "ctx-k9-missing-buf"

        # Simulate challenge issued and nonce registered, but buffered request missing
        interceptor.active_nonces.setdefault(task_id, set()).add("active-nonce-k9")
        interceptor.task_contexts[task_id] = context_id

        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/bot",
            sd_claims={
                "name": "Bot",
                "description": "Test Bot",
                "owner": {"id": "user-456", "name": "Bob"},
            },
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        vp_resp = wallet.create_vp_token(
            interceptor.dcql_query,
            nonce="active-nonce-k9",
            client_id=self.client_id,
            conversation_id=context_id,
        )

        resp_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp_resp.vp_token}},
            parts=[{"text": "Identity response."}],
        )

        res = interceptor.process_incoming_request(resp_msg, lambda _r, _v: None)  # type: ignore[return-value]
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertEqual(res.message["metadata"][EXTENSION_URI]["error"], ErrorCode.VP_MISSING.value)

    def test_k9_buffer_cleanup_on_verification_failure(self) -> None:
        """K9: Buffered request is discarded on verification failure."""
        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )
        task_id = "task-k9-cleanup"
        context_id = "ctx-k9-cleanup"

        init_req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "Initial payload"}],
        )
        resp1 = interceptor.process_incoming_request(init_req, lambda r, v: None)  # type: ignore[return-value]
        self.assertEqual(resp1.state, "TASK_STATE_AUTH_REQUIRED")
        self.assertIn(task_id, interceptor.buffered_requests)

        # Send tampered presentation that fails signature check
        bad_resp_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": {"agent_identity": ["corrupted~jwt~tampered"]}}},
            parts=[{"text": "Identity response."}],
        )
        resp2 = interceptor.process_incoming_request(bad_resp_msg, lambda r, v: None)  # type: ignore[return-value]
        self.assertEqual(resp2.state, "TASK_STATE_FAILED")
        # Buffer cleaned up
        self.assertNotIn(task_id, interceptor.buffered_requests)

    # -------------------------------------------------------------------------
    # TASK-1.4 (K12): Multi-Credential DCQL Verification
    # -------------------------------------------------------------------------

    def test_k12_multi_credential_dcql_verification_success(self) -> None:
        """K12: Multi-credential DCQL verification verifies all presented credentials."""
        # 1. Base Agent Identity Credential
        agent_id_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/staff-01",
            sd_claims={"name": "Staff Agent 01"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        # 2. Domain Employee Credential
        emp_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://example.com/credentials/EmployeeCredential/v1",
            id_claim="https://agents.example.com/staff-01",
            sd_claims={"role": "head_chef", "clearance": "level_3"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=agent_id_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        wallet.add_credential(
            CredentialItem(
                id="emp_credential",
                sd_jwt_string=emp_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        # DCQL query requesting BOTH credentials
        multi_dcql = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                    claims=[DCQLClaimQuery(path=["name"])],
                ),
                DCQLCredentialQuery(
                    id="emp_credential",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://example.com/credentials/EmployeeCredential/v1"]},
                    claims=[DCQLClaimQuery(path=["role"]), DCQLClaimQuery(path=["clearance"])],
                ),
            ]
        )

        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            dcql_query=multi_dcql,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        task_id = "task-k12-multi-001"
        context_id = "ctx-k12-001"
        verification_results_captured = []

        def handler(req: A2ATaskMessage, res: VerificationResult) -> A2ATaskStatusResponse:
            verification_results_captured.append(res)
            return A2ATaskStatusResponse(id=req.id, context_id=req.context_id, state="TASK_STATE_COMPLETED", message={})

        # Challenge
        init_req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "Execute kitchen prep"}],
        )
        ch_resp = interceptor.process_incoming_request(init_req, handler)
        self.assertEqual(ch_resp.state, "TASK_STATE_AUTH_REQUIRED")
        nonce = ch_resp.message["metadata"][EXTENSION_URI]["nonce"]

        # Holder creates presentations for both queries
        vp_resp = wallet.create_vp_token(
            multi_dcql,
            nonce=nonce,
            client_id=self.client_id,
            conversation_id=context_id,
        )
        self.assertIn("agent_identity", vp_resp.vp_token)
        self.assertIn("emp_credential", vp_resp.vp_token)

        # Send response
        ans_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp_resp.vp_token}},
            parts=[{"text": "Identity response."}],
        )
        final_resp = interceptor.process_incoming_request(ans_msg, handler)
        self.assertEqual(final_resp.state, "TASK_STATE_COMPLETED")
        self.assertEqual(len(verification_results_captured), 1)

        composite: VerificationResult = verification_results_captured[0]
        self.assertTrue(composite.is_valid)
        # Check that individual query results are accessible via get_credential_result
        agent_res = composite.get_credential_result("agent_identity")
        self.assertIsNotNone(agent_res)
        self.assertEqual(agent_res.disclosed_claims["name"], "Staff Agent 01")

        emp_res = composite.get_credential_result("emp_credential")
        self.assertIsNotNone(emp_res)
        self.assertEqual(emp_res.disclosed_claims["role"], "head_chef")
        self.assertEqual(emp_res.disclosed_claims["clearance"], "level_3")

        # Disclosed claims are aggregated in composite
        self.assertEqual(composite.disclosed_claims["name"], "Staff Agent 01")
        self.assertEqual(composite.disclosed_claims["role"], "head_chef")
        self.assertEqual(composite.disclosed_claims["clearance"], "level_3")

    def test_k12_multi_credential_fails_if_any_query_missing(self) -> None:
        """K12: Handshake fails with VP_DCQL_UNSATISFIED if any required credential query is missing."""
        multi_dcql = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                ),
                DCQLCredentialQuery(
                    id="emp_credential",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://example.com/credentials/EmployeeCredential/v1"]},
                ),
            ]
        )
        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            dcql_query=multi_dcql,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        task_id = "task-k12-partial"
        context_id = "ctx-k12-partial"

        init_req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "Prep"}],
        )
        ch_resp = interceptor.process_incoming_request(init_req, lambda r, v: None)  # type: ignore[return-value]
        self.assertEqual(ch_resp.state, "TASK_STATE_AUTH_REQUIRED")
        nonce = ch_resp.message["metadata"][EXTENSION_URI]["nonce"]

        # Only present agent_identity; omit emp_credential
        sd_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/bot",
            sd_claims={"name": "Bot"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=sd_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        single_query = DCQLQuery(credentials=[multi_dcql.credentials[0]])
        vp_resp = wallet.create_vp_token(single_query, nonce=nonce, client_id=self.client_id)

        ans_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp_resp.vp_token}},
            parts=[{"text": "Identity response."}],
        )
        res = interceptor.process_incoming_request(ans_msg, lambda r, v: None)  # type: ignore[return-value]
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertEqual(res.message["metadata"][EXTENSION_URI]["error"], ErrorCode.VP_DCQL_UNSATISFIED.value)
        self.assertIn("emp_credential", res.message["parts"][0]["text"])

    def test_k12_multi_credential_atomic_failure_on_invalid_presentation(self) -> None:
        """K12: Handshake fails atomically if one credential is valid but another is invalid."""
        # 1. Valid Agent Identity
        agent_id_jwt = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/staff-02",
            sd_claims={"name": "Staff Agent 02"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )
        # 2. Forged Employee Credential (signed by untrusted key)
        attacker_priv, _ = generate_ec_p256_keypair()
        emp_jwt_forged = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=export_jwk_from_private_key(attacker_priv),
            iss="https://issuer.example.com",
            vct="https://example.com/credentials/EmployeeCredential/v1",
            id_claim="https://agents.example.com/staff-02",
            sd_claims={"role": "chef"},
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=agent_id_jwt,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        wallet.add_credential(
            CredentialItem(
                id="emp_credential",
                sd_jwt_string=emp_jwt_forged,
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )

        multi_dcql = DCQLQuery(
            credentials=[
                DCQLCredentialQuery(
                    id="agent_identity",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]},
                    claims=[DCQLClaimQuery(path=["name"])],
                ),
                DCQLCredentialQuery(
                    id="emp_credential",
                    format="dc+sd-jwt",
                    meta={"vct_values": ["https://example.com/credentials/EmployeeCredential/v1"]},
                    claims=[DCQLClaimQuery(path=["role"])],
                ),
            ]
        )

        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
            dcql_query=multi_dcql,
            issuer_public_key_jwk=self.keys["iss_pub_jwk"],
        )

        task_id = "task-k12-atomic-fail"
        context_id = "ctx-k12-atomic-fail"

        init_req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "Prep"}],
        )
        ch_resp = interceptor.process_incoming_request(init_req, lambda r, v: None)  # type: ignore[return-value]
        nonce = ch_resp.message["metadata"][EXTENSION_URI]["nonce"]

        vp_resp = wallet.create_vp_token(
            multi_dcql,
            nonce=nonce,
            client_id=self.client_id,
            conversation_id=context_id,
        )

        ans_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp_resp.vp_token}},
            parts=[{"text": "Identity response."}],
        )
        res = interceptor.process_incoming_request(ans_msg, lambda r, v: None)  # type: ignore[return-value]
        # Must fail with signature error
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertEqual(res.message["metadata"][EXTENSION_URI]["error"], ErrorCode.VP_SIGNATURE_INVALID.value)
        # Nonce was consumed
        self.assertNotIn(task_id, interceptor.active_nonces)
        # Session was NOT authenticated
        self.assertNotIn(task_id, interceptor.authenticated_tasks)
        # Buffer was cleaned up
        self.assertNotIn(task_id, interceptor.buffered_requests)


if __name__ == "__main__":
    unittest.main()
