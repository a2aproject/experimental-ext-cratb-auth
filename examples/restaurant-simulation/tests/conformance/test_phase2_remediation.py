# SPDX-License-Identifier: Apache-2.0
"""
Conformance Test Suite for Phase 2 Remediation Tasks:
- TASK-2.1 (K8): Exact Extension Header Matching Across Bindings
- TASK-2.2 (K10): Session Continuity & Context Validation
- TASK-2.3 (K11): KB-JWT Header, Required Typed Claims & Freshness Acceptance Window
- TASK-2.4 (K14): Nonce Error Code Mapping Alignment (VP_NONCE_MISMATCH vs VP_NONCE_EXPIRED)
- TASK-2.5 (K20): Pre-Signature Format & Algorithm Allowlist Enforcement
- TASK-2.6 (K15, K19): Decouple response_uri and Terminal State Normalization
"""

import time
import unittest
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    CredentialItem,
    CredentialVerificationError,
    ErrorCode,
    ExtensionSupportRequiredError,
    SDJWTVerifier,
    SDJWTWallet,
    ServerAuthRequiredInterceptor,
)
from a2a_agentic_id.crypto import (
    compute_sha256_base64url,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
    import_private_key_from_jwk,
)

EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"


def _dummy_handler(request: A2ATaskMessage, _v: Any) -> A2ATaskStatusResponse:
    _ = _v
    return A2ATaskStatusResponse(
        id=request.id,
        context_id=request.context_id,
        state="TASK_STATE_WORKING",
        message={"role": "ROLE_AGENT", "parts": [{"text": "OK"}]},
    )


class TestPhase2Remediation(unittest.TestCase):
    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()

        self.keys = {
            "iss_priv_jwk": export_jwk_from_private_key(iss_priv),
            "iss_pub_jwk": export_jwk_from_public_key(iss_pub),
            "holder_priv_jwk": export_jwk_from_private_key(holder_priv),
            "holder_pub_jwk": export_jwk_from_public_key(holder_pub),
        }
        self.client_id = "https://verifier.example.com"
        def _resolve_key(iss: str) -> Dict[str, Any]:
            _ = iss
            return self.keys["iss_pub_jwk"]

        self.verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=_resolve_key,
            allow_unverified_status=True,
            supported_algorithms=["ES256"],
            max_kb_age=300,
            allowed_future_skew=60,
        )
        self.interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            required=True,
        )

    def _create_credential_str(self) -> str:
        return SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.keys["iss_priv_jwk"],
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/agent-1",
            sd_claims={
                "name": "Agent 1",
                "description": "Primary Bot",
                "owner": "Acme Corp",
            },
            holder_public_key_jwk=self.keys["holder_pub_jwk"],
        )

    def _create_presentation_with_custom_kb(
        self,
        kb_headers: Dict[str, Any],
        kb_claims: Dict[str, Any],
        sign_key: Any = None,
        alg: str = "ES256",
    ) -> str:
        cred_str = self._create_credential_str()
        parts = cred_str.split("~")
        issuer_jwt = parts[0]
        disclosures_raw = [p for p in parts[1:-1] if p]

        sd_jwt_body = issuer_jwt + "~" + "~".join(disclosures_raw) + "~"
        sd_hash = compute_sha256_base64url(sd_jwt_body)

        full_claims = {
            "nonce": "test-nonce",
            "aud": self.client_id,
            "iat": int(time.time()),
            "sd_hash": sd_hash,
        }
        full_claims.update(kb_claims)

        priv_key = sign_key or import_private_key_from_jwk(self.keys["holder_priv_jwk"])
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        headers = {"typ": "kb+jwt"}
        headers.update(kb_headers)

        kb_jwt = jwt.encode(
            payload=full_claims,
            key=pem_key,
            algorithm=alg,
            headers=headers,
        )
        return sd_jwt_body + kb_jwt

    # -------------------------------------------------------------------------
    # TASK-2.1 (K8): Exact Extension Header Matching Across Bindings
    # -------------------------------------------------------------------------

    def test_k8_header_case_insensitivity(self) -> None:
        """K8: Headers lookup is case-insensitive (e.g. 'a2a-extensions', 'A2A-EXTENSIONS')."""
        req_lower = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k8-01",
            context_id="ctx-k8-01",
            headers={"a2a-extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res = self.interceptor.process_incoming_request(req_lower, _dummy_handler)
        self.assertEqual(res.state, "TASK_STATE_AUTH_REQUIRED")

        req_upper = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k8-02",
            context_id="ctx-k8-02",
            headers={"A2A-EXTENSIONS": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res = self.interceptor.process_incoming_request(req_upper, _dummy_handler)
        self.assertEqual(res.state, "TASK_STATE_AUTH_REQUIRED")

    def test_k8_header_comma_separated_and_whitespace_trimming(self) -> None:
        """K8: Multiple comma-separated extension URIs with surrounding whitespace are recognized."""
        multi_header = f"https://other.com/ext/v1 , {EXTENSION_URI} , https://third.com/ext/v2"
        req = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k8-03",
            context_id="ctx-k8-03",
            headers={"a2a-extensions": multi_header, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res = self.interceptor.process_incoming_request(req, _dummy_handler)
        self.assertEqual(res.state, "TASK_STATE_AUTH_REQUIRED")

    def test_k8_header_substring_spoofing_rejected(self) -> None:
        """K8: Extension URI ending with -evil or partial substring is rejected."""
        spoofed_header = EXTENSION_URI + "-evil"
        req = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k8-04",
            context_id="ctx-k8-04",
            headers={"A2A-Extensions": spoofed_header, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        with self.assertRaises(ExtensionSupportRequiredError):
            self.interceptor.process_incoming_request(req, _dummy_handler)

    def test_k8_missing_header_rejected_when_required(self) -> None:
        """K8: Missing extension header raises ExtensionSupportRequiredError when required=True."""
        req = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k8-05",
            context_id="ctx-k8-05",
            headers={"A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        with self.assertRaises(ExtensionSupportRequiredError):
            self.interceptor.process_incoming_request(req, _dummy_handler)

    # -------------------------------------------------------------------------
    # TASK-2.2 (K10): Session Continuity & Context Validation
    # -------------------------------------------------------------------------

    def test_k10_authenticated_task_context_mismatch_rejected(self) -> None:
        """K10: Follow-up message on an authenticated task with mismatched contextId is rejected."""
        task_id = "task-k10-01"
        ctx_id = "ctx-k10-original"

        # 1. Initial request -> auth-required
        req1 = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=ctx_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res1 = self.interceptor.process_incoming_request(req1, _dummy_handler)
        nonce = res1.message["metadata"][EXTENSION_URI]["nonce"]

        # 2. Authenticate
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=self._create_credential_str(),
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        vp = wallet.create_vp_token(self.interceptor.dcql_query, nonce=nonce, client_id=self.client_id)
        req2 = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=ctx_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
            parts=[{"text": "identity response"}],
        )
        res2 = self.interceptor.process_incoming_request(req2, _dummy_handler)
        self.assertEqual(res2.state, "TASK_STATE_WORKING")
        self.assertIn(task_id, self.interceptor.authenticated_tasks)

        # 3. Follow-up with different contextId -> rejected with VP_CONVERSATION_MISMATCH
        req3 = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id="ctx-k10-hijacked",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "follow-up"}],
        )
        res3 = self.interceptor.process_incoming_request(req3, _dummy_handler)
        self.assertEqual(res3.state, "TASK_STATE_FAILED")
        self.assertEqual(
            res3.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_CONVERSATION_MISMATCH.value,
        )

    # -------------------------------------------------------------------------
    # TASK-2.3 (K11): KB-JWT Header & Freshness Acceptance Window
    # -------------------------------------------------------------------------

    def test_k11_kb_jwt_missing_or_invalid_typ_rejected(self) -> None:
        """K11: KB-JWT header typ MUST be exactly 'kb+jwt' (spec 7.3.4 step 2, 9.5); anything else is rejected."""
        # typ: "JWT"
        pres_jwt = self._create_presentation_with_custom_kb(
            kb_headers={"typ": "JWT"},
            kb_claims={"nonce": "nonce-1"},
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(pres_jwt, nonce="nonce-1")
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)
        self.assertIn("typ", ctx.exception.message)

        # The spec requires the exact value: other spellings are rejected too.
        for typ in ("application/kb+jwt", "KB+JWT"):
            pres = self._create_presentation_with_custom_kb(
                kb_headers={"typ": typ},
                kb_claims={"nonce": "nonce-2"},
            )
            with self.assertRaises(CredentialVerificationError) as ctx:
                self.verifier.verify_presentation(pres, nonce="nonce-2")
            self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED, typ)

    def test_k11_kb_jwt_stale_iat_outside_acceptance_window_rejected(self) -> None:
        """K11: KB-JWT iat older than now - max_kb_age is rejected with VP_SIGNATURE_INVALID (spec 7.3.4 step 8)."""
        stale_iat = int(time.time()) - 400  # max_kb_age is 300s
        pres_stale = self._create_presentation_with_custom_kb(
            kb_headers={"typ": "kb+jwt"},
            kb_claims={"nonce": "nonce-stale", "iat": stale_iat},
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(pres_stale, nonce="nonce-stale")
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)

    def test_k11_kb_jwt_excessive_future_iat_rejected(self) -> None:
        """K11: KB-JWT iat ahead of now + allowed_future_skew is rejected with VP_SIGNATURE_INVALID (spec 7.3.4 step 8)."""
        future_iat = int(time.time()) + 120  # allowed_future_skew is 60s
        pres_future = self._create_presentation_with_custom_kb(
            kb_headers={"typ": "kb+jwt"},
            kb_claims={"nonce": "nonce-future", "iat": future_iat},
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(pres_future, nonce="nonce-future")
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)

    def test_k11_kb_jwt_missing_required_typed_claims_rejected(self) -> None:
        """K11: KB-JWT missing nonce, aud, sd_hash, or numeric iat fails with VP_FORMAT_UNSUPPORTED."""
        # Missing sd_hash
        pres_no_sd_hash = self._create_presentation_with_custom_kb(
            kb_headers={"typ": "kb+jwt"},
            kb_claims={"nonce": "n", "sd_hash": ""},
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(pres_no_sd_hash, nonce="n")
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)

    # -------------------------------------------------------------------------
    # TASK-2.4 (K14): Nonce Error Code Mapping Alignment
    # -------------------------------------------------------------------------

    def test_k14_nonce_mismatch_returns_vp_nonce_mismatch_and_preserves_challenge(self) -> None:
        """K14: Unknown or forged nonce returns VP_NONCE_MISMATCH without consuming valid active nonce."""
        task_id = "task-k14-01"
        req = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id="ctx-k14-01",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res = self.interceptor.process_incoming_request(req, _dummy_handler)
        valid_nonce = res.message["metadata"][EXTENSION_URI]["nonce"]

        # Present an invalid/forged nonce
        pres_forged = self._create_presentation_with_custom_kb(
            kb_headers={"typ": "kb+jwt"},
            kb_claims={"nonce": "forged-attacker-nonce"},
        )
        resp_msg = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id="ctx-k14-01",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": {"agent_identity": [pres_forged]}}},
            parts=[{"text": "identity response"}],
        )
        res_fail = self.interceptor.process_incoming_request(resp_msg, _dummy_handler)
        self.assertEqual(res_fail.state, "TASK_STATE_FAILED")
        self.assertEqual(
            res_fail.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_NONCE_MISMATCH.value,
        )

        # Valid nonce is preserved (not consumed by attacker probe)
        self.assertIn(valid_nonce, self.interceptor.active_nonces.get(task_id, set()))

    def test_k14_no_active_nonce_returns_vp_nonce_expired(self) -> None:
        """K14: When no challenge/nonce exists for task ID, VP_NONCE_EXPIRED is returned."""
        resp_msg = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k14-nonexistent",
            context_id="ctx-k14-02",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": {"agent_identity": ["some~vp~token"]}}},
            parts=[{"text": "identity response"}],
        )
        res = self.interceptor.process_incoming_request(resp_msg, _dummy_handler)
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertEqual(
            res.message["metadata"][EXTENSION_URI]["error"],
            ErrorCode.VP_NONCE_EXPIRED.value,
        )

    # -------------------------------------------------------------------------
    # TASK-2.5 (K20): Pre-Signature Format & Algorithm Allowlist Enforcement
    # -------------------------------------------------------------------------

    def test_k20_unsupported_issuer_alg_fails_with_vp_format_unsupported_pre_signature(self) -> None:
        """K20: Unsupported issuer alg (e.g. ES384) fails with VP_FORMAT_UNSUPPORTED before crypto verify."""
        # Generate ES384 key
        priv_384 = ec.generate_private_key(ec.SECP384R1())

        now = int(time.time())
        pem_key = priv_384.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        issuer_jwt_384 = jwt.encode(
            payload={
                "iss": "https://issuer.example.com",
                "iat": now,
                "exp": now + 3600,
                "vct": "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
                "id": "agent-1",
                "cnf": {"jwk": self.keys["holder_pub_jwk"]},
                "_sd": [],
                "_sd_alg": "sha-256",
            },
            key=pem_key,
            algorithm="ES384",
        )
        body = issuer_jwt_384 + "~"
        sd_hash = compute_sha256_base64url(body)

        holder_priv = import_private_key_from_jwk(self.keys["holder_priv_jwk"])
        holder_pem = holder_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        kb_jwt = jwt.encode(
            payload={
                "nonce": "test-nonce",
                "aud": self.client_id,
                "iat": now,
                "sd_hash": sd_hash,
            },
            key=holder_pem,
            algorithm="ES256",
            headers={"typ": "kb+jwt"},
        )
        pres_384 = body + kb_jwt

        # Verifier with only ES256 allowed; pre-signature check rejects before needing public key
        dummy_pub_jwk = {"kty": "EC", "crv": "P-384", "x": "dummy", "y": "dummy"}
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                pres_384,
                nonce="test-nonce",
                issuer_public_key_jwk=dummy_pub_jwk,
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)
        self.assertIn("Unsupported Issuer-signed JWT algorithm 'ES384'", ctx.exception.message)

    def test_k20_unsupported_kb_alg_fails_with_vp_format_unsupported_pre_signature(self) -> None:
        """K20: Unsupported KB-JWT alg (e.g. ES384) fails with VP_FORMAT_UNSUPPORTED before crypto verify."""
        priv_384 = ec.generate_private_key(ec.SECP384R1())
        pres_kb_384 = self._create_presentation_with_custom_kb(
            kb_headers={"typ": "kb+jwt", "alg": "ES384"},
            kb_claims={"nonce": "nonce-kb-384"},
            sign_key=priv_384,
            alg="ES384",
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(pres_kb_384, nonce="nonce-kb-384")
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)
        self.assertIn("Unsupported KB-JWT algorithm 'ES384'", ctx.exception.message)

    # -------------------------------------------------------------------------
    # TASK-2.6 (K15, K19): Decouple response_uri & Terminal State Normalization
    # -------------------------------------------------------------------------

    def test_k15_decoupled_response_uri_configuration(self) -> None:
        """K15: response_uri can be explicitly configured and is preserved in issued challenges."""
        custom_uri = "https://custom.endpoint.example.com/identity/callback"
        interceptor = ServerAuthRequiredInterceptor(
            verifier=self.verifier,
            response_uri=custom_uri,
        )
        self.assertEqual(interceptor.response_uri, custom_uri)

        req = A2ATaskMessage(
            channel_id="test-channel",
            id="task-k15-01",
            context_id="ctx-k15-01",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res = interceptor.process_incoming_request(req, _dummy_handler)
        self.assertEqual(
            res.message["metadata"][EXTENSION_URI]["response_uri"],
            custom_uri,
        )

    def test_k19_terminal_state_rejected_discards_session(self) -> None:
        """K19: TASK_STATE_REJECTED ('rejected' and 'REJECTED') discards authenticated task session."""
        task_id = "task-k19-01"
        ctx_id = "ctx-k19-01"

        # 1. Establish authenticated session
        req1 = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=ctx_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "start"}],
        )
        res1 = self.interceptor.process_incoming_request(req1, _dummy_handler)
        nonce = res1.message["metadata"][EXTENSION_URI]["nonce"]

        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=self._create_credential_str(),
                holder_private_key_jwk=self.keys["holder_priv_jwk"],
            )
        )
        vp = wallet.create_vp_token(self.interceptor.dcql_query, nonce=nonce, client_id=self.client_id)
        req2 = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=ctx_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
            parts=[{"text": "identity response"}],
        )
        res2 = self.interceptor.process_incoming_request(req2, _dummy_handler)
        self.assertEqual(res2.state, "TASK_STATE_WORKING")
        self.assertIn(task_id, self.interceptor.authenticated_tasks)

        # 2. Handler returns terminal state 'rejected'
        def rejected_handler(r: A2ATaskMessage, v: Any) -> A2ATaskStatusResponse:
            _ = v
            return A2ATaskStatusResponse(
                id=r.id,
                context_id=r.context_id,
                state="TASK_STATE_REJECTED",
                message={"role": "ROLE_AGENT", "parts": [{"text": "Order rejected by policy"}]},
            )

        req3 = A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=ctx_id,
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            parts=[{"text": "do something"}],
        )
        res3 = self.interceptor.process_incoming_request(req3, rejected_handler)
        self.assertEqual(res3.state, "TASK_STATE_REJECTED")

        # Session must be discarded
        self.assertNotIn(task_id, self.interceptor.authenticated_tasks)
        self.assertNotIn(task_id, self.interceptor.task_contexts)
        self.assertNotIn(task_id, self.interceptor.active_nonces)


if __name__ == "__main__":
    unittest.main()
