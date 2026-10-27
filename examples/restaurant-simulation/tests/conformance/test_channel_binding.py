# SPDX-License-Identifier: Apache-2.0
"""
Conformance tests for TLS channel binding of presentations (spec 4.1, 5.5, 7.3.4 step 8, 9.5, 12.8):
- a Verifier that declares `channel_binding` accepts only a KB-JWT whose `channel_binding` claim
  equals the tls-exporter value of the connection the presentation arrived on;
- a presentation that leaks before it is consumed cannot be used over another connection to take
  over the Authenticated Task Session;
- Verifiers that do not declare channel binding behave as before.
"""

import os
import unittest
from typing import Any, Optional

import jwt
from pydantic import ValidationError

from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    AgentCardExtensionParams,
    ClientAuthHandler,
    CredentialItem,
    ErrorCode,
    IdentityChallenge,
    SDJWTVerifier,
    SDJWTWallet,
    ServerAuthRequiredInterceptor,
    TLS_EXPORTER,
    TunneledChallenge,
    encode_tls_exporter,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
)
from a2a_agentic_id.models import DCQLQuery
from a2a_agentic_id.verifier import CredentialVerificationError

EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"
HEADERS = {"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"}


def _ok_handler(request: A2ATaskMessage, _v: Any) -> A2ATaskStatusResponse:
    return A2ATaskStatusResponse(
        id=request.id, context_id=request.context_id, state="TASK_STATE_WORKING", message={}
    )


class _AllowAll:
    def is_terminal_allowed(self, client_id: str) -> bool:
        return True


class TestChannelBinding(unittest.TestCase):
    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.iss_priv = export_jwk_from_private_key(iss_priv)
        self.iss_pub = export_jwk_from_public_key(iss_pub)
        self.holder_priv = export_jwk_from_private_key(holder_priv)
        self.holder_pub = export_jwk_from_public_key(holder_pub)
        self.client_id = "https://verifier.example.com"
        # tls-exporter values of two distinct TLS connections: the Holder's and an attacker's.
        self.cb_holder = encode_tls_exporter(os.urandom(32))
        self.cb_attacker = encode_tls_exporter(os.urandom(32))
        self.wallet = SDJWTWallet()
        self.wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=SDJWTWallet.issue_sd_jwt(
                    issuer_private_key_jwk=self.iss_priv,
                    iss="https://issuer.example.com",
                    vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
                    id_claim="https://agents.example.com/a1",
                    sd_claims={"name": "A1", "description": "bot", "owner": "Acme"},
                    holder_public_key_jwk=self.holder_pub,
                ),
                holder_private_key_jwk=self.holder_priv,
            )
        )

    # ---------- helpers ----------

    def _verifier(self, channel_binding: Optional[list] = None) -> SDJWTVerifier:
        return SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda iss: self.iss_pub,
            allow_unverified_status=True,
            channel_binding=channel_binding,
        )

    def _vp(self, nonce: str, channel_binding: Optional[str]) -> str:
        resp = self.wallet.create_vp_token(
            DCQLQuery.default_agent_identity_query(),
            nonce=nonce,
            client_id=self.client_id,
            channel_binding=channel_binding,
        )
        return resp.vp_token["agent_identity"][0]

    @staticmethod
    def _kb_payload(vp: str) -> dict:
        return jwt.decode(vp.split("~")[-1], options={"verify_signature": False})

    def _verify_error(self, verifier: SDJWTVerifier, vp: str, tls_exporter: Optional[str]) -> ErrorCode:
        with self.assertRaises(CredentialVerificationError) as ctx:
            verifier.verify_presentation(vp, nonce="n", tls_exporter=tls_exporter)
        return ctx.exception.error_code

    def _challenge(self, ic: ServerAuthRequiredInterceptor, channel: str, cb: str) -> str:
        ch = ic.process_incoming_request(
            A2ATaskMessage(channel_id=channel, tls_exporter=cb, id="t-cb", context_id="c-cb", headers=HEADERS),
            _ok_handler,
        )
        return ch.message["metadata"][EXTENSION_URI]["nonce"]

    @staticmethod
    def _response(vp: str, channel: str, cb: Optional[str]) -> A2ATaskMessage:
        return A2ATaskMessage(
            channel_id=channel,
            tls_exporter=cb,
            id="t-cb",
            context_id="c-cb",
            headers=HEADERS,
            metadata={EXTENSION_URI: {"vp_token": {"agent_identity": [vp]}}},
            parts=[{"text": "Identity response."}],
        )

    # ---------- verifier (spec 7.3.4 step 8) ----------

    def test_matching_channel_binding_accepted(self) -> None:
        res = self._verifier([TLS_EXPORTER]).verify_presentation(
            self._vp("n", self.cb_holder), nonce="n", tls_exporter=self.cb_holder
        )
        self.assertTrue(res.is_valid)
        self.assertEqual(res.kb_jwt_payload["channel_binding"], self.cb_holder)

    def test_missing_claim_rejected(self) -> None:
        code = self._verify_error(self._verifier([TLS_EXPORTER]), self._vp("n", None), self.cb_holder)
        self.assertEqual(code, ErrorCode.VP_CHANNEL_BINDING_MISMATCH)

    def test_presentation_from_another_connection_rejected(self) -> None:
        code = self._verify_error(self._verifier([TLS_EXPORTER]), self._vp("n", self.cb_holder), self.cb_attacker)
        self.assertEqual(code, ErrorCode.VP_CHANNEL_BINDING_MISMATCH)

    def test_unavailable_exporter_fails_closed(self) -> None:
        code = self._verify_error(self._verifier([TLS_EXPORTER]), self._vp("n", self.cb_holder), None)
        self.assertEqual(code, ErrorCode.VP_CHANNEL_BINDING_MISMATCH)

    def test_undeclared_verifier_ignores_claim(self) -> None:
        verifier = self._verifier()
        for vp in (self._vp("n", None), self._vp("n", self.cb_holder)):
            self.assertTrue(verifier.verify_presentation(vp, nonce="n").is_valid)

    def test_channel_binding_checked_after_audience(self) -> None:
        # Spec 7.3.4 step 8 order: aud is checked before channel binding.
        vp = self.wallet.create_vp_token(
            DCQLQuery.default_agent_identity_query(), nonce="n", client_id="https://other.example.com",
            channel_binding=self.cb_attacker,
        ).vp_token["agent_identity"][0]
        code = self._verify_error(self._verifier([TLS_EXPORTER]), vp, self.cb_holder)
        self.assertEqual(code, ErrorCode.VP_AUDIENCE_MISMATCH)

    # ---------- configuration and encoding (spec 4.1, 9.5) ----------

    def test_unknown_channel_binding_type_rejected(self) -> None:
        for bad in ([], ["tls-unique"]):
            with self.assertRaises(ValueError):
                self._verifier(bad)
            with self.assertRaises(ValidationError):
                AgentCardExtensionParams(channel_binding=bad)
        self.assertEqual(AgentCardExtensionParams(channel_binding=[TLS_EXPORTER]).channel_binding, [TLS_EXPORTER])
        self.assertIsNone(AgentCardExtensionParams().channel_binding)

    def test_exporter_encoding(self) -> None:
        encoded = encode_tls_exporter(bytes(range(32)))
        self.assertNotIn("=", encoded)
        self.assertEqual(len(encoded), 43)
        for bad in (b"", bytes(31), bytes(33), "not-bytes"):
            with self.assertRaises(ValueError):
                encode_tls_exporter(bad)  # type: ignore[arg-type]

    def test_wallet_omits_claim_unless_given(self) -> None:
        self.assertNotIn("channel_binding", self._kb_payload(self._vp("n", None)))
        self.assertEqual(self._kb_payload(self._vp("n", self.cb_holder))["channel_binding"], self.cb_holder)

    def test_tunneled_presentation_never_channel_bound(self) -> None:
        # Spec 12.6.1 / 12.8: the terminal verifier receives the VP over the relay's connection.
        tunneled = TunneledChallenge(
            origin_task_id="t-terminal",
            challenge=IdentityChallenge(
                nonce="n-terminal",
                dcql_query=DCQLQuery.default_agent_identity_query(),
                client_id=self.client_id,
                response_uri=self.client_id + "/a2a",
            ),
        )
        meta = ClientAuthHandler(self.wallet).handle_tunneled_challenge(tunneled, tunnel_policy=_AllowAll())
        vp = meta[EXTENSION_URI]["tunneled_response"]["response"]["agent_identity"][0]
        self.assertNotIn("channel_binding", self._kb_payload(vp))

    # ---------- interceptor: session takeover with a leaked presentation (spec 5.5, 12.8) ----------

    def test_session_bound_to_proven_connection(self) -> None:
        ic = ServerAuthRequiredInterceptor(self._verifier([TLS_EXPORTER]))
        nonce = self._challenge(ic, "chan-holder", self.cb_holder)
        res = ic.process_incoming_request(self._response(self._vp(nonce, self.cb_holder), "chan-holder", self.cb_holder), _ok_handler)
        self.assertEqual(res.state, "TASK_STATE_WORKING")
        self.assertEqual(ic.task_channels["t-cb"], "chan-holder")

    def test_leaked_presentation_cannot_take_over_session(self) -> None:
        ic = ServerAuthRequiredInterceptor(self._verifier([TLS_EXPORTER]))
        nonce = self._challenge(ic, "chan-holder", self.cb_holder)
        leaked = self._vp(nonce, self.cb_holder)
        # The attacker submits the leaked presentation first, over its own connection.
        res = ic.process_incoming_request(self._response(leaked, "chan-attacker", self.cb_attacker), _ok_handler)
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertEqual(res.message["metadata"][EXTENSION_URI]["error"], ErrorCode.VP_CHANNEL_BINDING_MISMATCH.value)
        self.assertNotIn("t-cb", ic.authenticated_tasks)
        self.assertNotIn("t-cb", ic.task_channels)

    def test_without_channel_binding_leaked_presentation_takes_over_session(self) -> None:
        # The weakness that channel binding closes: an undeclared Verifier binds the session to
        # whichever connection delivers a valid presentation first.
        ic = ServerAuthRequiredInterceptor(self._verifier())
        nonce = self._challenge(ic, "chan-holder", self.cb_holder)
        leaked = self._vp(nonce, None)
        res = ic.process_incoming_request(self._response(leaked, "chan-attacker", self.cb_attacker), _ok_handler)
        self.assertEqual(res.state, "TASK_STATE_WORKING")
        self.assertEqual(ic.task_channels["t-cb"], "chan-attacker")

    def test_step_up_requires_binding_to_session_connection(self) -> None:
        ic = ServerAuthRequiredInterceptor(self._verifier([TLS_EXPORTER]))
        nonce = self._challenge(ic, "chan-holder", self.cb_holder)
        ic.process_incoming_request(self._response(self._vp(nonce, self.cb_holder), "chan-holder", self.cb_holder), _ok_handler)

        query = DCQLQuery.default_agent_identity_query()
        step = ic.issue_step_up_challenge("t-cb", query)
        with self.assertRaises(CredentialVerificationError) as ctx:
            ic.verify_step_up_response("t-cb", "c-cb", self._vp(step.nonce, self.cb_attacker), query, tls_exporter=self.cb_holder)
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_CHANNEL_BINDING_MISMATCH)

        step = ic.issue_step_up_challenge("t-cb", query)
        res = ic.verify_step_up_response("t-cb", "c-cb", self._vp(step.nonce, self.cb_holder), query, tls_exporter=self.cb_holder)
        self.assertTrue(res.is_valid)


if __name__ == "__main__":
    unittest.main()
