# SPDX-License-Identifier: Apache-2.0
"""
Conformance tests for Phase 4:
- TASK-4.1: demo domain objects live outside the core SDK
- TASK-4.2: Pydantic v2 config, A2A v1.0 canonical states, Initial Requests without a task id
- TASK-4.3: challenge TTL / nonce expiry
- TASK-4.4: kid-based issuer key selection from a JWKS
"""

import importlib
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

import jwt
from cryptography.hazmat.primitives import serialization

import a2a_agentic_id
from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    CredentialItem,
    ErrorCode,
    SDJWTVerifier,
    SDJWTWallet,
    ServerAuthRequiredInterceptor,
    VPFormatsSupported,
)
from a2a_agentic_id.crypto import (
    compute_sha256_base64url,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
    import_private_key_from_jwk,
)
from a2a_agentic_id.interceptor import validate_task_state
from a2a_agentic_id.models import DCQLQuery
from a2a_agentic_id.verifier import CredentialVerificationError

SDK_ROOT = Path(__file__).resolve().parents[4] / "sdk" / "python"
EXTENSION_URI = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"
HEADERS = {"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"}


def _ok_handler(request: A2ATaskMessage, _v: Any) -> A2ATaskStatusResponse:
    return A2ATaskStatusResponse(
        id=request.id, context_id=request.context_id, state="TASK_STATE_WORKING", message={}
    )


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class TestPhase4Remediation(unittest.TestCase):
    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.iss_priv = export_jwk_from_private_key(iss_priv)
        self.iss_pub = export_jwk_from_public_key(iss_pub)
        self.holder_priv = export_jwk_from_private_key(holder_priv)
        self.holder_pub = export_jwk_from_public_key(holder_pub)
        self.client_id = "https://verifier.example.com"
        self.verifier = SDJWTVerifier(
            client_id=self.client_id,
            jwks_resolver=lambda iss: self.iss_pub,
            allow_unverified_status=True,
        )

    # ---------- helpers ----------

    def _credential(self) -> str:
        return SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.iss_priv,
            iss="https://issuer.example.com",
            vct="https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            id_claim="https://agents.example.com/a1",
            sd_claims={"name": "A1", "description": "bot", "owner": "Acme"},
            holder_public_key_jwk=self.holder_pub,
        )

    def _respond(self, nonce: str, task_id: str, context_id: str) -> A2ATaskMessage:
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(
                id="agent_identity",
                sd_jwt_string=self._credential(),
                holder_private_key_jwk=self.holder_priv,
            )
        )
        vp = wallet.create_vp_token(
            DCQLQuery.default_agent_identity_query(), nonce=nonce, client_id=self.client_id
        )
        return A2ATaskMessage(
            channel_id="test-channel",
            id=task_id,
            context_id=context_id,
            headers=HEADERS,
            metadata={EXTENSION_URI: {"vp_token": vp.vp_token}},
            parts=[{"text": "Identity response."}],
        )

    @staticmethod
    def _nonce_of(resp: A2ATaskStatusResponse) -> str:
        return resp.message["metadata"][EXTENSION_URI]["nonce"]

    @staticmethod
    def _error_of(resp: A2ATaskStatusResponse) -> str:
        return resp.message["metadata"][EXTENSION_URI]["error"]

    # ---------- 4.1 ----------

    def test_41_domain_objects_not_in_core_sdk(self) -> None:
        for name in ("OrderState", "OrderPaymentCommitment", "OrderCommitmentSigner",
                     "https://example.com/credentials/IngredientSubstitutionApproval/v1", "SubstitutionIssuer"):
            self.assertFalse(hasattr(a2a_agentic_id, name), name)
        for mod in ("a2a_agentic_id.order", "a2a_agentic_id.substitution"):
            with self.assertRaises(ImportError):
                importlib.import_module(mod)

    def test_41_domain_objects_available_from_restaurant_domain(self) -> None:
        domain = importlib.import_module("restaurant_domain")
        for name in ("OrderPaymentCommitment", "OrderCommitmentSigner", "SubstitutionIssuer"):
            self.assertTrue(hasattr(domain, name), name)

    # ---------- 4.2 ----------

    def test_42_no_pydantic_deprecation_from_models(self) -> None:
        # Fresh interpreter: reloading models in-process would redefine its classes and
        # break isinstance checks in every other test.
        import subprocess
        import sys

        code = (
            "import warnings; warnings.simplefilter('error'); "
            "import a2a_agentic_id.models"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(SDK_ROOT)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_42_vp_formats_alias_roundtrip_still_works(self) -> None:
        f = VPFormatsSupported(**{"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]})
        self.assertEqual(f.model_dump(by_alias=True)["sd-jwt_alg_values"], ["ES256"])
        self.assertEqual(VPFormatsSupported(sd_jwt_alg_values=["ES256"]).sd_jwt_alg_values, ["ES256"])

    def test_42_only_v1_task_states_are_accepted(self) -> None:
        # The SDK speaks A2A v1.0.0 only: canonical states pass, legacy v0.3 spellings do not.
        for ok in ("TASK_STATE_AUTH_REQUIRED", "TASK_STATE_WORKING", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"):
            self.assertEqual(validate_task_state(ok), ok)
        for legacy in ("auth-required", "working", "cancelled", "canceled", "completed", "bogus", ""):
            with self.assertRaises(ValueError, msg=legacy):
                validate_task_state(legacy)

    def test_42_challenge_serialises_canonical_state_on_wire(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        resp = ic.process_incoming_request(
            A2ATaskMessage(channel_id="test-channel", id="t1", context_id="c1", headers=HEADERS), _ok_handler
        )
        self.assertEqual(resp.to_wire()["status"]["state"], "TASK_STATE_AUTH_REQUIRED")
        self.assertEqual(resp.state, "TASK_STATE_AUTH_REQUIRED")  # internal accessor unchanged

    def test_42_initial_request_without_ids_gets_allocated_ids(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        resp = ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", headers=HEADERS), _ok_handler)
        self.assertEqual(resp.state, "TASK_STATE_AUTH_REQUIRED")
        self.assertTrue(resp.id)
        self.assertTrue(resp.context_id)
        # The allocated ids complete the handshake and the buffered request is released.
        seen: List[A2ATaskMessage] = []

        def handler(req: A2ATaskMessage, _v: Any) -> A2ATaskStatusResponse:
            seen.append(req)
            return _ok_handler(req, _v)

        done = ic.process_incoming_request(
            self._respond(self._nonce_of(resp), resp.id, resp.context_id), handler
        )
        self.assertEqual(done.state, "TASK_STATE_WORKING")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].id, resp.id)

    def test_42_two_idless_requests_get_distinct_tasks(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        a = ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", headers=HEADERS), _ok_handler)
        b = ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", headers=HEADERS), _ok_handler)
        self.assertNotEqual(a.id, b.id)

    def test_42_terminal_detection_uses_canonical_states(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        ic.authenticated_tasks.add("t9")
        ic._finalize(A2ATaskStatusResponse(id="t9", context_id="c", state="TASK_STATE_COMPLETED", message={}))
        self.assertNotIn("t9", ic.authenticated_tasks)
        ic.authenticated_tasks.add("t10")
        ic._finalize(A2ATaskStatusResponse(id="t10", context_id="c", state="TASK_STATE_WORKING", message={}))
        self.assertIn("t10", ic.authenticated_tasks)
        # An unknown state is not silently tolerated: the response cannot even be built.
        with self.assertRaises(ValueError):
            A2ATaskStatusResponse(id="t10", context_id="c", state="mystery", message={})
        self.assertIn("t10", ic.authenticated_tasks)

    # ---------- 4.3 ----------

    def test_43_response_within_ttl_accepted(self) -> None:
        clock = _Clock()
        ic = ServerAuthRequiredInterceptor(self.verifier, challenge_ttl=60, time_fn=clock)
        ch = ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=HEADERS), _ok_handler)
        clock.now += 30
        done = ic.process_incoming_request(self._respond(self._nonce_of(ch), "t", "c"), _ok_handler)
        self.assertEqual(done.state, "TASK_STATE_WORKING")

    def test_43_response_after_ttl_returns_nonce_expired(self) -> None:
        clock = _Clock()
        ic = ServerAuthRequiredInterceptor(self.verifier, challenge_ttl=60, time_fn=clock)
        ch = ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=HEADERS), _ok_handler)
        clock.now += 61
        resp = ic.process_incoming_request(self._respond(self._nonce_of(ch), "t", "c"), _ok_handler)
        self.assertEqual(resp.state, "TASK_STATE_FAILED")
        self.assertEqual(self._error_of(resp), ErrorCode.VP_NONCE_EXPIRED.value)
        # Expired nonce is consumed and its time record cleaned up; request buffer dropped.
        self.assertNotIn("t", ic.active_nonces)
        self.assertNotIn("t", ic.nonce_issued_at)
        self.assertNotIn("t", ic.buffered_requests)

    def test_43_unknown_nonce_is_mismatch_not_expired(self) -> None:
        clock = _Clock()
        ic = ServerAuthRequiredInterceptor(self.verifier, challenge_ttl=60, time_fn=clock)
        ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=HEADERS), _ok_handler)
        clock.now += 1000
        resp = ic.process_incoming_request(self._respond("forged-nonce", "t", "c"), _ok_handler)
        self.assertEqual(self._error_of(resp), ErrorCode.VP_NONCE_MISMATCH.value)

    def test_43_ttl_none_disables_expiry(self) -> None:
        clock = _Clock()
        ic = ServerAuthRequiredInterceptor(self.verifier, challenge_ttl=None, time_fn=clock)
        ch = ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=HEADERS), _ok_handler)
        clock.now += 10_000_000
        done = ic.process_incoming_request(self._respond(self._nonce_of(ch), "t", "c"), _ok_handler)
        self.assertEqual(done.state, "TASK_STATE_WORKING")

    def test_43_step_up_challenge_expires(self) -> None:
        clock = _Clock()
        ic = ServerAuthRequiredInterceptor(self.verifier, challenge_ttl=60, time_fn=clock)
        step = ic.issue_step_up_challenge("t", DCQLQuery.default_agent_identity_query())
        self.assertIn(step.nonce, ic.nonce_issued_at["t"])
        wallet = SDJWTWallet()
        wallet.add_credential(
            CredentialItem(id="agent_identity", sd_jwt_string=self._credential(), holder_private_key_jwk=self.holder_priv)
        )
        vp = wallet.create_vp_token(
            DCQLQuery.default_agent_identity_query(), nonce=step.nonce, client_id=self.client_id
        ).vp_token["agent_identity"][0]
        clock.now += 61
        with self.assertRaises(CredentialVerificationError) as ctx:
            ic.verify_step_up_response("t", "c", vp, DCQLQuery.default_agent_identity_query())
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_NONCE_EXPIRED)

    def test_43_close_task_session_clears_issue_times(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=HEADERS), _ok_handler)
        self.assertIn("t", ic.nonce_issued_at)
        ic.close_task_session("t")
        self.assertNotIn("t", ic.nonce_issued_at)

    # ---------- 4.4 ----------

    def _signed(self, kid: Any, key_jwk: Dict[str, Any], typ: Any = "dc+sd-jwt") -> str:
        pem = import_private_key_from_jwk(key_jwk).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        now = int(time.time())
        headers = {} if typ is None else {"typ": typ}
        if kid is not None:
            headers["kid"] = kid
        tok = jwt.encode(
            {"iss": "https://issuer.example.com", "iat": now, "exp": now + 3600,
             "vct": "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1", "id": "a", "cnf": {"jwk": self.holder_pub},
             "_sd_alg": "sha-256"},
            pem, algorithm="ES256", headers=headers,
        )
        return tok + "~"

    def _present(self, sd_jwt: str, nonce: str = "n") -> str:
        pem = import_private_key_from_jwk(self.holder_priv).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        kb = jwt.encode(
            {"nonce": nonce, "aud": self.client_id, "iat": int(time.time()),
             "sd_hash": compute_sha256_base64url(sd_jwt)},
            pem, algorithm="ES256", headers={"typ": "kb+jwt"},
        )
        return sd_jwt + kb

    def _verifier_with(self, resolved: Dict[str, Any]) -> SDJWTVerifier:
        return SDJWTVerifier(client_id=self.client_id, jwks_resolver=lambda iss: resolved,
                             allow_unverified_status=True)

    def test_44_jwks_selects_key_by_kid(self) -> None:
        other_priv, other_pub = generate_ec_p256_keypair()
        other_pub_jwk = export_jwk_from_public_key(other_pub)
        jwks = {"keys": [
            {**other_pub_jwk, "kid": "other"},
            {**self.iss_pub, "kid": "good"},
        ]}
        res = self._verifier_with(jwks).verify_presentation(
            self._present(self._signed("good", self.iss_priv)), nonce="n"
        )
        self.assertTrue(res.is_valid)

    # ---------- S28: Issuer-signed JWT typ (spec 7.3.4 step 2) ----------

    def _issuer_typ_error(self, typ: Any) -> CredentialVerificationError:
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                self._present(self._signed(None, self.iss_priv, typ=typ)), nonce="n"
            )
        return ctx.exception

    def test_s28_issuer_typ_dc_sd_jwt_accepted(self) -> None:
        res = self.verifier.verify_presentation(self._present(self._signed(None, self.iss_priv)), nonce="n")
        self.assertTrue(res.is_valid)

    def test_s28_issuer_typ_missing_rejected(self) -> None:
        err = self._issuer_typ_error(None)
        self.assertEqual(err.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)
        self.assertIn("typ", err.message)

    def test_s28_issuer_typ_wrong_value_rejected(self) -> None:
        for typ in ("JWT", "kb+jwt", "vc+sd-jwt", "statuslist+jwt", "DC+SD-JWT", "application/dc+sd-jwt"):
            self.assertEqual(self._issuer_typ_error(typ).error_code, ErrorCode.VP_FORMAT_UNSUPPORTED, typ)

    def test_s28_issuer_typ_non_string_rejected(self) -> None:
        self.assertEqual(self._issuer_typ_error(["dc+sd-jwt"]).error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)

    def test_s28_issuer_typ_checked_before_signature(self) -> None:
        # A wrong typ is a format problem, not a signature problem, even if the key is also wrong.
        other_priv, _ = generate_ec_p256_keypair()
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(
                self._present(self._signed(None, export_jwk_from_private_key(other_priv), typ="JWT")), nonce="n"
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)

    def test_s28_issued_credentials_carry_typ_and_verify(self) -> None:
        tok = self._credential()
        self.assertEqual(jwt.get_unverified_header(tok.split("~")[0])["typ"], "dc+sd-jwt")

    def test_44_wrong_kid_key_fails_signature(self) -> None:
        other_priv, other_pub = generate_ec_p256_keypair()
        jwks = {"keys": [
            {**export_jwk_from_public_key(other_pub), "kid": "other"},
            {**self.iss_pub, "kid": "good"},
        ]}
        # Token is signed with the issuer key but claims the other key's kid.
        with self.assertRaises(CredentialVerificationError) as ctx:
            self._verifier_with(jwks).verify_presentation(
                self._present(self._signed("other", self.iss_priv)), nonce="n"
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)
        self.assertIn("signature verification failed", str(ctx.exception).lower())

    def test_44_unknown_kid_rejected(self) -> None:
        jwks = {"keys": [{**self.iss_pub, "kid": "good"}]}
        with self.assertRaises(CredentialVerificationError) as ctx:
            self._verifier_with(jwks).verify_presentation(
                self._present(self._signed("nope", self.iss_priv)), nonce="n"
            )
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)
        self.assertIn("No unique key with kid", str(ctx.exception))

    def test_44_multi_key_jwks_without_kid_rejected(self) -> None:
        _, other_pub = generate_ec_p256_keypair()
        jwks = {"keys": [{**export_jwk_from_public_key(other_pub), "kid": "a"}, {**self.iss_pub, "kid": "b"}]}
        with self.assertRaises(CredentialVerificationError) as ctx:
            self._verifier_with(jwks).verify_presentation(
                self._present(self._signed(None, self.iss_priv)), nonce="n"
            )
        self.assertIn("no 'kid'", str(ctx.exception))

    def test_44_single_key_jwks_without_kid_and_bare_jwk_still_work(self) -> None:
        for resolved in ({"keys": [self.iss_pub]}, self.iss_pub):
            res = self._verifier_with(resolved).verify_presentation(
                self._present(self._signed(None, self.iss_priv)), nonce="n"
            )
            self.assertTrue(res.is_valid)

    def test_44_duplicate_kid_rejected(self) -> None:
        jwks = {"keys": [{**self.iss_pub, "kid": "dup"}, {**self.iss_pub, "kid": "dup"}]}
        with self.assertRaises(CredentialVerificationError) as ctx:
            self._verifier_with(jwks).verify_presentation(
                self._present(self._signed("dup", self.iss_priv)), nonce="n"
            )
        self.assertIn("2 matches", str(ctx.exception))


class TestS2TransportChannelBinding(TestPhase4Remediation):
    """Spec 5.5 items 2-3: the Authenticated Task Session is bound to the transport channel."""

    def _open(self, ic: ServerAuthRequiredInterceptor, channel: str = "chan-A") -> A2ATaskStatusResponse:
        ch = ic.process_incoming_request(
            A2ATaskMessage(channel_id=channel, id="t-s2", context_id="c-s2", headers=HEADERS), _ok_handler
        )
        resp = self._respond(self._nonce_of(ch), "t-s2", "c-s2")
        resp.channel_id = channel
        return ic.process_incoming_request(resp, _ok_handler)

    def _follow_up(self, channel):
        return A2ATaskMessage(channel_id=channel, id="t-s2", context_id="c-s2", headers=HEADERS)

    def test_s2_bound_channel_continues_session(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        self.assertEqual(self._open(ic).state, "TASK_STATE_WORKING")
        self.assertEqual(ic.process_incoming_request(self._follow_up("chan-A"), _ok_handler).state, "TASK_STATE_WORKING")

    def test_s2_other_channel_cannot_use_session(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        self._open(ic)
        res = ic.process_incoming_request(self._follow_up("chan-B"), _ok_handler)
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        # Rejecting the stranger does not end the owner's session.
        self.assertIn("t-s2", ic.authenticated_tasks)
        self.assertEqual(ic.process_incoming_request(self._follow_up("chan-A"), _ok_handler).state, "TASK_STATE_WORKING")

    def test_s2_missing_channel_cannot_use_session(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        self._open(ic)
        self.assertEqual(ic.process_incoming_request(self._follow_up(None), _ok_handler).state, "TASK_STATE_FAILED")

    def test_s2_no_session_without_channel(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        ch = ic.process_incoming_request(A2ATaskMessage(id="t-s2", context_id="c-s2", headers=HEADERS), _ok_handler)
        resp = self._respond(self._nonce_of(ch), "t-s2", "c-s2")
        resp.channel_id = None
        res = ic.process_incoming_request(resp, _ok_handler)
        self.assertEqual(res.state, "TASK_STATE_FAILED")
        self.assertNotIn("t-s2", ic.authenticated_tasks)

    def test_s2_opt_out_for_channelless_transports(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier, require_channel_binding=False)
        ch = ic.process_incoming_request(A2ATaskMessage(id="t-s2", context_id="c-s2", headers=HEADERS), _ok_handler)
        resp = self._respond(self._nonce_of(ch), "t-s2", "c-s2")
        resp.channel_id = None
        res = ic.process_incoming_request(resp, _ok_handler)
        self.assertEqual(res.state, "TASK_STATE_WORKING")

    def test_s2_binding_cleared_on_close(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        self._open(ic)
        ic.close_task_session("t-s2")
        self.assertNotIn("t-s2", ic.task_channels)


if __name__ == "__main__":
    unittest.main()
