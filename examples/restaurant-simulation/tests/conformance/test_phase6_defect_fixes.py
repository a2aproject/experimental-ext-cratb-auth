# SPDX-License-Identifier: Apache-2.0
"""
Regression tests for the SDK defects found while verifying the remediation backlog:
K1 (exact vct), K6 (wallet selection), K10/S2 (unsolicited vp_token, task-id entropy),
S18 (VP_MISSING / VP_KEY_BINDING_MISSING), S19 (VP_MALFORMED), S20 (plaintext id / vct),
K14 (consumed-nonce replay), K9/S3 (bounded buffer, atomic release, no metadata merge).
"""

import threading
import time
import unittest
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    CredentialItem,
    DCQLQuery,
    ErrorCode,
    SDJWTVerifier,
    SDJWTWallet,
    ServerAuthRequiredInterceptor,
)
from a2a_agentic_id.crypto import (
    base64url_encode,
    compute_sha256_base64url,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
    import_private_key_from_jwk,
)
from a2a_agentic_id.interceptor import EXTENSION_URI
from a2a_agentic_id.models import DCQLClaimQuery, DCQLCredentialQuery
from a2a_agentic_id.verifier import CredentialVerificationError

GOOD_VCT = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"
H = {"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"}


def _pem(jwk: Dict[str, Any]) -> bytes:
    return import_private_key_from_jwk(jwk).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class TestPhase6DefectFixes(unittest.TestCase):
    def setUp(self) -> None:
        ip, ipub = generate_ec_p256_keypair()
        hp, hpub = generate_ec_p256_keypair()
        self.iss_priv, self.iss_pub = export_jwk_from_private_key(ip), export_jwk_from_public_key(ipub)
        self.holder_priv, self.holder_pub = export_jwk_from_private_key(hp), export_jwk_from_public_key(hpub)
        self.client_id = "https://verifier.example.com"
        self.verifier = SDJWTVerifier(
            client_id=self.client_id, jwks_resolver=lambda i: self.iss_pub, allow_unverified_status=True
        )

    # ---------- helpers ----------

    def _cred(self, vct: str = GOOD_VCT, id_claim: str = "agent-1", sd: Optional[Dict[str, Any]] = None) -> str:
        return SDJWTWallet.issue_sd_jwt(
            self.iss_priv, "https://issuer.example.com", vct=vct, id_claim=id_claim,
            sd_claims=sd or {"name": "n", "description": "d", "owner": "o"},
            holder_public_key_jwk=self.holder_pub,
        )

    def _wallet(self, sd_jwt: str, wallet_id: str = "agent_identity") -> SDJWTWallet:
        w = SDJWTWallet()
        w.add_credential(CredentialItem(id=wallet_id, sd_jwt_string=sd_jwt, holder_private_key_jwk=self.holder_priv))
        return w

    def _vp(self, sd_jwt: str, nonce: str, wallet_id: str = "agent_identity") -> str:
        w = self._wallet(sd_jwt, wallet_id)
        return w.create_vp_token(
            DCQLQuery.default_agent_identity_query(), nonce=nonce, client_id=self.client_id
        ).vp_token["agent_identity"][0]

    def _msg(self, task: str, vp: Optional[str] = None, ctx: str = "c", text: str = "hi") -> A2ATaskMessage:
        meta = {EXTENSION_URI: {"vp_token": {"agent_identity": [vp]}}} if vp else {}
        return A2ATaskMessage(channel_id="test-channel", id=task, context_id=ctx, headers=H, metadata=meta, parts=[{"text": text}])

    @staticmethod
    def _done(req: A2ATaskMessage, _v: Any) -> A2ATaskStatusResponse:
        return A2ATaskStatusResponse(id=req.id, context_id=req.context_id, state="TASK_STATE_WORKING", message={})

    @staticmethod
    def _err(resp: A2ATaskStatusResponse) -> Optional[str]:
        return resp.message.get("metadata", {}).get(EXTENSION_URI, {}).get("error")

    def _challenge(self, ic: ServerAuthRequiredInterceptor, task: str) -> str:
        r = ic.process_incoming_request(self._msg(task), self._done)
        self.assertEqual(r.state, "TASK_STATE_AUTH_REQUIRED")
        return r.message["metadata"][EXTENSION_URI]["nonce"]

    def _code(self, vp: str, nonce: str = "n") -> ErrorCode:
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp, nonce=nonce)
        return ctx.exception.error_code

    # ---------- K1 ----------

    def test_k1_suffix_and_cross_namespace_types_rejected(self) -> None:
        q = DCQLQuery.default_agent_identity_query().credentials[0]
        q2 = q.model_copy(update={"meta": {"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]}})
        evil = self._cred(vct="https://evil.example.org/AIAgentIdentityCredential")
        w = self._wallet(evil)
        # Disclose every requested claim so the *type* check is the only thing that can fail.
        vp = w.create_presentation(
            w.get_credential("agent_identity"), ["name", "description", "owner"], nonce="n", client_id=self.client_id
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp, nonce="n", single_cred_query=q2)
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)
        self.assertIn("does not satisfy requested vct_values", ctx.exception.message)

    def test_k1_exact_types_still_accepted(self) -> None:
        q = DCQLQuery.default_agent_identity_query().credentials[0]
        for vct in (GOOD_VCT, "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"):  # both are listed in the default query
            vp = self._vp(self._cred(vct=vct), "n")
            self.assertTrue(self.verifier.verify_presentation(vp, nonce="n", single_cred_query=q).is_valid)

    # ---------- K6 ----------

    def test_k6_exact_id_credential_of_wrong_type_is_not_presented(self) -> None:
        w = self._wallet(self._cred(vct="https://other.example/Employee/v1"))
        with self.assertRaises(ValueError):
            w.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="n", client_id=self.client_id)

    def test_k6_exact_id_credential_missing_claims_is_not_presented(self) -> None:
        w = self._wallet(self._cred(sd={"name": "only-name"}))
        with self.assertRaises(ValueError):
            w.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="n", client_id=self.client_id)

    def test_k6_correct_credential_under_a_different_storage_id_is_found(self) -> None:
        w = self._wallet(self._cred(), wallet_id="stored-under-another-name")
        out = w.create_vp_token(DCQLQuery.default_agent_identity_query(), nonce="n", client_id=self.client_id)
        self.assertIn("agent_identity", out.vp_token)

    def test_k6_wallet_does_not_suffix_match_types(self) -> None:
        w = self._wallet(self._cred(vct="https://evil.example.org/AIAgentIdentityCredential"), wallet_id="x")
        q = DCQLCredentialQuery(id="q", format="dc+sd-jwt", meta={"vct_values": ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"]})
        self.assertIsNone(w._find_matching_credential(q))

    def test_k6_exact_id_wins_when_several_candidates_qualify(self) -> None:
        w = SDJWTWallet()
        a, b = self._cred(id_claim="a"), self._cred(id_claim="b")
        w.add_credential(CredentialItem(id="other", sd_jwt_string=a, holder_private_key_jwk=self.holder_priv))
        w.add_credential(CredentialItem(id="agent_identity", sd_jwt_string=b, holder_private_key_jwk=self.holder_priv))
        q = DCQLQuery.default_agent_identity_query().credentials[0]
        self.assertEqual(w._find_matching_credential(q).id, "agent_identity")

    def test_k6_selection_is_by_type_not_query_id(self) -> None:
        # Spec 9.6: candidates are chosen by format and type, NOT by equating the query id with
        # the wallet storage id. Every dc+sd-jwt query now carries vct_values (S29).
        w = self._wallet(self._cred())
        q = DCQLCredentialQuery(id="agent_identity", format="dc+sd-jwt", meta={"vct_values": [GOOD_VCT]})
        self.assertEqual(w._find_matching_credential(q).id, "agent_identity")
        other_id = DCQLCredentialQuery(id="nope", format="dc+sd-jwt", meta={"vct_values": [GOOD_VCT]})
        self.assertEqual(w._find_matching_credential(other_id).id, "agent_identity")
        other_type = DCQLCredentialQuery(id="agent_identity", format="dc+sd-jwt", meta={"vct_values": ["https://example.com/credentials/Other/v1"]})
        self.assertIsNone(w._find_matching_credential(other_type))

    # ---------- K10 / S2 ----------

    def test_s2_unsolicited_vp_token_on_authenticated_task_is_not_dispatched(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        self.assertEqual(ic.process_incoming_request(self._msg("t", self._vp(self._cred(), n)), self._done).state, "TASK_STATE_WORKING")
        seen: List[A2ATaskMessage] = []

        def handler(r: A2ATaskMessage, v: Any) -> A2ATaskStatusResponse:
            seen.append(r)
            return self._done(r, v)

        resp = ic.process_incoming_request(self._msg("t", "garbage~vp"), handler)
        self.assertEqual(resp.state, "TASK_STATE_FAILED")
        self.assertEqual(seen, [], "an unverified vp_token must never reach the business handler")
        self.assertIn("t", ic.authenticated_tasks, "rejecting one message must not close the session")
        # a routine message with no vp_token still passes
        self.assertEqual(ic.process_incoming_request(self._msg("t"), handler).state, "TASK_STATE_WORKING")
        self.assertEqual(len(seen), 1)

    def test_s2_wrong_context_followup_does_not_close_the_session(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        ic.process_incoming_request(self._msg("t", self._vp(self._cred(), n)), self._done)
        resp = ic.process_incoming_request(self._msg("t", ctx="hijacked"), self._done)
        self.assertEqual(self._err(resp), ErrorCode.VP_CONVERSATION_MISMATCH.value)
        self.assertIn("t", ic.authenticated_tasks)
        self.assertEqual(ic.process_incoming_request(self._msg("t"), self._done).state, "TASK_STATE_WORKING")

    def test_s2_server_allocated_task_ids_have_at_least_128_bits(self) -> None:
        import a2a_agentic_id.interceptor as mod

        asked: List[int] = []
        real = mod.secrets.token_hex

        def spy(nbytes: Optional[int] = None) -> str:
            asked.append(nbytes or 0)
            return real(nbytes)

        mod.secrets.token_hex = spy  # type: ignore[assignment]
        try:
            ic = ServerAuthRequiredInterceptor(self.verifier)
            ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", headers=H), self._done)
        finally:
            mod.secrets.token_hex = real  # type: ignore[assignment]
        self.assertTrue(asked and min(asked) >= 16, f"task ids must come from >=16 CSPRNG bytes, got {asked}")

        ic = ServerAuthRequiredInterceptor(self.verifier)
        ids = {ic.process_incoming_request(A2ATaskMessage(channel_id="test-channel", headers=H), self._done).id for _ in range(50)}
        self.assertEqual(len(ids), 50)
        for i in ids:
            self.assertGreaterEqual(len(i), 32)  # 32 hex chars = 128 bits
            int(i, 16)

    # ---------- S18 ----------

    def test_s18_followup_without_vp_token_gets_vp_missing_and_no_second_nonce(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        resp = ic.process_incoming_request(self._msg("t"), self._done)
        self.assertEqual(resp.state, "TASK_STATE_FAILED")
        self.assertEqual(self._err(resp), ErrorCode.VP_MISSING.value)
        self.assertEqual(ic.active_nonces["t"], {n}, "the active challenge must not be replaced")
        self.assertIn("t", ic.buffered_requests, "the retained original must survive a stray follow-up")

    def test_s18_challenge_still_answerable_after_stray_followup(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        ic.process_incoming_request(self._msg("t"), self._done)
        self.assertEqual(ic.process_incoming_request(self._msg("t", self._vp(self._cred(), n)), self._done).state, "TASK_STATE_WORKING")

    def test_s18_empty_kb_jwt_segment_is_key_binding_missing(self) -> None:
        sd = self._cred()  # "<jwt>~<d1>~<d2>~<d3>~" -- no KB-JWT
        self.assertEqual(self._code(sd), ErrorCode.VP_KEY_BINDING_MISSING)

    # ---------- S19 ----------

    def test_s19_unparseable_input_is_malformed_not_unsupported_format(self) -> None:
        self.assertEqual(self._code("no-tildes-at-all"), ErrorCode.VP_MALFORMED)
        self.assertEqual(self._code("not.a.jwt~kb"), ErrorCode.VP_MALFORMED)

    def test_s19_malformed_disclosure_is_malformed(self) -> None:
        sd = self._cred().rsplit("~", 1)[0]  # drop trailing empty KB segment
        bad = sd + "~" + base64url_encode(b"not json") + "~"
        w = self._wallet(self._cred())
        kb = jwt.encode(
            {"nonce": "n", "aud": self.client_id, "iat": int(time.time()), "sd_hash": compute_sha256_base64url(bad)},
            _pem(self.holder_priv), algorithm="ES256", headers={"typ": "kb+jwt"},
        )
        self.assertEqual(self._code(bad + kb), ErrorCode.VP_MALFORMED)

    def test_s19_unsupported_algorithm_is_still_format_unsupported(self) -> None:
        v = SDJWTVerifier(client_id=self.client_id, jwks_resolver=lambda i: self.iss_pub, supported_algorithms=["ES384"])
        with self.assertRaises(CredentialVerificationError) as ctx:
            v.verify_presentation(self._vp(self._cred(), "n"), nonce="n")
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)

    # ---------- S20 ----------

    def test_s20_empty_plaintext_id_rejected(self) -> None:
        w = self._wallet(self._cred(id_claim=""))
        vp = w.create_presentation(w.get_credential("agent_identity"), [], nonce="n", client_id=self.client_id)
        self.assertEqual(self._code(vp), ErrorCode.VP_SIGNATURE_INVALID)

    def test_s20_selectively_disclosed_id_rejected(self) -> None:
        # id carried only as a disclosure (and absent from the plaintext payload)
        disc = base64url_encode(b'["salt","id","agent-1"]')
        now = int(time.time())
        tok = jwt.encode(
            {"iss": "https://issuer.example.com", "iat": now, "exp": now + 3600, "vct": GOOD_VCT,
             "cnf": {"jwk": self.holder_pub}, "_sd_alg": "sha-256", "_sd": [compute_sha256_base64url(disc)]},
            _pem(self.iss_priv), algorithm="ES256", headers={"typ": "dc+sd-jwt"},
        )
        body = tok + "~" + disc + "~"
        kb = jwt.encode(
            {"nonce": "n", "aud": self.client_id, "iat": now, "sd_hash": compute_sha256_base64url(body)},
            _pem(self.holder_priv), algorithm="ES256", headers={"typ": "kb+jwt"},
        )
        self.assertEqual(self._code(body + kb), ErrorCode.VP_SIGNATURE_INVALID)

    def test_s20_selectively_disclosed_vct_rejected(self) -> None:
        disc = base64url_encode(('["salt","vct","%s"]' % GOOD_VCT).encode())
        now = int(time.time())
        tok = jwt.encode(
            {"iss": "https://issuer.example.com", "iat": now, "exp": now + 3600, "id": "a1",
             "cnf": {"jwk": self.holder_pub}, "_sd_alg": "sha-256", "_sd": [compute_sha256_base64url(disc)]},
            _pem(self.iss_priv), algorithm="ES256", headers={"typ": "dc+sd-jwt"},
        )
        body = tok + "~" + disc + "~"
        kb = jwt.encode(
            {"nonce": "n", "aud": self.client_id, "iat": now, "sd_hash": compute_sha256_base64url(body)},
            _pem(self.holder_priv), algorithm="ES256", headers={"typ": "kb+jwt"},
        )
        self.assertEqual(self._code(body + kb), ErrorCode.VP_DCQL_UNSATISFIED)

    # ---------- K14 ----------

    def test_k14_replay_of_consumed_nonce_is_mismatch(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        vp = self._vp(self._cred(), n)
        self.assertEqual(ic.process_incoming_request(self._msg("t", vp), self._done).state, "TASK_STATE_WORKING")
        ic.close_task_session("t")  # task finished; the consumed history is cleared with it
        # a replay on a task that still has a consumed nonce but nothing outstanding
        ic2 = ServerAuthRequiredInterceptor(self.verifier)
        n2 = self._challenge(ic2, "t2")
        wrong = self._wallet(self._cred(vct="https://other.example/X/v1"))
        bad = wrong.create_presentation(  # wallet selection would refuse; the verifier must still reject it
            wrong.get_credential("agent_identity"), [], nonce=n2, client_id=self.client_id
        )  # fails DCQL, consumes n2
        self.assertEqual(self._err(ic2.process_incoming_request(self._msg("t2", bad), self._done)),
                         ErrorCode.VP_DCQL_UNSATISFIED.value)
        replay = ic2.process_incoming_request(self._msg("t2", bad), self._done)
        self.assertEqual(self._err(replay), ErrorCode.VP_NONCE_MISMATCH.value)

    def test_k14_never_issued_nonce_with_nothing_outstanding_is_still_expired(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        resp = ic.process_incoming_request(self._msg("ghost", self._vp(self._cred(), "forged")), self._done)
        self.assertEqual(self._err(resp), ErrorCode.VP_NONCE_EXPIRED.value)

    # ---------- K9 / S3 ----------

    def test_k9_released_request_is_the_original_and_never_merged(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        first = A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=H, metadata={"order": "42"},
                               parts=[{"text": "original"}])
        n = ic.process_incoming_request(first, self._done).message["metadata"][EXTENSION_URI]["nonce"]
        resp = self._msg("t", self._vp(self._cred(), n), text="Identity response.")
        resp.metadata["injected"] = "evil"
        seen: List[A2ATaskMessage] = []
        ic.process_incoming_request(resp, lambda r, v: (seen.append(r), self._done(r, v))[1])
        self.assertEqual(seen[0].metadata, {"order": "42"})
        self.assertEqual(seen[0].parts, [{"text": "original"}])

    def test_k9_mutating_the_callers_object_does_not_change_the_retained_snapshot(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        first = A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=H, metadata={"k": "v"}, parts=[{"text": "orig"}])
        n = ic.process_incoming_request(first, self._done).message["metadata"][EXTENSION_URI]["nonce"]
        first.metadata["k"] = "tampered"
        first.parts[0]["text"] = "tampered"
        seen: List[A2ATaskMessage] = []
        ic.process_incoming_request(self._msg("t", self._vp(self._cred(), n)),
                                    lambda r, v: (seen.append(r), self._done(r, v))[1])
        self.assertEqual(seen[0].metadata, {"k": "v"})
        self.assertEqual(seen[0].parts, [{"text": "orig"}])

    def test_k9_concurrent_responses_release_the_original_exactly_once(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        vp = self._vp(self._cred(), n)
        calls: List[str] = []
        gate = threading.Barrier(8)

        def handler(r: A2ATaskMessage, v: Any) -> A2ATaskStatusResponse:
            calls.append(r.id)
            return self._done(r, v)

        def worker() -> None:
            gate.wait()
            ic.process_incoming_request(self._msg("t", vp), handler)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(len(calls), 1, "the retained original must be dispatched at most once")

    def test_k9_unknown_nonce_does_not_delete_the_pending_original(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        bad = ic.process_incoming_request(self._msg("t", self._vp(self._cred(), "wrong-nonce")), self._done)
        self.assertEqual(self._err(bad), ErrorCode.VP_NONCE_MISMATCH.value)
        self.assertIn("t", ic.buffered_requests, "a mismatched nonce must not delete the retained original")
        seen: List[A2ATaskMessage] = []
        ok = ic.process_incoming_request(
            self._msg("t", self._vp(self._cred(), n)), lambda r, v: (seen.append(r), self._done(r, v))[1]
        )
        self.assertEqual(ok.state, "TASK_STATE_WORKING")
        self.assertEqual(len(seen), 1)

    def test_k9_wrong_context_does_not_delete_the_pending_original(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        bad = ic.process_incoming_request(self._msg("t", self._vp(self._cred(), n), ctx="other"), self._done)
        self.assertEqual(self._err(bad), ErrorCode.VP_CONVERSATION_MISMATCH.value)
        self.assertIn("t", ic.buffered_requests)
        self.assertIn(n, ic.active_nonces["t"])

    def test_k9_oversized_initial_request_is_refused_and_not_buffered(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier, max_buffered_bytes=200)
        big = A2ATaskMessage(channel_id="test-channel", id="t", context_id="c", headers=H, parts=[{"text": "x" * 1000}])
        resp = ic.process_incoming_request(big, self._done)
        self.assertEqual(resp.state, "TASK_STATE_FAILED")
        self.assertEqual(self._err(resp), ErrorCode.VP_MALFORMED.value)
        self.assertNotIn("t", ic.buffered_requests)
        self.assertNotIn("t", ic.active_nonces, "no challenge may be issued for a refused request")

    def test_k9_pending_request_limit_enforced(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier, max_buffered_requests=2)
        self.assertEqual(ic.process_incoming_request(self._msg("a"), self._done).state, "TASK_STATE_AUTH_REQUIRED")
        self.assertEqual(ic.process_incoming_request(self._msg("b"), self._done).state, "TASK_STATE_AUTH_REQUIRED")
        self.assertEqual(ic.process_incoming_request(self._msg("c"), self._done).state, "TASK_STATE_FAILED")
        self.assertEqual(len(ic.buffered_requests), 2)

    def test_k9_abandoned_buffer_expires(self) -> None:
        clock = _Clock()
        ic = ServerAuthRequiredInterceptor(self.verifier, challenge_ttl=60, time_fn=clock)
        ic.process_incoming_request(self._msg("a"), self._done)
        clock.now += 61
        ic.process_incoming_request(self._msg("b"), self._done)  # admission purges expired entries
        self.assertNotIn("a", ic.buffered_requests)
        self.assertIn("b", ic.buffered_requests)

    def test_k9_close_task_session_clears_all_per_task_state(self) -> None:
        ic = ServerAuthRequiredInterceptor(self.verifier)
        n = self._challenge(ic, "t")
        ic.process_incoming_request(self._msg("t", self._vp(self._cred(), n)), self._done)
        ic.close_task_session("t")
        for store in (ic.buffered_requests, ic.buffered_at, ic.consumed_nonces, ic.active_nonces,
                      ic.nonce_issued_at, ic.task_contexts):
            self.assertNotIn("t", store)
        self.assertNotIn("t", ic.released_tasks)


if __name__ == "__main__":
    unittest.main()
