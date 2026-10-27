# SPDX-License-Identifier: Apache-2.0
import json
import time
import unittest
import zlib
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from a2a_agentic_id import (
    ErrorCode,
    SDJWTVerifier,
    SDJWTWallet,
    TokenStatusListClient,
)
from a2a_agentic_id.crypto import (
    base64url_encode,
    compute_sha256_base64url,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
    import_private_key_from_jwk,
)
from a2a_agentic_id.verifier import CredentialVerificationError


def _pem(jwk: Dict[str, Any]) -> bytes:
    return import_private_key_from_jwk(jwk).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _disc(*items: Any) -> str:
    return base64url_encode(json.dumps(list(items), separators=(",", ":")).encode("utf-8"))


class TestPhase3Remediation(unittest.TestCase):
    """Phase 3: TSL (K5), recursive disclosures (K13), domains/conversation (K17), issuance (K18)."""

    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.iss_priv = export_jwk_from_private_key(iss_priv)
        self.iss_pub = export_jwk_from_public_key(iss_pub)
        self.holder_priv = export_jwk_from_private_key(holder_priv)
        self.holder_pub = export_jwk_from_public_key(holder_pub)
        self.client_id = "https://verifier.example.com"
        self.verifier = SDJWTVerifier(
            client_id=self.client_id, jwks_resolver=lambda i: self.iss_pub
        )

    # ---------- helpers ----------

    def _issue_raw(self, payload_extra: Dict[str, Any], disclosures: List[str]) -> str:
        now = int(time.time())
        payload = {
            "iss": "https://issuer.example.com",
            "iat": now,
            "exp": now + 3600,
            "vct": "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
            "id": "agent-1",
            "cnf": {"jwk": self.holder_pub},
            "_sd_alg": "sha-256",
        }
        payload.update(payload_extra)
        tok = jwt.encode(payload, _pem(self.iss_priv), algorithm="ES256", headers={"typ": "dc+sd-jwt"})
        return tok + "~" + "".join(d + "~" for d in disclosures)

    def _present(
        self,
        sd_jwt: str,
        nonce: str = "n1",
        extra_kb: Optional[Dict[str, Any]] = None,
    ) -> str:
        kb = {
            "nonce": nonce,
            "aud": self.client_id,
            "iat": int(time.time()),
            "sd_hash": compute_sha256_base64url(sd_jwt),
        }
        kb.update(extra_kb or {})
        return sd_jwt + jwt.encode(kb, _pem(self.holder_priv), algorithm="ES256", headers={"typ": "kb+jwt"})

    def _verify(self, pres: str, **kw: Any):
        return self.verifier.verify_presentation(pres, nonce="n1", **kw)

    def _code(self, pres: str, **kw: Any) -> ErrorCode:
        with self.assertRaises(CredentialVerificationError) as ctx:
            self._verify(pres, **kw)
        return ctx.exception.error_code

    # ---------- K13 ----------

    def test_k13_array_element_disclosure_accepted(self) -> None:
        d = _disc("salt1", "hello")
        sd = self._issue_raw({"tags": [{"...": compute_sha256_base64url(d)}]}, [d])
        res = self._verify(self._present(sd))
        self.assertTrue(res.is_valid)

    def test_k13_nested_object_disclosure_accepted(self) -> None:
        inner = _disc("s2", "city", "Paris")
        outer = _disc("s1", "address", {"_sd": [compute_sha256_base64url(inner)]})
        sd = self._issue_raw({"_sd": [compute_sha256_base64url(outer)]}, [outer, inner])
        res = self._verify(self._present(sd))
        self.assertEqual(res.disclosed_claims["address"], {"city": "Paris"})

    def test_k13_duplicate_disclosure_rejected(self) -> None:
        d = _disc("s", "name", "Bob")
        sd = self._issue_raw({"_sd": [compute_sha256_base64url(d)]}, [d, d])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_SIGNATURE_INVALID)

    def test_k13_duplicate_digest_reference_rejected(self) -> None:
        d = _disc("s", "name", "Bob")
        h = compute_sha256_base64url(d)
        sd = self._issue_raw({"_sd": [h, h]}, [d])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_SIGNATURE_INVALID)

    def test_k13_plaintext_collision_rejected(self) -> None:
        d = _disc("s", "role", "admin")
        sd = self._issue_raw({"role": "guest", "_sd": [compute_sha256_base64url(d)]}, [d])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_SIGNATURE_INVALID)

    def test_k13_orphan_disclosure_rejected(self) -> None:
        d = _disc("s", "name", "Bob")
        sd = self._issue_raw({"_sd": []}, [d])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_SIGNATURE_INVALID)

    def test_k13_non_sha256_alg_rejected(self) -> None:
        sd = self._issue_raw({"_sd_alg": "sha-512"}, [])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_SIGNATURE_INVALID)

    def test_k13_reserved_sd_alg_claim_name_in_disclosure_rejected(self) -> None:
        d = _disc("s", "_sd_alg", "sha-256")
        sd = self._issue_raw({"_sd": [compute_sha256_base64url(d)]}, [d])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_MALFORMED)

    # ---------- Spec 7.3.4 step ordering ----------

    def test_order_tsl_not_consulted_when_nonce_is_wrong(self) -> None:
        # Step 9 (status list) runs after step 8 (nonce): a bad nonce must not trigger a lookup.
        calls: List[Any] = []

        class _Tsl:
            def is_revoked(self, ref: Any) -> bool:
                calls.append(ref)
                return True

        self.verifier.tsl_client = _Tsl()
        sd = self._issue_raw({"status": {"status_list": {"idx": 1, "uri": "https://s.example/1"}}}, [])
        self.assertEqual(self._code(self._present(sd, nonce="wrong")), ErrorCode.VP_NONCE_MISMATCH)
        self.assertEqual(calls, [])

    def test_order_tsl_consulted_after_kb_checks_pass(self) -> None:
        class _Tsl:
            def is_revoked(self, ref: Any) -> bool:
                return True

        self.verifier.tsl_client = _Tsl()
        sd = self._issue_raw({"status": {"status_list": {"idx": 1, "uri": "https://s.example/1"}}}, [])
        self.assertEqual(self._code(self._present(sd)), ErrorCode.VP_CREDENTIAL_REVOKED)

    def test_order_kb_header_checked_before_issuer_key_resolution(self) -> None:
        # Step 2 inspects the KB-JWT header before any key is resolved.
        resolved: List[str] = []
        self.verifier.jwks_resolver = lambda i: resolved.append(i) or self.iss_pub
        sd = self._issue_raw({}, [])
        kb = jwt.encode({"nonce": "n1"}, _pem(self.holder_priv), algorithm="ES256", headers={"typ": "JWT"})
        self.assertEqual(self._code(sd + kb), ErrorCode.VP_FORMAT_UNSUPPORTED)
        self.assertEqual(resolved, [])

    # ---------- K17 ----------

    def test_k17_domains_exact_match_passes(self) -> None:
        sd = self._issue_raw({}, [])
        res = self._verify(self._present(sd, extra_kb={"domains": [self.client_id]}))
        self.assertTrue(res.is_valid)

    def test_k17_domains_string_substring_rejected(self) -> None:
        sd = self._issue_raw({}, [])
        pres = self._present(sd, extra_kb={"domains": self.client_id + "/extra"})
        self.assertEqual(self._code(pres), ErrorCode.VP_DOMAIN_NOT_ALLOWED)

    def test_k17_empty_domains_rejected(self) -> None:
        sd = self._issue_raw({}, [])
        self.assertEqual(
            self._code(self._present(sd, extra_kb={"domains": []})),
            ErrorCode.VP_DOMAIN_NOT_ALLOWED,
        )

    def test_k17_mixed_domains_rejected(self) -> None:
        sd = self._issue_raw({}, [])
        pres = self._present(sd, extra_kb={"domains": [self.client_id, 5]})
        self.assertEqual(self._code(pres), ErrorCode.VP_DOMAIN_NOT_ALLOWED)

    def test_k17_conversation_id_without_expected_context_rejected(self) -> None:
        sd = self._issue_raw({}, [])
        pres = self._present(sd, extra_kb={"conversation_id": "ctx-1"})
        self.assertEqual(self._code(pres), ErrorCode.VP_CONVERSATION_MISMATCH)

    def test_k17_conversation_id_mismatch_and_match(self) -> None:
        sd = self._issue_raw({}, [])
        pres = self._present(sd, extra_kb={"conversation_id": "ctx-1"})
        self.assertEqual(self._code(pres, expected_context_id="ctx-2"), ErrorCode.VP_CONVERSATION_MISMATCH)
        self.assertTrue(self._verify(pres, expected_context_id="ctx-1").is_valid)

    # ---------- K18 ----------

    def _issue(self, **kw: Any) -> str:
        return SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.iss_priv,
            iss="https://issuer.example.com",
            id_claim="agent-1",
            holder_public_key_jwk=self.holder_pub,
            **kw,
        )

    def test_k18_header_typ_is_dc_sd_jwt(self) -> None:
        tok = self._issue(sd_claims={"name": "A"})
        self.assertEqual(jwt.get_unverified_header(tok.split("~")[0])["typ"], "dc+sd-jwt")

    def test_k18_reserved_claims_rejected(self) -> None:
        for name in ("iss", "cnf", "_sd", "_sd_alg", "vct", "id"):
            with self.assertRaises(ValueError, msg=name):
                self._issue(plaintext_claims={name: "x"})
        with self.assertRaises(ValueError):
            self._issue(sd_claims={"cnf": {}})

    def test_k18_plaintext_sd_collision_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._issue(plaintext_claims={"name": "a"}, sd_claims={"name": "b"})

    def test_k18_status_list_ref_preserved(self) -> None:
        tok = self._issue(status_list_ref={"idx": 3, "uri": "https://issuer.example.com/s"})
        payload = jwt.decode(tok.split("~")[0], options={"verify_signature": False})
        self.assertEqual(payload["status"]["status_list"]["idx"], 3)
        with self.assertRaises(ValueError):
            self._issue(status_list_ref={"idx": -1, "uri": "u"})

    # ---------- K5 ----------

    def test_k5_unsigned_tsl_rejected(self) -> None:
        now = int(time.time())
        unsigned = jwt.encode(
            {
                "iss": "https://issuer.example.com",
                "sub": "https://issuer.example.com/s",
                "iat": now,
                "status_list": {"bits": 1, "lst": base64url_encode(zlib.compress(b"\x00"))},
            },
            key=None,
            algorithm="none",
        )
        with self.assertRaises(ValueError):
            TokenStatusListClient().register_status_list_jwt(
                "https://issuer.example.com/s", unsigned, issuer_public_key_jwk=self.iss_pub
            )

    def test_k5_wrong_typ_rejected_when_verifying(self) -> None:
        now = int(time.time())
        tok = jwt.encode(
            {
                "iss": "https://issuer.example.com",
                "sub": "https://issuer.example.com/s",
                "iat": now,
                "status_list": {"bits": 1, "lst": base64url_encode(zlib.compress(b"\x00"))},
            },
            _pem(self.iss_priv),
            algorithm="ES256",
        )
        with self.assertRaises(ValueError):
            TokenStatusListClient().register_status_list_jwt(
                "https://issuer.example.com/s", tok, issuer_public_key_jwk=self.iss_pub
            )

    def test_k5_sub_mismatch_rejected(self) -> None:
        tok = TokenStatusListClient.create_status_list_jwt(
            self.iss_priv, "https://issuer.example.com", [1], sub="https://evil.example.org/x"
        )
        with self.assertRaises(ValueError):
            TokenStatusListClient().register_status_list_jwt(
                "https://issuer.example.com/s", tok, issuer_public_key_jwk=self.iss_pub
            )

    def test_k5_decompression_bomb_and_raw_fallback_rejected(self) -> None:
        now = int(time.time())

        def mk(lst: bytes) -> str:
            return jwt.encode(
                {
                    "iss": "https://issuer.example.com",
                    "sub": "https://issuer.example.com/s",
                    "iat": now,
                    "status_list": {"bits": 1, "lst": base64url_encode(lst)},
                },
                _pem(self.iss_priv),
                algorithm="ES256",
                headers={"typ": "statuslist+jwt"},
            )

        client = TokenStatusListClient()
        with self.assertRaises(ValueError):
            client.register_status_list_jwt(
                "https://issuer.example.com/s",
                mk(zlib.compress(b"\x00" * (5 * 1024 * 1024))),
                issuer_public_key_jwk=self.iss_pub,
            )
        with self.assertRaises(ValueError):
            client.register_status_list_jwt(
                "https://issuer.example.com/s", mk(b"\x00\x01\x02raw"), issuer_public_key_jwk=self.iss_pub
            )


    def test_k5_signed_tsl_without_key_rejected_by_default(self) -> None:
        uri = "https://issuer.example.com/s"
        tok = TokenStatusListClient.create_status_list_jwt(
            self.iss_priv, "https://issuer.example.com", [1], sub=uri
        )
        with self.assertRaises(ValueError) as ctx:
            TokenStatusListClient().register_status_list_jwt(uri, tok)
        self.assertIn("Signature verification required", str(ctx.exception))
        # per-call require_signature=False must NOT bypass the default
        with self.assertRaises(ValueError):
            TokenStatusListClient().register_status_list_jwt(uri, tok, require_signature=False)
        # explicit unsafe opt-in works
        c = TokenStatusListClient(allow_unverified_for_testing=True)
        c.register_status_list_jwt(uri, tok)

    def test_k5_sub_must_equal_uri_exactly(self) -> None:
        tok = TokenStatusListClient.create_status_list_jwt(
            self.iss_priv, "https://issuer.example.com", [1], sub="https://issuer.example.com/other"
        )
        with self.assertRaises(ValueError) as ctx:
            TokenStatusListClient().register_status_list_jwt(
                "https://issuer.example.com/s", tok, issuer_public_key_jwk=self.iss_pub
            )
        self.assertIn("does not match registered URI", str(ctx.exception))

    def test_k5_stale_cache_evicted_and_fails_closed(self) -> None:
        from a2a_agentic_id.models import StatusListReference

        uri = "https://issuer.example.com/s"
        tok = TokenStatusListClient.create_status_list_jwt(
            self.iss_priv, "https://issuer.example.com", [1], sub=uri
        )
        client = TokenStatusListClient(max_tsl_age=60)
        client.register_status_list_jwt(uri, tok, issuer_public_key_jwk=self.iss_pub)
        self.assertTrue(client.is_revoked(StatusListReference(idx=1, uri=uri)))

        client.cache_timestamps[uri] -= 3600  # cached an hour ago
        with self.assertRaises(KeyError):
            client.is_revoked(StatusListReference(idx=1, uri=uri))
        self.assertNotIn(uri, client.cached_status_lists)

    def test_k5_expired_list_exp_evicted(self) -> None:
        from a2a_agentic_id.models import StatusListReference

        uri = "https://issuer.example.com/s"
        tok = TokenStatusListClient.create_status_list_jwt(
            self.iss_priv, "https://issuer.example.com", [1], sub=uri
        )
        client = TokenStatusListClient()
        client.register_status_list_jwt(uri, tok, issuer_public_key_jwk=self.iss_pub)
        client.cached_metadata[uri]["exp"] = int(time.time()) - 3600
        with self.assertRaises(KeyError):
            client.is_revoked(StatusListReference(idx=1, uri=uri))


if __name__ == "__main__":
    unittest.main()
