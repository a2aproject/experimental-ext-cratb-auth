# SPDX-License-Identifier: Apache-2.0
"""
S28: the credential type is the plaintext `vct` claim (spec 7.3.4 step 5, 9.2).
The legacy `dct` claim is not part of the profile: it is never read, never written, and a
credential that carries only `dct` is not an acceptable credential.
"""

import time
import unittest
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from a2a_agentic_id import (
    AIAgentIdentityCredential,
    CredentialItem,
    DCQLCredentialQuery,
    DCQLQuery,
    ErrorCode,
    SDJWTVerifier,
    SDJWTWallet,
)
from a2a_agentic_id.crypto import (
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
)
from a2a_agentic_id.verifier import CredentialVerificationError

VCT = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"
CLIENT = "https://verifier.example.com"


class _VctFixtures(unittest.TestCase):
    """Shared issuer/holder keys and token helpers. Defines no tests, so subclasses do not repeat each other."""

    def setUp(self) -> None:
        self.iss_priv_key, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.iss_priv = export_jwk_from_private_key(self.iss_priv_key)
        self.iss_pub = export_jwk_from_public_key(iss_pub)
        self.holder_priv = export_jwk_from_private_key(holder_priv)
        self.holder_pub = export_jwk_from_public_key(holder_pub)
        self.verifier = SDJWTVerifier(
            client_id=CLIENT, jwks_resolver=lambda iss: self.iss_pub, allow_unverified_status=True
        )
        self.query = DCQLQuery(credentials=[DCQLCredentialQuery(id="q", meta={"vct_values": [VCT]})])

    def _token(self, **claims: Any) -> str:
        """Hand-built issuer JWT so the type claims can be controlled exactly."""
        now = int(time.time())
        pem = self.iss_priv_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        payload: Dict[str, Any] = {
            "iss": "https://issuer.example.com", "iat": now, "exp": now + 3600, "id": "agent-1",
            "cnf": {"jwk": self.holder_pub}, "_sd": [], "_sd_alg": "sha-256",
        }
        payload.update({k: v for k, v in claims.items() if v is not None})
        return jwt.encode(payload, pem, algorithm="ES256", headers={"typ": "dc+sd-jwt"}) + "~"

    def _verify(self, token: str):
        w = SDJWTWallet()
        item = CredentialItem(id="q", sd_jwt_string=token, holder_private_key_jwk=self.holder_priv)
        w.add_credential(item)
        vp = w.create_presentation(item, [], nonce="n", client_id=CLIENT)
        return self.verifier.verify_presentation(vp, nonce="n", dcql_query=self.query)

    def _rejected(self, token: str) -> CredentialVerificationError:
        with self.assertRaises(CredentialVerificationError) as ctx:
            self._verify(token)
        return ctx.exception

    def _issue(self, **kw: Any) -> Dict[str, Any]:
        tok = SDJWTWallet.issue_sd_jwt(
            issuer_private_key_jwk=self.iss_priv, iss="https://issuer.example.com", id_claim="a",
            holder_public_key_jwk=self.holder_pub, **kw,
        )
        return jwt.decode(tok.split("~")[0], options={"verify_signature": False})


class TestStrictVct(_VctFixtures):
    # ---- verifier

    def test_vct_credential_accepted(self) -> None:
        res = self._verify(self._token(vct=VCT))
        self.assertEqual(res.credential_type, VCT)

    def test_dct_only_credential_rejected(self) -> None:
        err = self._rejected(self._token(dct=VCT))
        self.assertEqual(err.error_code, ErrorCode.VP_DCQL_UNSATISFIED)
        self.assertIn("vct", err.message)

    def test_missing_vct_rejected_even_without_a_vct_values_constraint(self) -> None:
        # Spec step 5 requires `vct` regardless of what the query asks for.
        unconstrained = DCQLQuery(credentials=[DCQLCredentialQuery(id="q", format="jwt_vc_json")])
        w = SDJWTWallet()
        item = CredentialItem(id="q", sd_jwt_string=self._token(dct=VCT), holder_private_key_jwk=self.holder_priv)
        vp = w.create_presentation(item, [], nonce="n", client_id=CLIENT)
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp, nonce="n", dcql_query=unconstrained)
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)

    def test_dct_is_ignored_when_vct_present(self) -> None:
        # A stray/conflicting `dct` neither helps nor hurts: only `vct` is consulted.
        res = self._verify(self._token(vct=VCT, dct="https://example.com/credentials/Other/v1"))
        self.assertEqual(res.credential_type, VCT)

    def test_dct_cannot_satisfy_vct_values_when_vct_is_wrong(self) -> None:
        err = self._rejected(self._token(vct="https://example.com/credentials/Other/v1", dct=VCT))
        self.assertEqual(err.error_code, ErrorCode.VP_DCQL_UNSATISFIED)

    def test_non_string_or_empty_vct_rejected(self) -> None:
        for bad in ("", 7, ["x"], {"a": 1}):
            self.assertEqual(self._rejected(self._token(vct=bad)).error_code, ErrorCode.VP_DCQL_UNSATISFIED, repr(bad))

    # ---- wallet

    def test_wallet_does_not_select_a_dct_only_credential(self) -> None:
        w = SDJWTWallet()
        w.add_credential(CredentialItem(id="q", sd_jwt_string=self._token(dct=VCT), holder_private_key_jwk=self.holder_priv))
        self.assertIsNone(w._find_matching_credential(self.query.credentials[0]))

    def test_wallet_selects_a_vct_credential(self) -> None:
        w = SDJWTWallet()
        w.add_credential(CredentialItem(id="q", sd_jwt_string=self._token(vct=VCT), holder_private_key_jwk=self.holder_priv))
        self.assertEqual(w._find_matching_credential(self.query.credentials[0]).id, "q")

    # ---- issuer helper

    def test_issuer_writes_vct_and_never_dct(self) -> None:
        payload = self._issue(vct=VCT)
        self.assertEqual(payload["vct"], VCT)
        self.assertNotIn("dct", payload)

    def test_issuer_dct_argument_is_an_alias_for_vct(self) -> None:
        payload = self._issue(dct="https://example.com/credentials/Legacy/v1")
        self.assertEqual(payload["vct"], "https://example.com/credentials/Legacy/v1")
        self.assertNotIn("dct", payload)

    def test_issuer_conflicting_vct_and_dct_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._issue(vct=VCT, dct="https://example.com/credentials/Other/v1")

    def test_issuer_cannot_override_vct_via_claims(self) -> None:
        with self.assertRaises(ValueError):
            self._issue(vct=VCT, plaintext_claims={"dct": "x"})

    # ---- credential model

    def test_identity_credential_model_requires_vct_and_has_no_dct(self) -> None:
        base = {"iss": "https://issuer.example.com", "iat": 0, "exp": 1, "id": "a"}
        with self.assertRaises(Exception):
            AIAgentIdentityCredential(**base)
        cred = AIAgentIdentityCredential(**base, vct=VCT)
        self.assertEqual(cred.vct, VCT)
        self.assertFalse(hasattr(cred, "dct"))


class TestSubEqualsId(_VctFixtures):
    """Spec 7.3.4 step 5 and 9.2: if `sub` is present it MUST equal `id`; a mismatch is rejected."""

    def test_sub_equal_to_id_accepted(self) -> None:
        self.assertEqual(self._verify(self._token(vct=VCT, sub="agent-1")).credential_type, VCT)

    def test_sub_absent_accepted(self) -> None:
        self.assertTrue(self._verify(self._token(vct=VCT)).is_valid)

    def test_sub_different_from_id_rejected(self) -> None:
        err = self._rejected(self._token(vct=VCT, sub="someone-else"))
        self.assertEqual(err.error_code, ErrorCode.VP_SIGNATURE_INVALID)
        self.assertIn("sub", err.message)

    def test_sub_that_is_not_a_string_rejected(self) -> None:
        for bad in (7, ["agent-1"], {"a": 1}, "", None):
            token = self._token(vct=VCT, sub=bad) if bad is not None else self._token_with_null_sub()
            self.assertEqual(self._rejected(token).error_code, ErrorCode.VP_SIGNATURE_INVALID, repr(bad))

    def test_sub_differing_only_in_case_or_whitespace_rejected(self) -> None:
        for bad in ("AGENT-1", "agent-1 ", " agent-1"):
            self.assertEqual(self._rejected(self._token(vct=VCT, sub=bad)).error_code, ErrorCode.VP_SIGNATURE_INVALID, repr(bad))

    def test_selectively_disclosed_sub_is_checked_too(self) -> None:
        import json
        from a2a_agentic_id.crypto import base64url_encode, compute_sha256_base64url, generate_salt

        disclosure = base64url_encode(json.dumps([generate_salt(), "sub", "someone-else"]).encode())
        now = int(time.time())
        pem = self.iss_priv_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        issuer_jwt = jwt.encode(
            {"iss": "https://issuer.example.com", "iat": now, "exp": now + 3600, "vct": VCT, "id": "agent-1",
             "cnf": {"jwk": self.holder_pub}, "_sd": [compute_sha256_base64url(disclosure)], "_sd_alg": "sha-256"},
            pem, algorithm="ES256", headers={"typ": "dc+sd-jwt"},
        )
        w = SDJWTWallet()
        item = CredentialItem(
            id="q", sd_jwt_string=issuer_jwt + "~" + disclosure + "~", holder_private_key_jwk=self.holder_priv
        )
        vp = w.create_presentation(item, ["sub"], nonce="n", client_id=CLIENT)
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp, nonce="n", dcql_query=self.query)
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID)

    def test_issuer_helper_still_refuses_to_set_sub(self) -> None:
        with self.assertRaises(ValueError):
            self._issue(vct=VCT, plaintext_claims={"sub": "agent-1"})

    def _token_with_null_sub(self) -> str:
        now = int(time.time())
        pem = self.iss_priv_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return jwt.encode(
            {"iss": "https://issuer.example.com", "iat": now, "exp": now + 3600, "vct": VCT, "id": "agent-1",
             "sub": None, "cnf": {"jwk": self.holder_pub}, "_sd": [], "_sd_alg": "sha-256"},
            pem, algorithm="ES256", headers={"typ": "dc+sd-jwt"},
        ) + "~"


if __name__ == "__main__":
    unittest.main()
