# SPDX-License-Identifier: Apache-2.0
"""
S29: DCQL conformance (spec 9.6, OID4VP 1.0 Appendix B.3.5).
- every dc+sd-jwt Credential Query carries a non-empty meta.vct_values
- claim paths are object-key paths resolved in full, not just their first segment
- unsupported path forms are rejected, not silently ignored
"""

import json
import time
import unittest
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from a2a_agentic_id import (
    CredentialItem,
    DCQLClaimQuery,
    DCQLCredentialQuery,
    DCQLQuery,
    ErrorCode,
    SDJWTVerifier,
    SDJWTWallet,
)
from a2a_agentic_id.crypto import (
    base64url_encode,
    compute_sha256_base64url,
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
    generate_salt,
)
from a2a_agentic_id.verifier import CredentialVerificationError

VCT = "https://example.com/credentials/Nested/v1"
CLIENT = "https://verifier.example.com"


class TestVctValuesRequired(unittest.TestCase):
    def test_dc_sd_jwt_query_without_meta_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            DCQLCredentialQuery(id="q", format="dc+sd-jwt")

    def test_empty_or_malformed_vct_values_rejected(self) -> None:
        for meta in ({}, {"vct_values": []}, {"vct_values": [""]}, {"vct_values": [1]}, {"vct_values": "T"}, {"other": 1}):
            with self.assertRaises(ValidationError, msg=str(meta)):
                DCQLCredentialQuery(id="q", format="dc+sd-jwt", meta=meta)

    def test_valid_vct_values_accepted(self) -> None:
        q = DCQLCredentialQuery(id="q", format="dc+sd-jwt", meta={"vct_values": ["https://example.com/credentials/A/v1", "urn:example:b"]})
        self.assertEqual(q.meta["vct_values"], ["https://example.com/credentials/A/v1", "urn:example:b"])

    def test_default_agent_identity_query_still_valid(self) -> None:
        self.assertTrue(DCQLQuery.default_agent_identity_query().credentials[0].meta["vct_values"])

    def test_query_without_vct_values_rejected_when_parsed_from_wire(self) -> None:
        wire = {"credentials": [{"id": "q", "format": "dc+sd-jwt", "claims": [{"path": ["name"]}]}]}
        with self.assertRaises(ValidationError):
            DCQLQuery.model_validate(wire)

    def test_other_formats_not_forced_to_carry_vct_values(self) -> None:
        # vct_values is the dc+sd-jwt rule; the wallet simply finds no such credential.
        self.assertEqual(DCQLCredentialQuery(id="q", format="jwt_vc_json").format, "jwt_vc_json")


class TestClaimPathForms(unittest.TestCase):
    def test_empty_path_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            DCQLClaimQuery(path=[])

    def test_array_selection_segments_rejected(self) -> None:
        for path in (["owner", None], ["owner", 0], ["a", ""]):
            with self.assertRaises(ValidationError, msg=str(path)):
                DCQLClaimQuery(path=path)  # type: ignore[arg-type]

    def test_multi_segment_key_path_accepted(self) -> None:
        self.assertEqual(DCQLClaimQuery(path=["owner", "id"]).path, ["owner", "id"])


class TestNestedClaimPaths(unittest.TestCase):
    def setUp(self) -> None:
        iss_priv, iss_pub = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        self.holder_priv = export_jwk_from_private_key(holder_priv)
        holder_pub_jwk = export_jwk_from_public_key(holder_pub)
        self.verifier = SDJWTVerifier(
            client_id=CLIENT,
            jwks_resolver=lambda iss: export_jwk_from_public_key(iss_pub),
            allow_unverified_status=True,
        )

        def disc(name: str, value: Any) -> str:
            return base64url_encode(json.dumps([generate_salt(), name, value]).encode())

        # owner = { id: <selectively disclosed>, name: "Acme" (plaintext) }, itself disclosed.
        d_id = disc("id", "org:acme")
        d_owner = disc("owner", {"_sd": [compute_sha256_base64url(d_id)], "name": "Acme"})
        now = int(time.time())
        pem = iss_priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        tok = jwt.encode(
            {"iss": "https://issuer.example.com", "iat": now, "exp": now + 3600, "vct": VCT, "id": "agent-1",
             "cnf": {"jwk": holder_pub_jwk}, "_sd": [compute_sha256_base64url(d_owner)], "_sd_alg": "sha-256"},
            pem, algorithm="ES256", headers={"typ": "dc+sd-jwt"},
        )
        self.wallet = SDJWTWallet()
        self.wallet.add_credential(CredentialItem(
            id="stored", sd_jwt_string=tok + "~" + d_owner + "~" + d_id + "~",
            holder_private_key_jwk=self.holder_priv,
        ))

    @staticmethod
    def _query(path: List[str], values: Optional[List[str]] = None) -> DCQLQuery:
        return DCQLQuery(credentials=[DCQLCredentialQuery(
            id="q", meta={"vct_values": [VCT]}, claims=[DCQLClaimQuery(path=path, values=values)]
        )])

    def _present_and_verify(self, query: DCQLQuery) -> str:
        vp = self.wallet.create_vp_token(query, nonce="n", client_id=CLIENT).vp_token["q"][0]
        self.verifier.verify_presentation(vp, nonce="n", dcql_query=query)
        return vp

    def test_nested_disclosed_path_resolves(self) -> None:
        vp = self._present_and_verify(self._query(["owner", "id"]))
        self.assertEqual(len(vp.split("~")) - 2, 2)  # owner and owner.id are both revealed

    def test_plaintext_leaf_under_disclosed_parent_resolves(self) -> None:
        vp = self._present_and_verify(self._query(["owner", "name"]))
        self.assertEqual(len(vp.split("~")) - 2, 1)  # only the parent is revealed

    def test_value_constraint_applies_to_the_leaf(self) -> None:
        self._present_and_verify(self._query(["owner", "id"], ["org:acme"]))

    def test_wallet_refuses_when_leaf_value_not_allowed(self) -> None:
        with self.assertRaises(ValueError):
            self.wallet.create_vp_token(self._query(["owner", "id"], ["org:other"]), nonce="n", client_id=CLIENT)

    def test_wallet_refuses_when_path_does_not_exist(self) -> None:
        with self.assertRaises(ValueError):
            self.wallet.create_vp_token(self._query(["owner", "nope"]), nonce="n", client_id=CLIENT)

    def test_verifier_does_not_match_only_the_first_segment(self) -> None:
        # Present only `owner.name`, then ask the verifier for `owner.id`: it must NOT be
        # satisfied just because the first segment `owner` was disclosed.
        vp = self.wallet.create_vp_token(self._query(["owner", "name"]), nonce="n", client_id=CLIENT).vp_token["q"][0]
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp, nonce="n", dcql_query=self._query(["owner", "id"]))
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)

    def test_verifier_value_constraint_on_nested_leaf(self) -> None:
        vp = self.wallet.create_vp_token(self._query(["owner", "id"]), nonce="n", client_id=CLIENT).vp_token["q"][0]
        with self.assertRaises(CredentialVerificationError) as ctx:
            self.verifier.verify_presentation(vp, nonce="n", dcql_query=self._query(["owner", "id"], ["org:other"]))
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_DCQL_UNSATISFIED)


if __name__ == "__main__":
    unittest.main()
