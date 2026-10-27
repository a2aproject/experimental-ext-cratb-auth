# SPDX-License-Identifier: Apache-2.0
"""
S28: `vct` and `meta.vct_values` are collision-resistant type identifiers (spec 9.2 table, 9.6).

A bare label such as "AIAgentIdentityCredential" is not namespaced, so it is not collision
resistant. This profile accepts an absolute http(s) URI with a host, or a URN.
"""

import unittest
from typing import Any

from pydantic import ValidationError

from a2a_agentic_id import (
    AI_AGENT_IDENTITY_VCT,
    AIAgentIdentityCredential,
    DCQLCredentialQuery,
    DCQLQuery,
    SDJWTWallet,
    is_collision_resistant_type,
)
from a2a_agentic_id.crypto import (
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
)

GOOD = [
    "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1",
    "https://example.com/t",
    "http://types.example.org/agent",
    "urn:example:agent:v1",
    "URN:Example:agent",
]
BAD = [
    "AIAgentIdentityCredential", "EmployeeCredential", "", " ", "https://", "https:///path",
    "ftp://example.com/t", "mailto:a@example.com", "//example.com/t", "example.com/t",
    "urn:", "urn:example:", "urn:-bad:x", "https://exa mple.com/t", "https://example.com/t\n",
    "https://example.com/\tt", "https://[::1", None, 5, ["https://example.com/t"],
]


class TestCollisionResistantType(unittest.TestCase):
    def test_namespaced_identifiers_accepted(self) -> None:
        for v in GOOD:
            self.assertTrue(is_collision_resistant_type(v), v)

    def test_bare_labels_and_malformed_values_rejected(self) -> None:
        for v in BAD:
            self.assertFalse(is_collision_resistant_type(v), repr(v))

    def test_the_specs_illustrative_type_is_valid(self) -> None:
        self.assertTrue(is_collision_resistant_type(AI_AGENT_IDENTITY_VCT))
        self.assertEqual(AI_AGENT_IDENTITY_VCT, "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1")


class TestQueryVctValues(unittest.TestCase):
    def test_bare_vct_value_rejected(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            DCQLCredentialQuery(id="q", meta={"vct_values": ["AIAgentIdentityCredential"]})
        self.assertIn("collision-resistant", str(ctx.exception))

    def test_one_bare_value_among_valid_ones_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            DCQLCredentialQuery(id="q", meta={"vct_values": [AI_AGENT_IDENTITY_VCT, "Bare"]})

    def test_namespaced_values_accepted_including_alternatives(self) -> None:
        q = DCQLCredentialQuery(id="q", meta={"vct_values": [AI_AGENT_IDENTITY_VCT, "urn:example:other"]})
        self.assertEqual(len(q.meta["vct_values"]), 2)

    def test_bare_value_rejected_when_parsed_from_the_wire(self) -> None:
        wire: Any = {"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["Bare"]}}]}
        with self.assertRaises(ValidationError):
            DCQLQuery.model_validate(wire)

    def test_default_query_lists_only_the_namespaced_type(self) -> None:
        # The bare alias that used to sit beside the URI is gone (it was not collision resistant).
        vcts = DCQLQuery.default_agent_identity_query().credentials[0].meta["vct_values"]
        self.assertEqual(vcts, [AI_AGENT_IDENTITY_VCT])


class TestIssuerAndModel(unittest.TestCase):
    def _issue(self, **kw: Any) -> str:
        priv, _ = generate_ec_p256_keypair()
        _, holder_pub = generate_ec_p256_keypair()
        return SDJWTWallet.issue_sd_jwt(
            export_jwk_from_private_key(priv), "https://issuer.example.com", id_claim="a",
            holder_public_key_jwk=export_jwk_from_public_key(holder_pub), **kw,
        )

    def test_issuer_refuses_a_bare_vct(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._issue(vct="AIAgentIdentityCredential")
        self.assertIn("collision-resistant", str(ctx.exception))

    def test_issuer_refuses_a_bare_dct_alias_too(self) -> None:
        with self.assertRaises(ValueError):
            self._issue(dct="EmployeeCredential")

    def test_issuer_default_type_is_the_namespaced_agent_identity_type(self) -> None:
        import jwt

        payload = jwt.decode(self._issue().split("~")[0], options={"verify_signature": False})
        self.assertEqual(payload["vct"], AI_AGENT_IDENTITY_VCT)

    def test_issuer_accepts_a_namespaced_type(self) -> None:
        self.assertTrue(self._issue(vct="https://example.com/credentials/Thing/v1"))

    def test_identity_credential_model_rejects_a_bare_vct(self) -> None:
        base = {"iss": "https://issuer.example.com", "iat": 0, "exp": 1, "id": "a"}
        with self.assertRaises(ValidationError):
            AIAgentIdentityCredential(**base, vct="AIAgentIdentityCredential")
        self.assertEqual(AIAgentIdentityCredential(**base, vct=AI_AGENT_IDENTITY_VCT).vct, AI_AGENT_IDENTITY_VCT)


if __name__ == "__main__":
    unittest.main()
